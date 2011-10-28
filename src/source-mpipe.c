/* Copyright (C) 2011 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Tom DeCanio <decanio.tom@gmail.com>
 *
 * Tilera tilegx mpipe ingress packet support
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-threads.h"
#include "runmode-tile.h"
#include "source-mpipe.h"
#include "conf.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-privs.h"
#include "tmqh-packetpool.h"

#ifdef __tilegx__

#include <tmc/alloc.h>
#include <arch/sim.h>
#include <arch/cycle.h>
#include <gxio/mpipe.h>
#include <tmc/cpus.h>
#include <tmc/spin.h>
#include <tmc/sync.h>
#include <tmc/task.h>
#include <tmc/perf.h>
#include <arch/sim.h>

// Define this to verify a bunch of facts about each packet.
#define PARANOIA

//#define MPIPE_DEBUG

// Align "p" mod "align", assuming "p" is a "void*".
#define ALIGN(p, align) do { (p) += -(long)(p) & ((align) - 1); } while(0)

#define VERIFY(VAL, WHAT)                                       \
  do {                                                          \
    int __val = (VAL);                                          \
    if (__val < 0)                                              \
      tmc_task_die("Failure in '%s': %d: %s.",                  \
                   (WHAT), __val, gxio_strerror(__val));        \
  } while (0)

extern uint8_t suricata_ctl_flags;
extern unsigned int MpipeNumPipes;
extern int max_pending_packets;

/** storage for mpipe device names */
typedef struct MpipeDevice_ {
    char *dev;  /**< the device (e.g. "xgbe1") */
    TAILQ_ENTRY(MpipeDevice_) next;
} MpipeDevice;

/** private device list */
static TAILQ_HEAD(, MpipeDevice_) mpipe_devices =
    TAILQ_HEAD_INITIALIZER(mpipe_devices);

static pthread_barrier_t barrier;

/**
 * \brief Structure to hold thread specifc variables.
 */
typedef struct MpipeThreadVars_
{
    /* data link type for the thread */
    int datalink;

    /* ocunters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;

    ThreadVars *tv;
    TmSlot *slot;

    Packet *in_p;

} MpipeThreadVars;

TmEcode ReceiveMpipeLoop(ThreadVars *tv, void *data, void *slot);
TmEcode ReceiveMpipeThreadInit(ThreadVars *, void *, void **);
void ReceiveMpipeThreadExitStats(ThreadVars *, void *);

TmEcode DecodeMpipeThreadInit(ThreadVars *, void *, void **);
TmEcode DecodeMpipe(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

/*
 * mpipe configuration.
 */

/* The mpipe context (shared by all workers) */
static gxio_mpipe_context_t context_body;
static gxio_mpipe_context_t* context = &context_body;

/* The ingress queues (one per worker) */
//static gxio_mpipe_iqueue_t iqueue_body;
//static gxio_mpipe_iqueue_t* iqueue = &iqueue_body;
static gxio_mpipe_iqueue_t** iqueues;

static unsigned long long tilera_gtod_fast_boot = 0;
static const unsigned long tilera_gtod_fast_mhz = /* tmc_perf_get_cpu_speed() */ 866000000 / 1000000;

static int tilera_fast_gettimeofday(struct timeval *tv) {
    unsigned long long x = get_cycle_count();
    if(tilera_gtod_fast_boot) {
        x = tilera_gtod_fast_boot + x/tilera_gtod_fast_mhz;
        tv->tv_usec = x%1000000;
        tv->tv_sec = x/1000000;
    } else {
        gettimeofday(tv, 0);
        tilera_gtod_fast_boot = tv->tv_sec * 1000000LL + tv->tv_usec - x/tilera_gtod_fast_mhz;
    }
    return 0;
}

/**
 * \brief Registration Function for ReceiveMpipe.
 * \todo Unit tests are needed for this module.
 */
void TmModuleReceiveMpipeRegister (void) {
    tmm_modules[TMM_RECEIVEMPIPE].name = "ReceiveMpipe";
    tmm_modules[TMM_RECEIVEMPIPE].ThreadInit = ReceiveMpipeThreadInit;
    tmm_modules[TMM_RECEIVEMPIPE].Func = NULL; /* was ReceiveMpipe; */
    tmm_modules[TMM_RECEIVEMPIPE].PktAcqLoop = ReceiveMpipeLoop;
    tmm_modules[TMM_RECEIVEMPIPE].ThreadExitPrintStats = ReceiveMpipeThreadExitStats;
    tmm_modules[TMM_RECEIVEMPIPE].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEMPIPE].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEMPIPE].cap_flags = SC_CAP_NET_RAW;
    tmm_modules[TMM_RECEIVEMPIPE].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Registraction Function for DecodeNetio.
 * \todo Unit tests are needed for this module.
 */
void TmModuleDecodeMpipeRegister (void) {
    tmm_modules[TMM_DECODEMPIPE].name = "DecodeMpipe";
    tmm_modules[TMM_DECODEMPIPE].ThreadInit = DecodeMpipeThreadInit;
    tmm_modules[TMM_DECODEMPIPE].Func = DecodeMpipe;
    tmm_modules[TMM_DECODEMPIPE].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEMPIPE].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEMPIPE].RegisterTests = NULL;
    tmm_modules[TMM_DECODEMPIPE].cap_flags = 0;
}

static __attribute__((always_inline)) void
cycle_pause(unsigned int delay)
{
  const unsigned int start = get_cycle_count_low();
  while (get_cycle_count_low() - start < delay)
    ;
}

void MpipeFreePacket(Packet *p) {
#ifdef MPIPE_DEBUG
    SCLogInfo("MpipeFreePacket %p", p);
#endif
    gxio_mpipe_push_buffer(context, p->idesc.stack_idx, (void *)(intptr_t)p->idesc.va);

#ifdef __TILEGX_SIMULATION__
    static uint32_t packet_count = 0;

    // disable profiling at end of simulation input
    if (++packet_count == 10000) {
        SCLogInfo("Mpipe disabling profiler\n");
        sim_profiler_disable();
        SCLogInfo("Mpipe exiting\n");
        EngineStop();
    }
#endif
}

/**
 * \brief Mpipe Packet Process function.
 *
 * This function fills in our packet structure from mpipe.
 * From here the packets are picked up by the  DecodeMpipe thread.
 *
 * \param user pointer to MpipeThreadVars passed from pcap_dispatch
 * \param h pointer to gxio packet header
 * \param pkt pointer to current packet
 */
static inline void MpipeProcessPacket(u_char *user, gxio_mpipe_idesc_t *idesc, Packet *p) {
    int caplen = idesc->l2_size;
    u_char *pkt = (void *)(intptr_t)idesc->va;
    MpipeThreadVars *ptv = (MpipeThreadVars *)user;

    ptv->bytes += caplen;
    ptv->pkts++;

    tilera_fast_gettimeofday(&p->ts);
    /*
    p->ts.tv_sec = h->ts.tv_sec;
    p->ts.tv_usec = h->ts.tv_usec;
    */

    p->datalink = ptv->datalink;
    p->flags |= PKT_MPIPE;
    SET_PKT_LEN(p, caplen);
    p->pkt = pkt;

#ifdef MPIPE_DEBUG
    SCLogInfo("p->pktlen: %" PRIu32 " (pkt %02x, p->pkt %02x)", p->pktlen, *pkt, *p->pkt);
#endif
}

/**
 * \brief Receives packets from an interface via gxio mpipe.
 */
TmEcode ReceiveMpipeLoop(ThreadVars *tv, void *data, void *slot) {
    uint16_t packet_q_len = 0;
    MpipeThreadVars *ptv = (MpipeThreadVars *)data;
    TmSlot *s = (TmSlot *)slot;
    ptv->slot = s->slot_next;
    Packet *p = NULL;
    int cpu = tmc_cpus_get_my_cpu();
    int rank = (cpu-1)/TILES_PER_MPIPE_PIPELINE;
    int result;

printf("ReceiveMpipeLoop(cpu: %d rank: %d)\n", cpu, rank);

    SCEnter();

    gxio_mpipe_iqueue_t* iqueue = iqueues[rank];

    for (;;) {
        if (suricata_ctl_flags & SURICATA_STOP ||
                suricata_ctl_flags & SURICATA_KILL) {
            SCReturnInt(TM_ECODE_FAILED);
        }

        /* make sure we have at least one packet in the packet pool, to prevent
         * us from alloc'ing packets at line rate */
        do {
            packet_q_len = PacketPoolSize();
            if (packet_q_len == 0) {
                PacketPoolWait();
            }
        } while (packet_q_len == 0);

        p = PacketGetFromQueueOrAlloc();
        if (p == NULL) {
            SCReturnInt(TM_ECODE_FAILED);
        }

#ifdef MPIPE_DEBUG
        SCLogInfo("ReceiveMpipe!!!");
#endif

        int r = 0;
        while (r == 0) {
            result = gxio_mpipe_iqueue_try_get(iqueue, &p->idesc);
            if (result == 0) {
#ifdef MPIPE_DEBUG
                char buf[128];
                sprintf(buf, "Got a packet size: %d", p->idesc.l2_size);
                SCLogInfo(buf);
#endif
                if (!p->idesc.be) {
                    MpipeProcessPacket((u_char *)ptv,  &p->idesc, p);
                    TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p);
                    r = 1;
                }
            } else if (suricata_ctl_flags & SURICATA_STOP ||
                    suricata_ctl_flags & SURICATA_KILL) {
                SCReturnInt(TM_ECODE_FAILED);
            }
        }
        SCPerfSyncCountersIfSignalled(tv, 0);
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode MpipeRegisterPipeStage(void *td) {
    SCEnter()

    //pthread_barrier_wait(&barrier);

    SCReturnInt(TM_ECODE_OK);
}

TmEcode ReceiveMpipeThreadInit(ThreadVars *tv, void *initdata, void **data) {
    SCEnter()
    int cpu = tmc_cpus_get_my_cpu();
    int rank = (cpu-1)/TILES_PER_MPIPE_PIPELINE;
#ifdef MPIPE_DEBUG
    SCLogInfo("ReceiveMpipeThreadInit\n");
#endif
    unsigned int num_buffers = 2048;
    unsigned int num_workers = NUM_TILERA_MPIPE_PIPELINES;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    MpipeThreadVars *ptv = SCMalloc(sizeof(MpipeThreadVars));
    if (ptv == NULL)
        SCReturnInt(TM_ECODE_FAILED);
    memset(ptv, 0, sizeof(MpipeThreadVars));

    ptv->tv = tv;
    ptv->datalink = LINKTYPE_ETHERNET;

    SCLogInfo("using interface %s", (char *)initdata);

    int result;
    char *link_name = (char *)initdata;
  
    /* Bind to a single cpu. */
    cpu_set_t cpus;
    result = tmc_cpus_get_my_affinity(&cpus);
    VERIFY(result, "tmc_cpus_get_my_affinity()");
    result = tmc_cpus_set_my_cpu(tmc_cpus_find_first_cpu(&cpus));
    VERIFY(result, "tmc_cpus_set_my_cpu()");

    if (rank == 0) {
        /* Start the driver. */
        result = gxio_mpipe_init(context, gxio_mpipe_link_instance(link_name));
        VERIFY(result, "gxio_mpipe_init()");

        gxio_mpipe_link_t link;
        result = gxio_mpipe_link_open(&link, context, link_name, 0);
        VERIFY(result, "gxio_mpipe_link_open()");

        /* Allocate some iqueues. */
        iqueues = calloc(num_workers, sizeof(*iqueues));
        if (iqueues == NULL)
             tmc_task_die("Failure in 'calloc()'.");

        /* Allocate some NotifRings. */
        result = gxio_mpipe_alloc_notif_rings(context,
                                              num_workers,
                                              0, 0);
        VERIFY(result, "gxio_mpipe_alloc_notif_rings()");
        int ring = result;

        /* Init the NotifRings. */
        size_t notif_ring_entries = 128;
        size_t notif_ring_size = notif_ring_entries * sizeof(gxio_mpipe_idesc_t);
        for (unsigned int i = 0; i < num_workers; i++) {
            tmc_alloc_t alloc = TMC_ALLOC_INIT;
            tmc_alloc_set_home(&alloc, (i * TILES_PER_MPIPE_PIPELINE ) + 1);
            if (notif_ring_size > (size_t)getpagesize())
                tmc_alloc_set_huge(&alloc);
            unsigned int needed = notif_ring_size + sizeof(gxio_mpipe_iqueue_t);
            void *iqueue_mem = tmc_alloc_map(&alloc, needed);
            if (iqueue_mem == NULL)
                tmc_task_die("Failure in 'tmc_alloc_map()'.");
            gxio_mpipe_iqueue_t *iqueue = iqueue_mem + notif_ring_size;
            result = gxio_mpipe_iqueue_init(iqueue, context, ring + i,
                                            iqueue_mem, notif_ring_size, 0);
            VERIFY(result, "gxio_mpipe_iqueue_init()");
            iqueues[i] = iqueue;
        }

        /* Allocate one huge page to hold our buffer stack, notif ring, and
         * packets.  This should be more than enough space. */
        size_t page_size = (1 << 24);
        tmc_alloc_t alloc = TMC_ALLOC_INIT;
        tmc_alloc_set_huge(&alloc);
        void* page = tmc_alloc_map(&alloc, page_size);

        assert(page);

        void* mem = page;

        // Allocate a NotifGroup.
        result = gxio_mpipe_alloc_notif_groups(context, 1, 0, 0);
        VERIFY(result, "gxio_mpipe_alloc_notif_groups()");
        int group = result;

        // Allocate a bucket.
        int num_buckets = 1024;
        result = gxio_mpipe_alloc_buckets(context, num_buckets, 0, 0);
        VERIFY(result, "gxio_mpipe_alloc_buckets()");
        int bucket = result;

        // Init group and buckets, preserving packet order among flows.
        gxio_mpipe_bucket_mode_t mode = GXIO_MPIPE_BUCKET_DYNAMIC_FLOW_AFFINITY;
        result = gxio_mpipe_init_notif_group_and_buckets(context, group,
                                                   ring, num_workers,
                                                   bucket, num_buckets, mode);
        VERIFY(result, "gxio_mpipe_init_notif_group_and_buckets()");


        // Allocate a buffer stack.
        result = gxio_mpipe_alloc_buffer_stacks(context, 1, 0, 0);
        VERIFY(result, "gxio_mpipe_alloc_buffer_stacks()");
        int stack = result;

        // Initialize the buffer stack.
        ALIGN(mem, 0x10000);
        size_t stack_bytes = gxio_mpipe_calc_buffer_stack_bytes(num_buffers);
        gxio_mpipe_buffer_size_enum_t buf_size = GXIO_MPIPE_BUFFER_SIZE_1664;
        result = gxio_mpipe_init_buffer_stack(context, stack, buf_size,
                                              mem, stack_bytes, 0);
        VERIFY(result, "gxio_mpipe_init_buffer_stack()");
        mem += stack_bytes;

        ALIGN(mem, 0x10000);

        // Register the entire huge page of memory which contains all the buffers.
        result = gxio_mpipe_register_page(context, stack, page, page_size, 0);
        VERIFY(result, "gxio_mpipe_register_page()");

        // Push some buffers onto the stack.
        for (unsigned int i = 0; i < num_buffers; i++)
        {
            gxio_mpipe_push_buffer(context, stack, mem);
            mem += 1664;
        }

        // Paranoia.
        assert(mem <= page + page_size);


        // Register for packets.
        gxio_mpipe_rules_t rules;
        gxio_mpipe_rules_init(&rules, context);
        gxio_mpipe_rules_begin(&rules, bucket, num_buckets, NULL);
        result = gxio_mpipe_rules_commit(&rules);
        VERIFY(result, "gxio_mpipe_rules_commit()");
    }
    /*
     * There is some initialization race condition that I haven't found
     * yet.  This delay seems to prevent taking packets in until everything
     * else has initialized avoiding a crash.
     */
    cycle_pause(2000*1000*1000); /* delay 2 secs */

    pthread_barrier_wait(&barrier);

    SCLogInfo("ReceiveMpipe-%d initialization complete!!!", rank);
    *data = (void *)ptv;
    SCReturnInt(TM_ECODE_OK);
}

TmEcode ReceiveMpipeInit(void) {
    SCEnter();

    pthread_barrier_init(&barrier, NULL, MpipeNumPipes/* * TILES_PER_MPIPE_PIPELINE*/);

    SCReturnInt(TM_ECODE_OK);
}

TmEcode ReceiveMpipeGo(void) {
    SCEnter();
    SCLogInfo("Mpipe enabling input and profiling\n");
    // Turn on all the links on mpipe0.
    sim_enable_mpipe_links(0, -1);

#ifdef __TILEGX_SIMULATION__
    // Clear any old profiler data
    sim_profiler_clear();

    // Enable the profiler
    sim_profiler_enable();
#endif
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function prints stats to the screen at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into NetiohreadVars for ptv
 */
void ReceiveMpipeThreadExitStats(ThreadVars *tv, void *data) {
    SCEnter();
#ifdef NOTYET
    MpipeThreadVars *ptv = (MpipeThreadVars *)data;
#endif
    SCReturn;
}

TmEcode DecodeMpipeThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter()
    DecodeThreadVars *dtv = NULL;

    dtv = DecodeThreadVarsAlloc();

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;
    SCLogInfo("DecodeMpipeThreadInit");

    SCReturnInt(TM_ECODE_OK);

}

TmEcode DecodeMpipe(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postq)
{
    SCEnter()
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    /* update counters */
    SCPerfCounterIncr(dtv->counter_pkts, tv->sc_perf_pca);
    SCPerfCounterIncr(dtv->counter_pkts_per_sec, tv->sc_perf_pca);

    SCPerfCounterAddUI64(dtv->counter_bytes, tv->sc_perf_pca, p->pktlen);
    SCPerfCounterAddDouble(dtv->counter_bytes_per_sec, tv->sc_perf_pca, p->pktlen);
    SCPerfCounterAddDouble(dtv->counter_mbit_per_sec, tv->sc_perf_pca,
                           (p->pktlen * 8)/1000000.0);

    SCPerfCounterAddUI64(dtv->counter_avg_pkt_size, tv->sc_perf_pca, p->pktlen);
    SCPerfCounterSetUI64(dtv->counter_max_pkt_size, tv->sc_perf_pca, p->pktlen);

    /* call the decoder */
    switch(p->datalink) {
    case LINKTYPE_ETHERNET:
#ifdef DEBUG_MPIPE
        SCLogInfo("DecodeMpipe Decode Ethernet p %p", p);
#endif
        DecodeEthernet(tv, dtv, p, p->pkt, p->pktlen, pq);
        break;
    default:
#ifdef DEBUG_MPIPE
        SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED, "Error: datalink type %" PRId32 " not yet supported in module DecodeNetio", p->datalink);
#endif
        break;
    }
 
    SCReturnInt(TM_ECODE_OK);
}

/**
 *  \brief Add a mpipe device for monitoring
 *
 *  \param dev string with the device name
 *
 *  \retval 0 on success.
 *  \retval -1 on failure.
 */
int MpipeLiveRegisterDevice(char *dev)
{
    MpipeDevice *nd = SCMalloc(sizeof(MpipeDevice));
    if (nd == NULL) {
        return -1;
    }

    nd->dev = SCStrdup(dev);
    TAILQ_INSERT_TAIL(&mpipe_devices, nd, next);

    SCLogDebug("Mpipe device \"%s\" registered.", dev);
    return 0;
}

/**
 *  \brief Get the number of registered devices
 *
 *  \retval cnt the number of registered devices
 */
int MpipeLiveGetDeviceCount(void) {
    int i = 0;
    MpipeDevice *nd;

    TAILQ_FOREACH(nd, &mpipe_devices, next) {
        i++;
    }

    return i;
}

#endif // __tilegx__
