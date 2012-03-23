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
#include "util-device.h"
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

/* Define this to verify a bunch of facts about each packet. */
#define PARANOIA

//#define MPIPE_DEBUG

// return bucket credits after completely done with packet
#define LATE_MPIPE_CREDIT 1
//#define LATE_MPIPE_BUCKET_CREDIT 1

/* Align "p" mod "align", assuming "p" is a "void*". */
#define ALIGN(p, align) do { (p) += -(long)(p) & ((align) - 1); } while(0)

#define VERIFY(VAL, WHAT)                                       \
  do {                                                          \
    int __val = (VAL);                                          \
    if (__val < 0)                                              \
      tmc_task_die("Failure in '%s': %d: %s.",                  \
                   (WHAT), __val, gxio_strerror(__val));        \
  } while (0)

#define min(a,b) (((a) < (b)) ? (a) : (b))

extern uint8_t suricata_ctl_flags;
extern intmax_t max_pending_packets;
extern size_t tile_vhuge_size;

/** storage for mpipe device names */
typedef struct MpipeDevice_ {
    char *dev;  /**< the device (e.g. "xgbe1") */
    TAILQ_ENTRY(MpipeDevice_) next;
} MpipeDevice;

/** private device list */
static TAILQ_HEAD(, MpipeDevice_) mpipe_devices =
    TAILQ_HEAD_INITIALIZER(mpipe_devices);

static tmc_sync_barrier_t barrier;
static uint16_t first_stack;

/**
 * \brief Structure to hold thread specifc variables.
 */
typedef struct MpipeThreadVars_
{
    /* data link type for the thread */
    int datalink;

    /* counters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;

    ThreadVars *tv;
    TmSlot *slot;

    Packet *in_p;

    /** stats/counters */
    uint16_t mpipe_depth;
    uint16_t counter_no_buffers_0;
    uint16_t counter_no_buffers_1;
    uint16_t counter_no_buffers_2;
    uint16_t counter_no_buffers_3;
    uint16_t counter_no_buffers_4;
    uint16_t counter_no_buffers_5;
    uint16_t counter_no_buffers_6;
    uint16_t counter_no_buffers_7;

} MpipeThreadVars;

TmEcode ReceiveMpipeLoop(ThreadVars *tv, void *data, void *slot);
TmEcode ReceiveMpipeLoopPair(ThreadVars *tv, void *data, void *slot);
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
static gxio_mpipe_iqueue_t** iqueues;

static unsigned long long tile_gtod_fast_boot = 0;
static unsigned long tile_gtod_fast_mhz;

static int tilera_fast_gettimeofday(struct timeval *tv) {
    unsigned long long x = get_cycle_count();
    if(tile_gtod_fast_boot) {
        x = tile_gtod_fast_boot + x/tile_gtod_fast_mhz;
        tv->tv_usec = x%1000000;
        tv->tv_sec = x/1000000;
    } else {
        gettimeofday(tv, 0);
	tile_gtod_fast_mhz = tmc_perf_get_cpu_speed() / 1000000;
        tile_gtod_fast_boot = tv->tv_sec * 1000000LL + tv->tv_usec - x/tile_gtod_fast_mhz;
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
    //tmm_modules[TMM_RECEIVEMPIPE].PktAcqLoop = ReceiveMpipeLoop;
    tmm_modules[TMM_RECEIVEMPIPE].PktAcqLoop = ReceiveMpipeLoopPair;
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

void MpipeFreePacket(Packet *p) {

#ifdef LATE_MPIPE_CREDIT
    gxio_mpipe_iqueue_t* iqueue = iqueues[p->pool];
#ifdef LATE_MPIPE_BUCKET_CREDIT
    gxio_mpipe_credit(iqueue->context, -1, p->idesc.bucket_id, 1);
#else
    gxio_mpipe_iqueue_release(iqueue, &p->idesc);
#endif
#endif
    gxio_mpipe_push_buffer(context,
                           p->idesc.stack_idx,
                           (void *)(intptr_t)p->idesc.va);

//#define __TILEGX_FEEDBACK_RUN__
#ifdef __TILEGX_FEEDBACK_RUN__
    static uint32_t packet_count = 0;

    /* disable profiling at end of simulation input */
    if (++packet_count == 1000000) {
        SCLogInfo("Mpipe exiting\n");
        EngineStop();
    }
#endif

#ifdef __TILEGX_SIMULATION__
    static uint32_t packet_count = 0;

    /* disable profiling at end of simulation input */
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
static inline void MpipeProcessPacket(MpipeThreadVars *ptv, gxio_mpipe_idesc_t *idesc, Packet *p, struct timeval *tv) {
    int caplen = idesc->l2_size;
    u_char *pkt = (void *)(intptr_t)idesc->va;

    ptv->bytes += caplen;
    ptv->pkts++;

    p->ts = *tv;
    //TimeGet(&p->ts);
    /*
    p->ts.tv_sec = h->ts.tv_sec;
    p->ts.tv_usec = h->ts.tv_usec;
    */

    p->datalink = ptv->datalink;
    p->flags |= PKT_MPIPE;
    SET_PKT_LEN(p, caplen);
    p->pkt = pkt;

    /* copy only the fields we use later */
#if 1
    p->idesc = *idesc;
#else
    p->idesc.cs = idesc->cs;
    p->idesc.va = idesc->va;
    p->idesc.stack_idx = idesc->stack_idx;
#endif
}

static inline Packet *PacketAlloc(int rank)
{
#if 1
    Packet *p = NULL;
    if (PacketPoolSize(rank) > 0) {
        p = PacketPoolGetPacket(rank);
    }
    return p;
#else
    return PacketGetFromQueueOrAlloc(rank);
#endif
}

static uint16_t xlate_stack(MpipeThreadVars *ptv, int stack_idx) {
    uint16_t counter;

    switch(stack_idx - first_stack) {
    case 0:
        counter = ptv->counter_no_buffers_0;
        break;
    case 1:
        counter = ptv->counter_no_buffers_1;
        break;
    case 2:
        counter = ptv->counter_no_buffers_2;
        break;
    case 3:
        counter = ptv->counter_no_buffers_3;
        break;
    case 4:
        counter = ptv->counter_no_buffers_4;
        break;
    case 5:
        counter = ptv->counter_no_buffers_5;
        break;
    case 6:
        counter = ptv->counter_no_buffers_6;
        break;
    case 7:
        counter = ptv->counter_no_buffers_7;
        break;
    default:
        counter = ptv->counter_no_buffers_7;
        break;
    }
    return counter;
}
/**
 * \brief Receives packets from an interface via gxio mpipe.
 */
TmEcode ReceiveMpipeLoop(ThreadVars *tv, void *data, void *slot) {
    struct timeval timeval;
    MpipeThreadVars *ptv = (MpipeThreadVars *)data;
    TmSlot *s = (TmSlot *)slot;
    ptv->slot = s->slot_next;
    Packet *p = NULL;
    int cpu = tmc_cpus_get_my_cpu();
#if 1
    int rank = (TileMpipeUnmapTile(cpu)-1)/TILES_PER_MPIPE_PIPELINE;
#else
    int rank = (cpu-1)/TILES_PER_MPIPE_PIPELINE;
#endif

    SCEnter();

    SCLogInfo("cpu: %d rank: %d", cpu, rank);

    gxio_mpipe_iqueue_t* iqueue = iqueues[rank];

    tilera_fast_gettimeofday(&timeval);

    for (;;) {
        if (suricata_ctl_flags & (SURICATA_STOP | SURICATA_KILL)) {
            SCReturnInt(TM_ECODE_FAILED);
        }

        while (p == NULL) {
            p = PacketAlloc(rank);
        }

        int r = 0;
        while (r == 0) {
            gxio_mpipe_idesc_t *idesc;

            int n = gxio_mpipe_iqueue_try_peek(iqueue, &idesc);
            if (likely(n > 0)) {
                int i; int m;

                m = min(n, 32);

                /* Prefetch the idescs (64 bytes each). */
                for (i = 0; i < m; i++) {
                    __insn_prefetch(&idesc[i]);
                }
                SCPerfCounterSetUI64(ptv->mpipe_depth, tv->sc_perf_pca,
                                     (uint64_t)n);
                for (i = 0; i < m; i++, idesc++) {
                    if (likely(!idesc->be)) {
                        MpipeProcessPacket(ptv,  idesc, p, &timeval);
                        TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p);
                        do {
                            p = PacketAlloc(rank);
                        } while (p == NULL);
                        r = 1;
#ifdef LATE_MPIPE_CREDIT
                        gxio_mpipe_iqueue_advance(iqueue, 1);
#ifdef LATE_MPIPE_BUCKET_CREDIT
                        gxio_mpipe_credit(iqueue->context, iqueue->ring, -1, 1);
#endif
#else
                        gxio_mpipe_iqueue_consume(iqueue, idesc);
#endif

                    } else {
                        gxio_mpipe_iqueue_consume(iqueue, idesc);
                        SCPerfCounterIncr(xlate_stack(ptv, idesc->stack_idx), tv->sc_perf_pca);
                    }
                }
            } else {
                tilera_fast_gettimeofday(&timeval);
                if (suricata_ctl_flags & (SURICATA_STOP | SURICATA_KILL)) {
                    SCReturnInt(TM_ECODE_FAILED);
                }
            }
        }
        SCPerfSyncCountersIfSignalled(tv, 0);
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode ReceiveMpipeLoopPair(ThreadVars *tv, void *data, void *slot) {
    struct timeval timeval;
    MpipeThreadVars *ptv = (MpipeThreadVars *)data;
    gxio_mpipe_iqueue_t* iqueue;
    TmSlot *s = (TmSlot *)slot;
    gxio_mpipe_idesc_t *idesc;
    ptv->slot = s->slot_next;
    Packet *p[2];
    int cpu = tmc_cpus_get_my_cpu();
    int rank = cpu-1;

    SCEnter();

    SCLogInfo("cpu: %d rank: %d", cpu, rank);

    tilera_fast_gettimeofday(&timeval);

    p[0] = NULL; p[1] = NULL;

    for (;;) {
        int i;

        if (suricata_ctl_flags & (SURICATA_STOP | SURICATA_KILL)) {
            SCReturnInt(TM_ECODE_FAILED);
        }

        for (i = 0; i < 2; i++) {
            int pool = (rank * 2) + i;

            iqueue = iqueues[pool];

            if (p[i] == NULL) {
                if ((p[i] = PacketAlloc(pool)) == NULL) {
                    continue;
                }
            }

            //SCLogInfo("Polling pool %d rank %d queue %d", pool, rank, i);
            int n = gxio_mpipe_iqueue_try_peek(iqueue, &idesc);
            if (likely(n > 0)) {
                int j; int m;

                //SCLogInfo("Got %d packets for pool %d", n, pool);
                m = min(n, 4);

                /* Prefetch the idescs (64 bytes each). */
                for (j = 0; j < m; j++) {
                    __insn_prefetch(&idesc[j]);
                }
                SCPerfCounterSetUI64(ptv->mpipe_depth, tv->sc_perf_pca,
                                     (uint64_t)n);
                for (j = 0; j < m; j++, idesc++) {
                    if (likely(!idesc->be)) {
                        MpipeProcessPacket(ptv,  idesc, p[i], &timeval);
                        TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p[i]);
#ifdef LATE_MPIPE_CREDIT
                        gxio_mpipe_iqueue_advance(iqueue, 1);
#ifdef LATE_MPIPE_BUCKET_CREDIT
                        gxio_mpipe_credit(iqueue->context, iqueue->ring, -1, 1);
#endif
#else
                        gxio_mpipe_iqueue_consume(iqueue, idesc);
#endif
                        if ((p[i] = PacketAlloc(pool)) == NULL) {
                            goto bail;
                        }
                    } else {
                        gxio_mpipe_iqueue_consume(iqueue, idesc);
                        SCPerfCounterIncr(xlate_stack(ptv, idesc->stack_idx), tv->sc_perf_pca);
                    }
                }
            } else {
                tilera_fast_gettimeofday(&timeval);
            }
bail:
            SCPerfSyncCountersIfSignalled(tv, 0);
        }
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode MpipeRegisterPipeStage(void *td) {
    SCEnter()

    SCReturnInt(TM_ECODE_OK);
}

static void MpipeRegisterPerfCounters(MpipeThreadVars *ptv, ThreadVars *tv) {
    /* register counters */
    ptv->mpipe_depth = SCPerfTVRegisterCounter("mpipe.mpipe_depth", tv,
                                               SC_PERF_TYPE_UINT64,
                                               "NULL");
    ptv->counter_no_buffers_0 = SCPerfTVRegisterCounter("mpipe.no_buf0", tv,
                                                        SC_PERF_TYPE_UINT64,
                                                        "NULL");
    ptv->counter_no_buffers_1 = SCPerfTVRegisterCounter("mpipe.no_buf1", tv,
                                                        SC_PERF_TYPE_UINT64,
                                                        "NULL");
    ptv->counter_no_buffers_2 = SCPerfTVRegisterCounter("mpipe.no_buf2", tv,
                                                        SC_PERF_TYPE_UINT64,
                                                        "NULL");
    ptv->counter_no_buffers_3 = SCPerfTVRegisterCounter("mpipe.no_buf3", tv,
                                                        SC_PERF_TYPE_UINT64,
                                                        "NULL");
    ptv->counter_no_buffers_4 = SCPerfTVRegisterCounter("mpipe.no_buf4", tv,
                                                        SC_PERF_TYPE_UINT64,
                                                        "NULL");
    ptv->counter_no_buffers_5 = SCPerfTVRegisterCounter("mpipe.no_buf5", tv,
                                                        SC_PERF_TYPE_UINT64,
                                                        "NULL");
    ptv->counter_no_buffers_6 = SCPerfTVRegisterCounter("mpipe.no_buf6", tv,
                                                        SC_PERF_TYPE_UINT64,
                                                        "NULL");
    ptv->counter_no_buffers_7 = SCPerfTVRegisterCounter("mpipe.no_buf7", tv,
                                                        SC_PERF_TYPE_UINT64,
                                                        "NULL");

   tv->sc_perf_pca = SCPerfGetAllCountersArray(tv, &tv->sc_perf_pctx);
   SCPerfAddToClubbedTMTable(tv->name, &tv->sc_perf_pctx);
}

TmEcode ReceiveMpipeThreadInit(ThreadVars *tv, void *initdata, void **data) {
    SCEnter()
    int cpu = tmc_cpus_get_my_cpu();
#if 1
    int rank = (cpu-1);
#else
#if 1
    int rank = (TileMpipeUnmapTile(cpu)-1)/TILES_PER_MPIPE_PIPELINE;
#else
    int rank = (cpu-1)/TILES_PER_MPIPE_PIPELINE;
#endif
#endif
    unsigned int num_buffers;
    //unsigned int total_buffers = max_pending_packets;
    unsigned int total_buffers = 0;
    unsigned int num_workers = TileNumPipelines /*DFLT_TILERA_MPIPE_PIPELINES*/;
    unsigned int stack_count = 0;
    const gxio_mpipe_buffer_size_enum_t gxio_buffer_sizes[] = {
            GXIO_MPIPE_BUFFER_SIZE_128,
            GXIO_MPIPE_BUFFER_SIZE_256,
            GXIO_MPIPE_BUFFER_SIZE_512,
            GXIO_MPIPE_BUFFER_SIZE_1024,
            GXIO_MPIPE_BUFFER_SIZE_1664,
            GXIO_MPIPE_BUFFER_SIZE_4096,
            GXIO_MPIPE_BUFFER_SIZE_10368,
            GXIO_MPIPE_BUFFER_SIZE_16384
        };
    const unsigned int buffer_sizes[] = {
            128,
            256,
            512,
            1024,
            1664,
            4096,
            10368,
            16384
        };
#if 1
static const struct {
   int mul;
   int div;
} buffer_scale[] = {
  { 1, 8 }, /* 128 */
  { 1, 8 }, /* 256 */
  { 1, 8 }, /* 512 */
  { 1, 8 }, /* 1024 */
  { 3, 8 }, /* 1664 */
  { 0, 8 }, /* 4096 */
  { 1, 8 }, /* 10386 */
  { 0, 8 }  /* 16384 */
};
#else
    /* sort of tuned these for expected traffic patterns.
     * should make these configurable now that we have insight into
     * no buffer conditions.
     */
    const unsigned int buffer_counts[] = {
            125440,
            64000,
            10000,
            10000,
            60000,
            0,
            1000,
            0
        };
#endif

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    MpipeThreadVars *ptv = SCThreadMalloc(tv, sizeof(MpipeThreadVars));
    if (ptv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    memset(ptv, 0, sizeof(MpipeThreadVars));

    ptv->tv = tv;
    ptv->datalink = LINKTYPE_ETHERNET;

    int result;
    char *link_name = (char *)initdata;
  
    /* Bind to a single cpu. */
    cpu_set_t cpus;
    result = tmc_cpus_get_my_affinity(&cpus);
    VERIFY(result, "tmc_cpus_get_my_affinity()");
    result = tmc_cpus_set_my_cpu(tmc_cpus_find_first_cpu(&cpus));
    VERIFY(result, "tmc_cpus_set_my_cpu()");

    if (rank == 0) {

        if (strcmp(link_name, "multi") == 0) {
            int nlive = LiveGetDeviceCount();
            //printf("nlive: %d\n", nlive);
            //printf("device 0: %d\n", LiveGetDeviceName(0));
            int instance = gxio_mpipe_link_instance(LiveGetDeviceName(0));
            for (int i = 1; i < nlive; i++) {
                link_name = LiveGetDeviceName(i);
                if (gxio_mpipe_link_instance(link_name) != instance) {
                    SCLogError(SC_ERR_INVALID_ARGUMENT, "All interfaces not on same mpipe instrance");
                    SCReturnInt(TM_ECODE_FAILED);
                }
            }
            gxio_mpipe_init(context, instance);
            VERIFY(result, "gxio_mpipe_init()");
            for (int i = 0; i < nlive; i++) {
                gxio_mpipe_link_t link;
                link_name = LiveGetDeviceName(i);
                SCLogInfo("opening interface %s", link_name);
                result = gxio_mpipe_link_open(&link, context, link_name, 0);
                VERIFY(result, "gxio_mpipe_link_open()");
            }
        } else {
            SCLogInfo("using single interface %s", (char *)initdata);

            /* Start the driver. */
            result = gxio_mpipe_init(context, gxio_mpipe_link_instance(link_name));
            VERIFY(result, "gxio_mpipe_init()");

            gxio_mpipe_link_t link;
            result = gxio_mpipe_link_open(&link, context, link_name, 0);
            VERIFY(result, "gxio_mpipe_link_open()");
        }

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

        /*
        SCLogInfo("DEBUG: sizeof(gxio_mpipe_idesc_t) %ld\n",
                   sizeof(gxio_mpipe_idesc_t));
        SCLogInfo("DEBUG: getpagesize() %d\n", getpagesize());
        SCLogInfo("DEBUG: idesc/page %ld\n",
                  getpagesize()/sizeof(gxio_mpipe_idesc_t));
        */
        /* Init the NotifRings. */
#if 0
        size_t notif_ring_entries = 65536;
#else
        size_t notif_ring_entries = 2048;
#endif
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

        /* Count required buffer stacks */
        for (unsigned int i = 0;
             i < sizeof(gxio_buffer_sizes)/sizeof(gxio_buffer_sizes[0]);
             i++) {
#if 1
            if (buffer_scale[i].mul != 0)
#else
            if (buffer_counts[i] != 0)
#endif
                ++stack_count;
        }
        SCLogInfo("DEBUG: %u non-zero sized stacks", stack_count);
        SCLogInfo("DEBUG: tile_vhuge_size %lu", tile_vhuge_size);

        /* Allocate one very huge page to hold our buffer stack, notif ring, and
         * packets.  This should be more than enough space. */
        tmc_alloc_t alloc = TMC_ALLOC_INIT;
        tmc_alloc_set_huge(&alloc);
        tmc_alloc_set_home(&alloc, TMC_ALLOC_HOME_HASH);
        if (tmc_alloc_set_pagesize_exact(&alloc, tile_vhuge_size) == NULL) {
            SCLogInfo("Could not allocate packet buffers from very huge page.");
            tmc_alloc_set_pagesize(&alloc, tile_vhuge_size);
        }
        void *page = tmc_alloc_map(&alloc, tile_vhuge_size);
        assert(page);
        void* mem = page;

        /* Allocate a NotifGroup. */
        result = gxio_mpipe_alloc_notif_groups(context, 1, 0, 0);
        VERIFY(result, "gxio_mpipe_alloc_notif_groups()");
        int group = result;

        /* Allocate a bucket. */
        int num_buckets = 4096;
        result = gxio_mpipe_alloc_buckets(context, num_buckets, 0, 0);
        VERIFY(result, "gxio_mpipe_alloc_buckets()");
        int bucket = result;

        /* Init group and buckets, preserving packet order among flows. */
#ifdef LATE_MPIPE_CREDIT
        gxio_mpipe_bucket_mode_t mode = GXIO_MPIPE_BUCKET_DYNAMIC_FLOW_AFFINITY;
#else
        gxio_mpipe_bucket_mode_t mode = GXIO_MPIPE_BUCKET_STATIC_FLOW_AFFINITY;
#endif
        result = gxio_mpipe_init_notif_group_and_buckets(context, group,
                                                   ring, num_workers,
                                                   bucket, num_buckets, mode);
        VERIFY(result, "gxio_mpipe_init_notif_group_and_buckets()");


        /* Allocate a buffer stack. */
        result = gxio_mpipe_alloc_buffer_stacks(context, stack_count, 0, 0);
        VERIFY(result, "gxio_mpipe_alloc_buffer_stacks()");
        int stack = result;
        first_stack = (uint16_t)stack;
	/*SCLogInfo("DEBUG: initial stack at %d", stack);*/

        unsigned int i = 0;
        for (unsigned int stackidx = stack;
             stackidx < stack + stack_count;
             stackidx++, i++) {

#if 1
            for (;buffer_scale[i].mul == 0; i++) ;
#else
            for (;buffer_counts[i] == 0; i++) ;
#endif

	    size_t stack_mem = tile_vhuge_size * buffer_scale[i].mul / buffer_scale[i].div;
            //total_buffers = buffer_counts[i];
            //total_buffers = stack_mem / buffer_sizes[i];
            num_buffers = stack_mem / buffer_sizes[i];
            unsigned buffer_size = buffer_sizes[i];

            SCLogInfo("Initializing stackidx %d i %d size %d buffers %d",
                     stackidx, i, buffer_size, num_buffers);

            /* Initialize the buffer stack. Must be aligned mod 64K. */
            ALIGN(mem, 0x10000);
            size_t stack_bytes = gxio_mpipe_calc_buffer_stack_bytes(num_buffers);
            gxio_mpipe_buffer_size_enum_t buf_size = gxio_buffer_sizes[i];
            result = gxio_mpipe_init_buffer_stack(context, stackidx, buf_size,
                                                  mem, stack_bytes, 0);
            VERIFY(result, "gxio_mpipe_init_buffer_stack()");
            mem += stack_bytes;

            ALIGN(mem, 0x10000);

            SCLogInfo("stack_bytes %lu", stack_bytes);
            stack_bytes = (stack_bytes + (0x10000)) & ~(0x10000-1);
            SCLogInfo("rounded stack_bytes %lu", stack_bytes);

            /* Register the entire huge page of memory which contains all
             * the buffers.
             */
            result = gxio_mpipe_register_page(context, stackidx, page,
                                              tile_vhuge_size, 0);
            VERIFY(result, "gxio_mpipe_register_page()");

            num_buffers -= ((stack_bytes / buffer_sizes[i]) + 1);

            total_buffers += num_buffers;

    	    SCLogInfo("Adding %d %d byte packet buffers",
                      num_buffers, buffer_size);

            /* Push some buffers onto the stack. */
            for (unsigned int j = 0; j < num_buffers; j++)
            {
                gxio_mpipe_push_buffer(context, stackidx, mem);
                mem += buffer_size;
            }

            /* Paranoia. */
            assert(mem <= page + tile_vhuge_size);

        }
    	SCLogInfo("%d total packet buffers", total_buffers);

        /* Register for packets. */
        gxio_mpipe_rules_t rules;
        gxio_mpipe_rules_init(&rules, context);
        gxio_mpipe_rules_begin(&rules, bucket, num_buckets, NULL);
        result = gxio_mpipe_rules_commit(&rules);
        VERIFY(result, "gxio_mpipe_rules_commit()");
    }

    MpipeRegisterPerfCounters(ptv, tv);

    tmc_sync_barrier_wait(&barrier);

    //SCLogInfo("ReceiveMpipe-%d initialization complete!!!", rank);
    *data = (void *)ptv;
    SCReturnInt(TM_ECODE_OK);
}

TmEcode ReceiveMpipeInit(void) {
    SCEnter();

    SCLogInfo("TileNumPipelines: %d", TileNumPipelines);
    tmc_sync_barrier_init(&barrier, TileNumPipelines/2);

    SCReturnInt(TM_ECODE_OK);
}

TmEcode ReceiveMpipeGo(void) {
    SCEnter();

    /* Turn on all the links on mpipe0. */
    sim_enable_mpipe_links(0, -1);

#ifdef __TILEGX_SIMULATION__
    /* Clear any old profiler data */
    sim_profiler_clear();

    /* Enable the profiler */
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

    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;
    /*SCLogInfo("DecodeMpipeThreadInit");*/

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
#if 0
    SCPerfCounterAddDouble(dtv->counter_bytes_per_sec, tv->sc_perf_pca, p->pktlen);
    SCPerfCounterAddDouble(dtv->counter_mbit_per_sec, tv->sc_perf_pca,
                           (p->pktlen * 8)/1000000.0);
#endif

    SCPerfCounterAddUI64(dtv->counter_avg_pkt_size, tv->sc_perf_pca, p->pktlen);
    SCPerfCounterSetUI64(dtv->counter_max_pkt_size, tv->sc_perf_pca, p->pktlen);

    /* call the decoder */
    switch(p->datalink) {
    case LINKTYPE_ETHERNET:
        DecodeEthernet(tv, dtv, p, p->pkt, p->pktlen, pq);
        break;
    default:
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
