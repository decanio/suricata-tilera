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
#include "host.h"
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
#include "util-profiling.h"
#include "tmqh-packetpool.h"
#include "pkt-var.h"

#ifdef __tilegx__
#include <mde-version.h>
#include <tmc/alloc.h>
#include <arch/sim.h>
#include <arch/atomic.h>
#include <arch/cycle.h>
#include <gxio/mpipe.h>
#include <gxio/trio.h>
#if MDE_VERSION_CODE >= MDE_VERSION(4,1,0)
#include <gxpci/gxpci.h>
#else
#include <gxpci.h>
#endif
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
#define max(a,b) (((a) > (b)) ? (a) : (b))

extern uint8_t suricata_ctl_flags;
extern int rule_reload;
extern intmax_t max_pending_packets;
extern size_t tile_vhuge_size;
void *tile_packet_page = NULL;
Packet *empty_p = NULL;

/*
 * Borrowed from pcap.h
 */
struct mpipe_pcap_pkthdr {
        //struct timeval ts;      /* time stamp */
        uint32_t ts_secs;    /* time stamp */
        uint32_t ts_nsecs;   /* time stamp */
        uint32_t caplen;     /* length of portion present */
        uint32_t len;        /* length this packet (off wire) */
} __attribute__((packed));

/** storage for mpipe device names */
typedef struct MpipeDevice_ {
    char *dev;  /**< the device (e.g. "xgbe1") */
    TAILQ_ENTRY(MpipeDevice_) next;
} MpipeDevice;

typedef enum capture_mode { off=0, pcap, idesc } capture_mode_t;
typedef enum timestamp_mode { ts_mpipe, ts_linux } timestamp_mode_t;

/** private device list */
static TAILQ_HEAD(, MpipeDevice_) mpipe_devices =
    TAILQ_HEAD_INITIALIZER(mpipe_devices);

static tmc_sync_barrier_t barrier;
static uint16_t first_stack;
static capture_mode_t capture_enabled = off;
static timestamp_mode_t timestamp = ts_linux;
static uint32_t headroom = 2;

/**
 * \brief Structure to hold thread specifc variables.
 */
typedef struct MpipeThreadVars_
{
    /* data link type for the thread */
    int datalink;

    ChecksumValidationMode checksum_mode;

    /* counters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;

    ThreadVars *tv;
    TmSlot *slot;

    Packet *in_p;

    /** stats/counters */
    uint16_t max_mpipe_depth0;
    uint16_t max_mpipe_depth1;
    uint16_t counter_no_buffers_0;
    uint16_t counter_no_buffers_1;
    uint16_t counter_no_buffers_2;
    uint16_t counter_no_buffers_3;
    uint16_t counter_no_buffers_4;
    uint16_t counter_no_buffers_5;
    uint16_t counter_no_buffers_6;
    uint16_t counter_no_buffers_7;
    uint16_t counter_capture_overrun;

} MpipeThreadVars;

TmEcode ReceiveMpipeLoop(ThreadVars *tv, void *data, void *slot);
TmEcode ReceiveMpipeLoopPair(ThreadVars *tv, void *data, void *slot);
TmEcode ReceiveMpipeThreadInit(ThreadVars *, void *, void **);
void ReceiveMpipeThreadExitStats(ThreadVars *, void *);

TmEcode DecodeMpipeThreadInit(ThreadVars *, void *, void **);
TmEcode DecodeMpipe(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

#define PIPELINES 6       /* fix this. look elsewhere */
#define MAX_INTERFACES 4  /* can probably find this in the MDE */
#define MAX_CHANNELS 32   /* can probably find this in the MDE */

/*
 * mpipe configuration.
 */

/* The mpipe context (shared by all workers) */
static gxio_mpipe_context_t context_body;
static gxio_mpipe_context_t* context = &context_body;

/* The ingress queues (one per worker) */
static gxio_mpipe_iqueue_t** iqueues;

/* The egress queues (one per port) */
static gxio_mpipe_equeue_t equeue_body[MAX_INTERFACES];
static gxio_mpipe_equeue_t *equeue[MAX_INTERFACES];

/* the number of entries in an equeue ring */
static const int equeue_entries = 2048;

/* Array of mpipe links */
static gxio_mpipe_link_t mpipe_link[MAX_INTERFACES];

/* Per interface configuration data */
static MpipeIfaceConfig *mpipe_conf[MAX_INTERFACES];

/* Per interface TAP/IPS configuration */
//static MpipePeerVars mpipe_iface[MAX_CHANNELS];

/* egress equeue associated with each ingress channel */
//static gxio_mpipe_equeue_t *channel_to_equeue[MAX_CHANNELS];
static MpipePeerVars channel_to_equeue[MAX_CHANNELS];

/*
 * trio configuration.
 */
static gxio_trio_context_t trio_context_body;
static gxio_trio_context_t* trio_context = &trio_context_body;
static int trio_inited = 0;

#define MAX_TILES 36

/*
 * gxpci packet queue contexts used for packet capture (one per pipeline)
 */
static gxpci_context_t gxpci_context_body[PIPELINES];
static gxpci_context_t* gxpci_context[PIPELINES];
static int *inflight[MAX_TILES];

/*
 * gxpci raw dma contexts used for log relay
 */
static gxpci_context_t gxpci_raw_context_body;
static gxpci_context_t *gxpci_raw_context = &gxpci_raw_context_body;

/* The TRIO index. */
static int trio_index = 0;

/* The queue index of a packet queue. */
static int queue_index = 0;

/* The local MAC index. */
static int loc_mac;

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
    tmm_modules[TMM_DECODEMPIPE].flags = TM_FLAG_DECODE_TM;
}

void MpipeFreePacket(void *arg) {
    Packet *p = (Packet *)arg;
    int result;
#ifdef LATE_MPIPE_CREDIT
    gxio_mpipe_iqueue_t* iqueue = iqueues[p->mpipe_v.pool];
#ifdef LATE_MPIPE_BUCKET_CREDIT
    gxio_mpipe_credit(iqueue->context, -1, p->mpipe_v.idesc.bucket_id, 1);
#else
    //gxio_mpipe_iqueue_release(iqueue, &p->idesc);
    int bucket = p->mpipe_v.idesc.nr ? -1 : p->mpipe_v.idesc.bucket_id;
    gxio_mpipe_credit(iqueue->context, iqueue->ring, bucket, 1);
#endif
#endif
    if (unlikely(capture_enabled)) {
        int *ptr;
        if ((ptr = inflight[p->mpipe_v.pool])) {
            arch_atomic_decrement(&inflight[p->mpipe_v.pool]);
        }
    }
    if (unlikely(p->mpipe_v.copy_mode == MPIPE_COPY_MODE_IPS)) {
        if (unlikely(p->action & ACTION_DROP)) {
            goto drop;
        }
        gxio_mpipe_edesc_t edesc;
        edesc.words[0] = 0;
        edesc.words[1] = 0;
        edesc.bound = 1;
        edesc.xfer_size = p->mpipe_v.idesc.l2_size;
        edesc.va = p->mpipe_v.idesc.va;
        edesc.stack_idx = p->mpipe_v.idesc.stack_idx;
        edesc.hwb = 1;
        edesc.size = p->mpipe_v.idesc.size;
//printf("Freeing packet from channel %d\n", p->mpipe_v.idesc.channel);
//printf("equeue[channel] %p\n", channel_to_equeue[p->mpipe_v.idesc.channel]);
//goto drop;
        result = gxio_mpipe_equeue_put(channel_to_equeue[p->mpipe_v.idesc.channel].peer_equeue, edesc);
        if (unlikely(result != 0)) {
            SCLogInfo("mpipe equeue put failed: %d", result);
        }
    } else if (unlikely(p->mpipe_v.copy_mode == MPIPE_COPY_MODE_TAP)) {
        gxio_mpipe_edesc_t edesc;
        edesc.words[0] = 0;
        edesc.words[1] = 0;
        edesc.bound = 1;
        edesc.xfer_size = p->mpipe_v.idesc.l2_size;
        edesc.va = p->mpipe_v.idesc.va;
        edesc.stack_idx = p->mpipe_v.idesc.stack_idx;
        edesc.hwb = 1;
        edesc.size = p->mpipe_v.idesc.size;
//printf("Freeing packet from channel %d\n", p->mpipe_v.idesc.channel);
//printf("equeue[channel] %p\n", channel_to_equeue[p->mpipe_v.idesc.channel]);
//goto drop;
        result = gxio_mpipe_equeue_put(channel_to_equeue[p->mpipe_v.idesc.channel].peer_equeue, edesc);
        if (unlikely(result != 0)) {
            SCLogInfo("mpipe equeue put failed: %d", result);
        }
    } else {
drop:
        gxio_mpipe_push_buffer(context,
                               p->mpipe_v.idesc.stack_idx,
                               (void *)(intptr_t)p->mpipe_v.idesc.va);
    }

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
static inline Packet *MpipeProcessPacket(MpipeThreadVars *ptv, gxio_mpipe_idesc_t *idesc, struct timeval *tv) {
    int caplen = idesc->l2_size;
    u_char *pkt = gxio_mpipe_idesc_get_va(idesc);
    Packet *p = (Packet *)(pkt - sizeof(Packet) - headroom/*2*/);

    PACKET_RECYCLE(p);

    ptv->bytes += caplen;
    ptv->pkts++;

    if (tv) {
        p->ts = *tv;
    } else {
        p->ts_nsec.tv_sec = idesc->time_stamp_sec;
        p->ts_nsec.tv_nsec = idesc->time_stamp_ns;
    }
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
    p->mpipe_v.idesc.bucket_id = idesc->bucket_id;
    p->mpipe_v.idesc.nr = idesc->nr;
    p->mpipe_v.idesc.cs = idesc->cs;
    p->mpipe_v.idesc.va = idesc->va;
    p->mpipe_v.idesc.stack_idx = idesc->stack_idx;
    if (unlikely((p->mpipe_v.copy_mode = channel_to_equeue[idesc->channel].copy_mode) !=
             MPIPE_COPY_MODE_NONE)) {
        p->mpipe_v.idesc.size = idesc->size;
        p->mpipe_v.idesc.l2_size = idesc->l2_size;
        p->mpipe_v.idesc.channel = idesc->channel;
//printf("rx on chan: %d %d\n",        p->mpipe_v.idesc.channel, idesc->channel);
        //p->mpipe_v.copy_mode = channel_to_equeue[idesc->channel].copy_mode;
    }


    if (ptv->checksum_mode == CHECKSUM_VALIDATION_DISABLE)
        p->flags |= PKT_IGNORE_CHECKSUM;

    return p;
}

static inline Packet *MpipePrepPacket(MpipeThreadVars *ptv, gxio_mpipe_idesc_t *idesc, struct timeval *tv) {
    int caplen = idesc->l2_size;
    u_char *pkt = gxio_mpipe_idesc_get_va(idesc);
    Packet *p = (Packet *)(pkt - sizeof(Packet) - headroom/*2*/);

    PACKET_RECYCLE(p);

    ptv->bytes += caplen;
    ptv->pkts++;

    if (tv) {
        p->ts = *tv;
    } else {
        p->ts_nsec.tv_sec = idesc->time_stamp_sec;
        p->ts_nsec.tv_nsec = idesc->time_stamp_ns;
    }
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
    p->mpipe_v.idesc.bucket_id = idesc->bucket_id;
    p->mpipe_v.idesc.nr = idesc->nr;
    p->mpipe_v.idesc.cs = idesc->cs;
    p->mpipe_v.idesc.va = idesc->va;
    p->mpipe_v.idesc.size = idesc->size;
    p->mpipe_v.idesc.stack_idx = idesc->stack_idx;
    p->mpipe_v.idesc.l2_size = idesc->l2_size;
    p->mpipe_v.idesc.channel = idesc->channel;

    p->mpipe_v.copy_mode = channel_to_equeue[idesc->channel].copy_mode;

    if (ptv->checksum_mode == CHECKSUM_VALIDATION_DISABLE)
        p->flags |= PKT_IGNORE_CHECKSUM;

    return p;
}

#if 0
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
#endif

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
                SCPerfCounterSetUI64(ptv->max_mpipe_depth0, tv->sc_perf_pca,
                                     (uint64_t)n);
                for (i = 0; i < m; i++, idesc++) {
                    if (likely(!idesc->be)) {
                        p = MpipeProcessPacket(ptv, idesc, (timestamp == ts_linux) ? &timeval : NULL);
                        p->mpipe_v.pool = rank;
                        TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p);
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
                if (timestamp == ts_linux) {
                    tilera_fast_gettimeofday(&timeval);
                }
                if (suricata_ctl_flags & (SURICATA_STOP | SURICATA_KILL)) {
                    SCReturnInt(TM_ECODE_FAILED);
                }
            }
        }
        SCPerfSyncCountersIfSignalled(tv, 0);
    }

    SCReturnInt(TM_ECODE_OK);
}

static TmEcode ReceiveMpipePollPair(ThreadVars *tv, MpipeThreadVars *ptv,
                                    TmSlot *s, int nqueues)
{
    struct timeval timeval;
    gxio_mpipe_iqueue_t* iqueue;
    gxio_mpipe_idesc_t *idesc;
    ptv->slot = s->slot_next;
    Packet *p;
    char run = 1;
    int cpu = tmc_cpus_get_my_cpu();
    int rank = cpu-1;
    int max[2];

    if (rank == 0) {
        /* Make pattern memory read only, but only if rule-reload is disabled */
        if (rule_reload == 0) {
            SCMpmFreeze();
        }
        SCLogInfo("suricata is ready to process network traffic");
    }

    tilera_fast_gettimeofday(&timeval);

    max[0] = 0;
    max[1] = 0;

    while (run) {
        int i;
        int t;

        if (suricata_ctl_flags & (SURICATA_STOP | SURICATA_KILL)) {
            SCReturnInt(TM_ECODE_FAILED);
        }

        for (i = 0, t = 0; i < nqueues; i++) {
            int pool;
            if (nqueues == 2)
                pool = (rank * 2) + i;
            else
                pool = rank + i;
             

            iqueue = iqueues[pool];

            //SCLogInfo("Polling pool %d rank %d queue %d", pool, rank, i);
            int n = gxio_mpipe_iqueue_try_peek(iqueue, &idesc);
            if (likely(n > 0)) {
                int j; int m;
                t += n;

                //SCLogInfo("Got %d packets for pool %d", n, pool);
                m = min(n, 4);

                /* Prefetch the idescs (64 bytes each). */
                for (j = 0; j < m; j++) {
                    __insn_prefetch(&idesc[j]);
                }

                if (unlikely(n > max[i])) {
                    SCPerfCounterSetUI64((i == 0) ? ptv->max_mpipe_depth0 :
                                                    ptv->max_mpipe_depth1,
                                         tv->sc_perf_pca,
                                         (uint64_t)n);
                    max[i] = n;
                }

                for (j = 0; j < m; j++, idesc++) {
                    if (likely(!idesc->be)) {
                        p = MpipeProcessPacket(ptv, idesc, (timestamp == ts_linux) ? &timeval : NULL);
                        p->mpipe_v.pool = pool;
                        TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p);
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
            }
        }
        SCPerfSyncCountersIfSignalled(tv, 0);
        if (t == 0) {
            if (timestamp == ts_linux) {
                tilera_fast_gettimeofday(&timeval);
            }
        }
        if (TmThreadsCheckFlag(tv, THV_KILL)) {
            run = 0;
        }
    }
    TmThreadsSetFlag(tv, THV_CLOSED);
    SCLogInfo("cpu: %d rank: %d fell out of loop", cpu, rank);
    SCReturnInt(TM_ECODE_OK);
}

#define MAX_CMDS_BATCH 64
#define MAX_PCI_CHANNELS 6

static TmEcode ReceiveMpipeCapturePollPair(ThreadVars *tv, MpipeThreadVars *ptv,
                                           TmSlot *s, int nqueues)
{
    gxpci_comp_t comp[MAX_CMDS_BATCH];
    gxpci_cmd_t cmd[MAX_CMDS_BATCH];
    struct timeval timeval;
    gxio_mpipe_iqueue_t* iqueue;
    gxio_mpipe_idesc_t *idesc;
    gxpci_context_t* gxpci_ctxt;
    ptv->slot = s->slot_next;
    Packet *p;
    int cpu = tmc_cpus_get_my_cpu();
    int rank = cpu-1;
    int result;
    int i;
    capture_mode_t capture_mode = capture_enabled; /* grab cache local copy */
    timestamp_mode_t timestamp_mode = timestamp; /* grab cache local copy */
    int max[2];
    int max_inflight = max_pending_packets / TileNumPipelines;
    int cur_inflight[2];

    SCLogInfo("cpu: %d rank: %d", cpu, rank);

    tilera_fast_gettimeofday(&timeval);

    max[0] = 0;
    max[1] = 0;
    cur_inflight[0] = 0;
    cur_inflight[1] = 0;
    for(i = 0; i < nqueues; i++) {
        inflight[(rank*nqueues) + i] = &cur_inflight[i];
    }

    for (;;) {
        int i;
        int t;

        if (suricata_ctl_flags & (SURICATA_STOP | SURICATA_KILL)) {
            SCReturnInt(TM_ECODE_FAILED);
        }

        for (i = 0, t = 0; i < nqueues; i++) {
            int pool;
            if (nqueues == 2)
                pool = (rank * 2) + i;
            else
                pool = rank + i;

            iqueue = iqueues[pool];

            //SCLogInfo("Polling pool %d rank %d queue %d", pool, rank, i);
            int n = gxio_mpipe_iqueue_try_peek(iqueue, &idesc);
            if (likely(n > 0)) {
                int j; int m;
                t += n;

                //SCLogInfo("Got %d packets for pool %d %p", n, pool,
                //          gxio_mpipe_idesc_get_va(idesc));

                m = min(n, 16);

                /* Prefetch the idescs (64 bytes each). */
                for (j = 0; j < m; j++) {
                    __insn_prefetch(&idesc[j]);
                }
                if (unlikely(n > max[i])) {
                    SCPerfCounterSetUI64((i == 0) ? ptv->max_mpipe_depth0 :
                                                    ptv->max_mpipe_depth1,
                                         tv->sc_perf_pca,
                                         (uint64_t)n);
                    max[i] = n;
                }
                /* HACK: cant seem to open more than 4 channels */
                if (likely(pool < MAX_PCI_CHANNELS)) {
                    gxpci_ctxt = gxpci_context[pool];
                    int credits = gxpci_get_cmd_credits(gxpci_ctxt);
                    if (unlikely(credits == GXPCI_ERESET)) {
                        SCLogInfo("gxpci channel %d is reset", pool);
                        SCReturnInt(TM_ECODE_FAILED);
                    }
                    m = min(m, credits);
                    for (j = 0; j < m; j++, idesc++) {
                        if (likely(!idesc->be)) {
                            unsigned char *pkt = gxio_mpipe_idesc_get_va(idesc);
                            uint32_t caplen;
                            caplen = min(idesc->l2_size, 4096 - sizeof(struct mpipe_pcap_pkthdr));

                            if (capture_mode == pcap) {
                                struct mpipe_pcap_pkthdr *pcap = 
                                cmd[j].buffer = pkt-sizeof(struct mpipe_pcap_pkthdr);
                                cmd[j].size = caplen + sizeof(struct mpipe_pcap_pkthdr);
                                /* build pcap header from idesc */
                                pcap->ts_secs = idesc->time_stamp_sec;
                                pcap->ts_nsecs = idesc->time_stamp_ns;
                                pcap->caplen = caplen;
                                pcap->len = idesc->l2_size;
                            } else {
                                cmd[j].buffer = pkt-sizeof(gxio_mpipe_idesc_t);
                                cmd[j].size = caplen + sizeof(gxio_mpipe_idesc_t);

                                /* prepend idesc in headroom */
                                memcpy(pkt - sizeof(gxio_mpipe_idesc_t),
                                       idesc,
                                       sizeof(gxio_mpipe_idesc_t));
                            }

                            __insn_mf();

                            //SCLogInfo("Sending %d length packet to queue %d",
                            //          idesc->l2_size, pool);
                            result = gxpci_pq_t2h_cmd(gxpci_ctxt, &cmd[j]);
                            if (unlikely(credits == GXPCI_ERESET)) {
                                SCLogInfo("gxpci channel %d is reset", pool);
                                SCReturnInt(TM_ECODE_FAILED);
                            }

                            p = MpipePrepPacket(ptv, idesc, (timestamp_mode == ts_linux) ? &timeval : NULL);
                            p->mpipe_v.pool = pool;

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
                    for (j = 0; j < m; j++, idesc++) {
                        if (likely(!idesc->be)) {
                            p = MpipeProcessPacket(ptv,  idesc, (timestamp_mode == ts_linux) ? &timeval : NULL);
                            p->mpipe_v.pool = pool;
                            TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p);
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
                }
            }
            /* HACK: cant seem to open more than 4 channels */
            if (pool < MAX_PCI_CHANNELS) {
                result = gxpci_get_comps(gxpci_context[pool], comp, 0,
                                         MAX_CMDS_BATCH);
                if (unlikely(result == GXPCI_ERESET)) {
                    SCLogInfo("gxpci channel %d is reset", pool);
                    SCReturnInt(TM_ECODE_FAILED);
                } else if (result > 0) {
                    int j;

                    //SCLogInfo("gxpci channel %d received %d completions",
                    //          pool, result);
                    for (j = 0; j < result; j++) {
                        u_char *pkt = comp[j].buffer + headroom - 2;
                        Packet *p = (Packet *)(pkt - sizeof(Packet) - headroom/*2*/);
                        if (arch_atomic_increment(&cur_inflight[i]) < max_inflight) {
                            TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p);
                        } else {
                            MpipeFreePacket(p);
                            SCPerfCounterIncr(ptv->counter_capture_overrun,
                                              tv->sc_perf_pca);
                        }
                    }
                }
            }
        }
        SCPerfSyncCountersIfSignalled(tv, 0);
        if (timestamp_mode == ts_linux) {
            if (t == 0) {
                tilera_fast_gettimeofday(&timeval);
            }
        }
    }
    SCReturnInt(TM_ECODE_OK);
}

TmEcode ReceiveMpipeLoopPair(ThreadVars *tv, void *data, void *slot) {
    MpipeThreadVars *ptv = (MpipeThreadVars *)data;
    TmSlot *s = (TmSlot *)slot;
    intmax_t value = 0;
    int nqueue = 2;
    char *ctype;
    char *runmode;
    TmEcode rc;

    SCEnter();

    if (ConfGet("runmode", &runmode) == 1) {
        if (strcmp(runmode, "workers") == 0) {
	    nqueue = 1;
        }
    }

    if ((nqueue == 2) && (ConfGetInt("mpipe.poll", &value) == 1)) {
        /* only 1 and 2 are permitted */
        if ((value >= 1) && (value <= 2)) {
            nqueue = (int) value;
        } else {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Illegal mpipe.poll value.");
        }
    }

    ptv->checksum_mode = CHECKSUM_VALIDATION_DISABLE;
    if (ConfGet("mpipe.checksum-checks", &ctype) == 1) {
        if (strcmp(ctype, "yes") == 0) {
            ptv->checksum_mode = CHECKSUM_VALIDATION_ENABLE;
        } else if (strcmp(ctype, "no") == 0)  {
            ptv->checksum_mode = CHECKSUM_VALIDATION_DISABLE;
        } else {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid value for checksum-check for mpipe");
        }
    }

    if (capture_enabled != off)
        rc = ReceiveMpipeCapturePollPair(tv, ptv, s, nqueue);
    else
        rc = ReceiveMpipePollPair(tv, ptv, s, nqueue);
   
    SCReturnInt(rc);
}

TmEcode MpipeRegisterPipeStage(void *td) {
    SCEnter()

    SCReturnInt(TM_ECODE_OK);
}

static void MpipeRegisterPerfCounters(MpipeThreadVars *ptv, ThreadVars *tv) {
    /* register counters */
#if 1
    /* faster to calculate max inside source-mpipe */
    ptv->max_mpipe_depth0 = SCPerfTVRegisterCounter("mpipe.max_mpipe_depth0",
                                                    tv,
                                                    SC_PERF_TYPE_UINT64,
                                                    "NULL");
    ptv->max_mpipe_depth1 = SCPerfTVRegisterCounter("mpipe.max_mpipe_depth1",
                                                    tv,
                                                    SC_PERF_TYPE_UINT64,
                                                    "NULL");
#else
    ptv->max_mpipe_depth0 = SCPerfTVRegisterMaxCounter("mpipe.max_mpipe_depth0",
                                                       tv,
                                                       SC_PERF_TYPE_UINT64,
                                                       "NULL");
    ptv->max_mpipe_depth1 = SCPerfTVRegisterMaxCounter("mpipe.max_mpipe_depth1",
                                                       tv,
                                                       SC_PERF_TYPE_UINT64,
                                                       "NULL");
#endif
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
    ptv->counter_capture_overrun =
                        SCPerfTVRegisterCounter("mpipe.capture_overrun", tv,
                                                SC_PERF_TYPE_UINT64,
                                                "NULL");

   tv->sc_perf_pca = SCPerfGetAllCountersArray(tv, &tv->sc_perf_pctx);
   SCPerfAddToClubbedTMTable(tv->name, &tv->sc_perf_pctx);
}
static const gxio_mpipe_buffer_size_enum_t gxio_buffer_sizes[] = {
            GXIO_MPIPE_BUFFER_SIZE_128,
            GXIO_MPIPE_BUFFER_SIZE_256,
            GXIO_MPIPE_BUFFER_SIZE_512,
            GXIO_MPIPE_BUFFER_SIZE_1024,
            GXIO_MPIPE_BUFFER_SIZE_1664,
            GXIO_MPIPE_BUFFER_SIZE_4096,
            GXIO_MPIPE_BUFFER_SIZE_10368,
            GXIO_MPIPE_BUFFER_SIZE_16384
        };

static const unsigned int buffer_sizes[] = {
            128,
            256,
            512,
            1024,
            1664,
            4096,
            10368,
            16384
        };

static struct {
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


TmEcode ReceiveMpipeThreadInit(ThreadVars *tv, void *initdata, void **data) {
    SCEnter()
    int cpu = tmc_cpus_get_my_cpu();
    int rank = (cpu-1);
    unsigned int num_buffers;
    int num_buckets = 4096; 
    unsigned int total_buffers = 0;
    unsigned int num_workers = TileNumPipelines /*DFLT_TILERA_MPIPE_PIPELINES*/;
    unsigned int stack_count = 0;
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
        unsigned int i = 0;
        for (i = 0; i < sizeof(inflight)/sizeof(inflight[0]); i++) {
            inflight[i] = NULL;
        }

        if (ConfGetNode("mpipe.stack") != NULL) {
       	    char *ratio;
            unsigned i;
            for (i = 0; i < (sizeof(buffer_scale)/sizeof(buffer_scale[0])); i++)
    	        buffer_scale[i].mul = buffer_scale[i].div = 0;
	    if (ConfGet("mpipe.stack.size128", &ratio)) {
		sscanf(ratio, "%d/%d", &buffer_scale[0].mul,
                                       &buffer_scale[0].div);
	    }
	    if (ConfGet("mpipe.stack.size256", &ratio)) {
		sscanf(ratio, "%d/%d", &buffer_scale[1].mul,
                                       &buffer_scale[1].div);
	    }
	    if (ConfGet("mpipe.stack.size512", &ratio)) {
		sscanf(ratio, "%d/%d", &buffer_scale[2].mul,
                                       &buffer_scale[2].div);
	    }
	    if (ConfGet("mpipe.stack.size1024", &ratio)) {
		sscanf(ratio, "%d/%d", &buffer_scale[3].mul,
                                       &buffer_scale[3].div);
	    }
	    if (ConfGet("mpipe.stack.size1664", &ratio)) {
		sscanf(ratio, "%d/%d", &buffer_scale[4].mul,
                                       &buffer_scale[4].div);
	    }
	    if (ConfGet("mpipe.stack.size4096", &ratio)) {
		sscanf(ratio, "%d/%d", &buffer_scale[5].mul,
                                       &buffer_scale[5].div);
	    }
	    if (ConfGet("mpipe.stack.size10386", &ratio)) {
		sscanf(ratio, "%d/%d", &buffer_scale[6].mul,
                                       &buffer_scale[6].div);
	    }
	    if (ConfGet("mpipe.stack.size16384", &ratio)) {
		sscanf(ratio, "%d/%d", &buffer_scale[7].mul,
                                       &buffer_scale[7].div);
	    }
	    /*
            for (i = 0; i < (sizeof(buffer_scale)/sizeof(buffer_scale[0])); i++)
		printf("%u %d/%d\n", i, buffer_scale[i].mul,
                                        buffer_scale[i].div);
            */
            /* TBD.  Do some checking to make sure the ratios don't 
             * add up to more than 1.
             */
        }
        char *ts;
        if (ConfGet("mpipe.timestamp", &ts) == 1) {
            if (strcmp(ts, "mpipe") == 0) {
                timestamp = ts_mpipe;
                SCLogInfo("Applying mpipe timestamps");
            } else if (strcmp(ts, "linux") == 0) {
                timestamp = ts_linux;
                SCLogInfo("Applying Linux timestamps");
            } else {
                SCLogError(SC_ERR_FATAL, "Illegal mpipe.timestamp value.");
            }
        }
        intmax_t value = 0;
        if (ConfGetInt("mpipe.buckets", &value) == 1) {
            /* range check */
            if ((value >= 1) && (value <= 4096)) {
                num_buckets = (int) value;
            } else {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "Illegal mpipe.buckets value.");
            }
        }

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
            /* open ingress interfaces */
            for (int i = 0; i < nlive; i++) {
                link_name = LiveGetDeviceName(i);
                SCLogInfo("opening interface %s", link_name);
                result = gxio_mpipe_link_open(&mpipe_link[i], context,
                                              link_name, 0);
                VERIFY(result, "gxio_mpipe_link_open()");
                mpipe_conf[i] = ParseMpipeConfig(link_name);
            }
            /* find and open egress interfaces */
            for (int i = 0; i < nlive; i++) {
                MpipeIfaceConfig *aconf = mpipe_conf[i];
                if (aconf != NULL) {
                    if(aconf->copy_mode != MPIPE_COPY_MODE_NONE) {
                        int channel;
                        /* Initialize and equeue */
                        result = gxio_mpipe_alloc_edma_rings(context, 1, 0, 0);
                        VERIFY(result, "gxio_mpipe_alloc_edma_rings");
                        uint32_t ering = result;
                        size_t edescs_size = equeue_entries *
                                                sizeof(gxio_mpipe_edesc_t);
                        tmc_alloc_t edescs_alloc = TMC_ALLOC_INIT;
                        tmc_alloc_set_pagesize(&edescs_alloc, edescs_size);
                        void *edescs = tmc_alloc_map(&edescs_alloc, edescs_size);
                        if (edescs == NULL) {
                            SCLogError(SC_ERR_FATAL,
                                       "Failed to allocate egress descriptors");
                            SCReturnInt(TM_ECODE_FAILED);
                        }
                        /* retrieve channel of outbound interface */
                        for (int j = 0; j < nlive; j++) {
                            if (strcmp(aconf->out_iface,
                                       mpipe_conf[j]->iface) == 0) {
                                channel = gxio_mpipe_link_channel(&mpipe_link[j]);
                                SCLogInfo("egress link: %s is channel: %d", aconf->out_iface, channel);
                                result = gxio_mpipe_equeue_init(equeue[i],
                                                                context,
                                                                ering,
                                                                channel,
                                                                edescs,
                                                                edescs_size,
                                                                0);
                                VERIFY(result, "gxio_mpipe_equeue_init");
                                channel = gxio_mpipe_link_channel(&mpipe_link[i]);
                                SCLogInfo("ingress link: %s is channel: %d copy_mode: %d", aconf->iface, channel, aconf->copy_mode);
                                channel_to_equeue[channel].peer_equeue = equeue[i];
                                channel_to_equeue[channel].copy_mode = aconf->copy_mode;
                                break;
                            }
                        }
                    }
                }
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
        char *capture;
        if (ConfGet("mpipe.capture.enabled", &capture) == 1) {
            if (capture) {
                if (strcmp(capture, "idesc") == 0) {
                    capture_enabled = idesc;
                    SCLogInfo("Enabling PCIe idesc packet capture mode.");
                } else if (strcmp(capture, "pcap") == 0) {
                    capture_enabled = pcap;
                    SCLogInfo("Enabling PCIe pcap packet capture mode.");
                } else if (strcmp(capture, "no") == 0) {
                    capture_enabled = off;
                    SCLogInfo("Disabling PCIe packet capture.");
                } else {
                    SCLogInfo("Illegal PCIe capture configuration option %s",
                              capture);
                }
            }
        }

        if (capture_enabled != off) {
            result = gxio_trio_init(trio_context, trio_index);
            VERIFY(result, "gxio_trio_init()");
            trio_inited = 1;

            for (queue_index = 0; queue_index < TileNumPipelines; queue_index++) {

                gxpci_context[queue_index] = &gxpci_context_body[queue_index];

                result = gxpci_init(trio_context, gxpci_context[queue_index],
                                    trio_index, loc_mac);
                VERIFY(result, "gxpci_init()");

                /* HACK: cant seem to open more than 4 channels */
                if (queue_index >= MAX_PCI_CHANNELS)
                    continue;
                /*
                 * This indicates that we need to allocate an ASID ourselves,
                 * instead of using one that is allocated somewhere else.
                 */
                int asid = GXIO_ASID_NULL;

                printf("attempting to open queue_index %d\n", queue_index);
                do {
                    result = gxpci_open_queue(gxpci_context[queue_index],
                                              asid,
                                              GXPCI_PQ_T2H,
                                              0,
                                              queue_index,
                                              0,
                                              0);
                    /* retry on timeout */
                } while (result == GXIO_ERR_TIMEOUT);
                VERIFY(result, "gxpci_open_queue()");
                SCLogInfo("pcie queue_index %d opened", queue_index);
            }

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
            tmc_alloc_set_home(&alloc, 1+(i/2));
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
            if (buffer_scale[i].mul != 0)
                ++stack_count;
        }
        SCLogInfo("DEBUG: %u non-zero sized stacks", stack_count);
        SCLogInfo("DEBUG: tile_vhuge_size %lu", tile_vhuge_size);

#if 0
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
        tile_packet_page = page;
#else
        void* page;
        void* mem = page = tile_packet_page;
#endif

        /* Allocate a NotifGroup. */
        result = gxio_mpipe_alloc_notif_groups(context, 1, 0, 0);
        VERIFY(result, "gxio_mpipe_alloc_notif_groups()");
        int group = result;

        /* Allocate a bucket. */
        result = gxio_mpipe_alloc_buckets(context, num_buckets, 0, 0);
        if (result == GXIO_MPIPE_ERR_NO_BUCKET) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                       "Could not allocate mpipe buckets. "
                       "Try a smaller mpipe.buckets value in suricata.yaml");
            tmc_task_die("Could not allocate mpipe buckets");
        }
        int bucket = result;

        /* Init group and buckets, preserving packet order among flows. */
#ifdef LATE_MPIPE_CREDIT
        gxio_mpipe_bucket_mode_t mode = GXIO_MPIPE_BUCKET_STATIC_FLOW_AFFINITY;
        char *balance;
        if (ConfGet("mpipe.load-balance", &balance) == 1) {
            if (balance) {
                if (strcmp(balance, "static") == 0) {
                    mode = GXIO_MPIPE_BUCKET_STATIC_FLOW_AFFINITY;
                    SCLogInfo("Using \"static\" flow affinity.");
                } else if (strcmp(balance, "dynamic") == 0) {
                    mode = GXIO_MPIPE_BUCKET_DYNAMIC_FLOW_AFFINITY;
                    SCLogInfo("Using \"dynamic\" flow affinity.");
                } else {
                    SCLogInfo("Illegal load balancing mode %s using \"static\"",
                              balance);
                }
            }
        }
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

        i = 0;
        for (unsigned int stackidx = stack;
             stackidx < stack + stack_count;
             stackidx++, i++) {

            for (;buffer_scale[i].mul == 0; i++) ;

	    size_t stack_mem = tile_vhuge_size * buffer_scale[i].mul / buffer_scale[i].div;
            unsigned buffer_size = buffer_sizes[i];
            num_buffers = stack_mem / (buffer_size + sizeof(Packet));

            SCLogInfo("Initializing stackidx %d i %d stack_mem %ld size %d buffers %d Packet size %ld",
                     stackidx, i, stack_mem, buffer_size, num_buffers, 
                     sizeof(Packet));

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

            if ((capture_enabled != off) && (stackidx == stack)) {
                int i;
		for (i = 0; i < TileNumPipelines; i++) {
    	            SCLogInfo("Registering gxpci iomem for context %d", i);

		    /* HACK: cant seem to open more than 4 channels */
                    if (i >= MAX_PCI_CHANNELS)
                        continue;

                    result = gxpci_iomem_register(gxpci_context[i], page,
                                                  tile_vhuge_size);
                    VERIFY(result, "gxpci_iomem_register()");
		}
            }

            num_buffers -= ((stack_bytes / (sizeof(Packet) +buffer_size)) + 1);
            //num_buffers = ((stack_mem - stack_bytes) / 
            //               (sizeof(Packet) + buffer_size)) - 1;

            total_buffers += num_buffers;

    	    SCLogInfo("Adding %d %d byte packet buffers",
                      num_buffers, buffer_size);

            /* Push some buffers onto the stack. */
            for (unsigned int j = 0; j < num_buffers; j++)
            {
                PACKET_INITIALIZE((Packet *)mem);
                gxio_mpipe_push_buffer(context, stackidx, mem + sizeof(Packet));
                mem += (sizeof(Packet) + buffer_size);
            }

            /* Paranoia. */
            assert(mem <= page + tile_vhuge_size - sizeof(Packet));

        }
        ALIGN(mem, 64);
        empty_p = mem;
        PACKET_INITIALIZE(empty_p);
    	SCLogInfo("%d total packet buffers", total_buffers);

        /* Register for packets. */
        gxio_mpipe_rules_t rules;
        gxio_mpipe_rules_init(&rules, context);
        gxio_mpipe_rules_begin(&rules, bucket, num_buckets, NULL);
        if (capture_enabled != off) {
            if (capture_enabled == idesc)
                headroom = sizeof(gxio_mpipe_idesc_t) + 2;
            else
                headroom = sizeof(struct mpipe_pcap_pkthdr) + 2;
            gxio_mpipe_rules_set_headroom(&rules, headroom);
        }
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
    if (TileNumPipelinesPerRx == 1)
        tmc_sync_barrier_init(&barrier, TileNumPipelines);
    else
        tmc_sync_barrier_init(&barrier, (TileNumPipelines+1)/2);

    for (int i = 0; i < MAX_INTERFACES; i++) {
        equeue[i] = &equeue_body[i];
    }

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
        //printf("DecodeMpipe ETHERNET p %p datalink %x pkt %p len %d %04x\n", p, p->datalink, p->pkt, p->pktlen, *(uint16_t *)(&p->pkt[12]));
        DecodeEthernet(tv, dtv, p, p->pkt, p->pktlen, pq);
        break;
    default:
        printf("DecodeMpipe INVALID datatype p %p datalink %x\n", p, p->datalink);
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

#define PCIE_PQ_LOG     1 /* use PQ for file I/O instead of raw_dma */

#define OP_OPEN		1
#define OP_WRITE	2
#define OP_CLOSE	3

typedef struct {
    uint32_t	magic;
    uint32_t	fileno;
    uint32_t	op;
    uint32_t    seq;
    uint32_t	len;
    uint32_t	next_offset;
    char	buf[];
} __attribute__((__packed__)) TrioMsg;

static int gxpci_fileno = 0;
static int gxpci_raw_ctx_inited = 0;
static int raw_mutex_inited = 0;
static uint32_t wr_pos;		/* write position within log_mem */
static char *log_mem = NULL;
static SCMutex raw_mutex;
static uint32_t raw_seq = 0;
static uint32_t dma_cnt = 0;
static uint32_t comps_rcvd = 0;
static uint32_t offsets[1024];
uint_reg_t io_address[1024];
static uint32_t lens[1024];
static void *comp_buffer[1024];
#define LOG_WRAP_OFFSET (log_wrap_offset)
static size_t log_wrap_offset = 0;

#define HOST_CACHE_ALIGN 128

static void TrioDMABuf(void *p, uint32_t offset, uint32_t len)
{
    gxpci_comp_t comp[MAX_CMDS_BATCH];
#ifdef PCIE_PQ_LOG
    gxpci_cmd_t cmd;
#else
    gxpci_dma_cmd_t cmd;
#endif
    int result;
    int credits;
    uint32_t dmas;

    __insn_mf();

    do {
        credits = gxpci_get_cmd_credits(gxpci_raw_context);
        if (unlikely(credits == GXPCI_ERESET)) {
            SCLogInfo("gxpci channel is reset");
            SCReturn;
        }
    } while(credits == 0);

    if ((offset & (HOST_CACHE_ALIGN -1)) != 0) {
        tmc_task_die("UNALIGNED DMA: %d\n", offset);
    }
    cmd.buffer = p;
#ifndef PCIE_PQ_LOG
    cmd.remote_buf_offset = offset;
#endif
    cmd.size = (len + 63) & ~(63);

#ifdef PCIE_PQ_LOG
    result = gxpci_pq_t2h_cmd(gxpci_raw_context, &cmd);
#else
    result = gxpci_raw_dma_send_cmd(gxpci_raw_context, &cmd);
#endif
    dmas = arch_atomic_increment(&dma_cnt);
    if (unlikely(result == GXPCI_ERESET)) {
        SCLogInfo("gxpci channel is reset");
    } else if (unlikely(result != 0)) {
        SCLogInfo("gxpci_raw_dma_send_cmd returned non-zero");
    }
    offsets[dmas % 1024] = offset;
    lens[dmas % 1024] = len;

    result = gxpci_get_comps(gxpci_raw_context, comp, 0, MAX_CMDS_BATCH);
    if (unlikely(result == GXPCI_ERESET)) {
        SCLogInfo("gxpci channel is reset");
        SCReturn;
    } else {
        //printf("dma_send: %d comps_rcvd: %d\n", dmas, arch_atomic_add(&comps_rcvd, result));
        for(int i = 0; i < result; i++) {
           comp_buffer[(comps_rcvd + i) % 1024] = comp[i].buffer;
        }
        arch_atomic_add(&comps_rcvd, result);
    }
}


static void TrioWriteOpen(TrioFD *fp, const char *path, const char *append)
{
    SCMutexLock(&raw_mutex);
    TrioMsg *p = (TrioMsg *)&log_mem[wr_pos];
    uint32_t pos = wr_pos;

    p->magic = 5555;
    p->fileno = fp->fileno;
    p->op = OP_OPEN;
    p->seq = ++raw_seq;
    p->len = offsetof(TrioMsg, buf);
    p->len += sprintf(p->buf, "%s%s", append, path);
    if (wr_pos + p->len > LOG_WRAP_OFFSET) {
        wr_pos = p->next_offset = 0;
    } else {
        int roundup = (p->len + HOST_CACHE_ALIGN - 1) & ~(HOST_CACHE_ALIGN-1);
        wr_pos = p->next_offset = (wr_pos + roundup);
    }
    TrioDMABuf(p, pos, p->len);
    SCMutexUnlock(&raw_mutex);
}

int TileTrioPrintf(TrioFD *fp, const char *format, ...)
{
    va_list ap;
    SCMutexLock(&raw_mutex);
    TrioMsg *p = (TrioMsg *)&log_mem[wr_pos];
    uint32_t pos = wr_pos;

    va_start(ap, format);

    p->magic = 5555;
    p->fileno = fp->fileno;
    p->op = OP_WRITE;
    p->seq = ++raw_seq;
    p->len = offsetof(TrioMsg, buf);
    p->len += vsprintf(p->buf, format, ap);
    if (wr_pos + p->len > LOG_WRAP_OFFSET) {
        wr_pos = p->next_offset = 0;
    } else {
        int roundup = (p->len + HOST_CACHE_ALIGN - 1) & ~(HOST_CACHE_ALIGN-1);
        wr_pos = p->next_offset = (wr_pos + roundup);
    }
    TrioDMABuf(p, pos, p->len);
    SCMutexUnlock(&raw_mutex);
    /*vprintf(format, ap); for debugging */
    return 0;
}

void *TileTrioOpenFileFp(const char*path, const char *append_setting)
{
    int result;
    TrioFD *fp;

    SCLogInfo("opening PCIe file: %s\n", path);
    /* TBD: make this an atomic */
    if (arch_atomic_exchange(&raw_mutex_inited, 1) == 0) {
        SCMutexInit(&raw_mutex, NULL);
        SCLogInfo("raw mutex initialized\n");
    }
    if (trio_inited == 0) {
        result = gxio_trio_init(trio_context, trio_index);
        VERIFY(result, "gxio_trio_init()");
        trio_inited = 1;
    }
    if (gxpci_raw_ctx_inited == 0) {
        result = gxpci_init(trio_context, gxpci_raw_context, trio_index, loc_mac);
        VERIFY(result, "gxio_init()");

        /*
         * This indicates that we need to allocate an ASID ourselves,
         * instead of using one that is allocated somewhere else.
         */
        int asid = GXIO_ASID_NULL;

        result = gxpci_open_queue(gxpci_raw_context, asid,
#ifdef PCIE_PQ_LOG
                                  GXPCI_PQ_T2H,
#else
                                  GXPCI_RAW_DMA_SEND,
#endif
                                  0,
                                  queue_index,
                                  0,
                                  0);
        VERIFY(result, "gxio_open_queue()");

        /*
         * Allocate and register data buffer
         */
        size_t hugepagesz = tmc_alloc_get_huge_pagesize();
        tmc_alloc_t alloc = TMC_ALLOC_INIT;
        tmc_alloc_set_huge(&alloc);
        tmc_alloc_set_home(&alloc, TMC_ALLOC_HOME_HASH);
        tmc_alloc_set_pagesize_exact(&alloc, hugepagesz);
        log_mem = tmc_alloc_map(&alloc, hugepagesz);
        log_wrap_offset = (4 * 1024 * 1024) - 4096;

        result = gxpci_iomem_register(gxpci_raw_context, log_mem, hugepagesz);
        VERIFY(result, "gxio_iomem_register()");

        gxpci_raw_ctx_inited = 1;
    }
    fp = SCMalloc(sizeof(TrioFD));
    fp->fileno = arch_atomic_increment(&gxpci_fileno);
    TrioWriteOpen(fp, path, append_setting);
    return fp;
}

#endif // __tilegx__
