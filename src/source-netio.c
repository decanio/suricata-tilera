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
 * Tilera tile64/tilepro netio ingress packet support
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-modules.h"
#include "tm-threads.h"
#include "runmode-tile.h"
#include "source-netio.h"
#include "conf.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-privs.h"
#include "tmqh-packetpool.h"

#if defined(__tile__) && !defined(__tilegx__)

#include <netio/netio.h>
#include <tmc/cpus.h>
#include <tmc/spin.h>
#include <tmc/sync.h>
#include <tmc/task.h>
#include <tmc/perf.h>

extern uint8_t suricata_ctl_flags;
//extern unsigned int NetioNumPipes;

//#define NETIO_DEBUG

/** storage for netio device names */
typedef struct NetioDevice_ {
    char *dev;  /**< the device (e.g. "gbe/0") */
    TAILQ_ENTRY(NetioDevice_) next;
} NetioDevice;

/** private device list */
static TAILQ_HEAD(, NetioDevice_) netio_devices =
    TAILQ_HEAD_INITIALIZER(netio_devices);


/**
 * \brief Structure to hold thread specifc variables.
 */
typedef struct NetioThreadVars_
{
    /* data link type for the thread */
    int datalink;

    netio_queue_t queue;

    /* counters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;

    ThreadVars *tv;
    TmSlot *slot;

    Packet *in_p;

} NetioThreadVars;

TmEcode ReceiveNetioLoop(ThreadVars *, void *, void *);
TmEcode ReceiveNetioThreadInit(ThreadVars *, void *, void **);
void ReceiveNetioThreadExitStats(ThreadVars *, void *);

TmEcode DecodeNetioThreadInit(ThreadVars *, void *, void **);
TmEcode DecodeNetio(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

/*
 * NetIO configuration.
 */
#define IPP_HUGE_PAGES 12
static unsigned long long tilera_gtod_fast_boot = 0;
static const unsigned long tilera_gtod_fast_mhz = /* tmc_perf_get_cpu_speed() */ 866000000 / 1000000;

static pthread_barrier_t barrier;

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
 * \brief Registration Function for ReceiveNetio.
 * \todo Unit tests are needed for this module.
 */
void TmModuleReceiveNetioRegister (void) {
    tmm_modules[TMM_RECEIVENETIO].name = "ReceiveNetio";
    tmm_modules[TMM_RECEIVENETIO].ThreadInit = ReceiveNetioThreadInit;
    tmm_modules[TMM_RECEIVENETIO].Func = NULL;
    tmm_modules[TMM_RECEIVENETIO].PktAcqLoop = ReceiveNetioLoop;
    tmm_modules[TMM_RECEIVENETIO].ThreadExitPrintStats = ReceiveNetioThreadExitStats;
    tmm_modules[TMM_RECEIVENETIO].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVENETIO].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVENETIO].cap_flags = SC_CAP_NET_RAW;
    tmm_modules[TMM_RECEIVENETIO].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Registraction Function for DecodeNetio.
 * \todo Unit tests are needed for this module.
 */
void TmModuleDecodeNetioRegister (void) {
    tmm_modules[TMM_DECODENETIO].name = "DecodeNetio";
    tmm_modules[TMM_DECODENETIO].ThreadInit = DecodeNetioThreadInit;
    tmm_modules[TMM_DECODENETIO].Func = DecodeNetio;
    tmm_modules[TMM_DECODENETIO].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODENETIO].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODENETIO].RegisterTests = NULL;
    tmm_modules[TMM_DECODENETIO].cap_flags = 0;
}

static __attribute__((always_inline)) void
cycle_pause(unsigned int delay)
{
  const unsigned int start = get_cycle_count_low();
  while (get_cycle_count_low() - start < delay)
    ;
}

static __attribute__((always_inline)) int
packet_pull(netio_queue_t *queue, netio_pkt_t *packet)
{
    netio_error_t err = netio_get_packet(queue, packet);

    switch (err) {
    case NETIO_PKT:
        return 1;
    case NETIO_NOPKT:
        cycle_pause(4000);
        return 0;
    default:
        tmc_task_die("error from netio_get_packet: %s", netio_strerror(err));
        return 0;
    }
}

/**
 * \brief Netio Packet Process function.
 *
 * This function fills in our packet structure from netio.
 * From here the packets are picked up by the  DecodeNetio thread.
 *
 * \param user pointer to MpipeThreadVars passed from pcap_dispatch
 * \param h pointer to gxio packet header
 * \param pkt pointer to current packet
 */
static inline int NetioProcessPacket(u_char *user,  netio_queue_t *queue, Packet *p) {
    SCEnter();
    netio_pkt_t *packet = &p->netio_packet;
    NetioThreadVars *ptv = (NetioThreadVars *)user;
    netio_pkt_metadata_t *mda = NETIO_PKT_METADATA(packet);
    int caplen = NETIO_PKT_L2_LENGTH_M(mda, packet);
    u_char *pkt = NETIO_PKT_L2_DATA_M(mda, packet);
#ifdef NETIO_DEBUG
    static uint32_t bad_cnt = 0;
#endif

    if (NETIO_PKT_BAD(packet) != 0) {
        netio_free_buffer(&ptv->queue, packet);
#ifdef NETIO_DEBUG
	    if (++bad_cnt > 1024) {
           SCLogInfo("Dumped 1K bad packets");
           bad_cnt = 0;
    	}
#endif
        SCReturnInt(0);
    }
#ifdef NETIO_DEBUG
    bad_cnt = 0;
#endif

    /*
     * Invalidate any previously cached version of the packet 
     */
    netio_pkt_inv(pkt, caplen);

    tilera_fast_gettimeofday(&p->ts);
    /*
    p->ts.tv_sec = h->ts.tv_sec;
    p->ts.tv_usec = h->ts.tv_usec;
    */

    ptv->pkts++;
    ptv->bytes += caplen;

    p->datalink = ptv->datalink;
    p->flags |= PKT_NETIO;

    SET_PKT_LEN(p, caplen);
    p->pkt = pkt;

    SCReturnInt(1);
}

/**
 * \brief Receivews packets from an interface via netio.
 */
TmEcode ReceiveNetioLoop(ThreadVars *tv, void *data, void *slot) {
    uint16_t packet_q_len = 0;
    NetioThreadVars *ptv = (NetioThreadVars *)data;
    TmSlot *s = (TmSlot *)slot;
    ptv->slot = s->slot_next;
    Packet *p = NULL;

    SCEnter();
#ifdef __TILERAP__
    int pool = p->pool;
#endif

    for (;;) {
        if (suricata_ctl_flags & SURICATA_STOP ||
                suricata_ctl_flags & SURICATA_KILL) {
            SCReturnInt(TM_ECODE_FAILED);
        }

        /* make sure we have at least one packet in the packet pool, to prevent
         * us from alloc'ing packets at line rate */
        do {
#ifdef __TILERAP__
            packet_q_len = PacketPoolSize(pool);
            if (packet_q_len == 0) {
                PacketPoolWait(pool);
            }
#else
            packet_q_len = PacketPoolSize();
            if (packet_q_len == 0) {
                PacketPoolWait();
            }
#endif
        } while (packet_q_len == 0);

        p = PacketGetFromQueueOrAlloc();
        if (p == NULL) {
            SCReturnInt(TM_ECODE_FAILED);
        }

        int r = 0;
        while (r == 0) {
            if (packet_pull(&ptv->queue, &p->netio_packet)) {
                r = NetioProcessPacket((u_char *)ptv,  &ptv->queue, p);
                if (r) {
                    TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p);
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

TmEcode NetioRegisterOutputs(void *td) {
    SCEnter()
    ThreadVars *tv = (ThreadVars *)td;
    netio_input_config_t config = {
      .flags = NETIO_RECV | NETIO_NO_XMIT | NETIO_TAG_NONE,
      .num_receive_packets = 16,
      .interface = "xgbe/1", /* HACK */
      .queue_id = 0
    };

    while (1) {
        netio_error_t err = netio_input_register(&config, &tv->netio_queue);
        if (err == NETIO_NO_ERROR) {
            break;
        } else if (err == NETIO_LINK_DOWN) {
            sleep(2);
        } else {
            SCLogInfo("input_register failed: %s %d", netio_strerror(err), err);
            break;
        }
    }
    // syncronize with receivers
    pthread_barrier_wait(&barrier);

    SCReturnInt(TM_ECODE_OK);
}

TmEcode ReceiveNetioThreadInit(ThreadVars *tv, void *initdata, void **data) {
    SCEnter()

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    NetioThreadVars *ptv = SCMalloc(sizeof(NetioThreadVars));
    if (ptv == NULL)
        SCReturnInt(TM_ECODE_FAILED);
    memset(ptv, 0, sizeof(NetioThreadVars));

    ptv->tv = tv;
    ptv->datalink = LINKTYPE_ETHERNET;

    SCLogInfo("using interface %s", (char *)initdata);

    int cpu = tmc_cpus_get_my_cpu();
    int rank = (cpu-1)/TILES_PER_NETIO_PIPELINE;
    SCLogInfo("cpu %d rank %d interface %s\n", cpu, rank, (char *)initdata);

    /*
     * Register for packets.
     * Note that by ensuring the queue is located on this thread's stack,
     * we guarantee that references to it will be cached locally.
     */
    netio_input_config_t config = {
      .flags = NETIO_RECV | NETIO_NO_XMIT | NETIO_TAG_NONE,
      .num_receive_packets = 1024,
      .interface = (char *)initdata,
      .num_send_buffers_small_total = 8,
      .num_send_buffers_large_total = 8,
      .num_send_buffers_jumbo_total = 8,
      .queue_id = rank
    };

    netio_error_t err = netio_input_register(&config, &ptv->queue);
    if (err != NETIO_NO_ERROR)
      tmc_task_die("input_register failed: %s", netio_strerror(err));

    if (rank == 0) {
      /*
       * Set up packet distribution; we do flow hashing so that we have a chance
       * of getting packets delivered back-to-back to one tile.
       */
      netio_group_t group = {
        .bits.__balance_on_l4 = 1,
        .bits.__balance_on_l3 = 1,
        .bits.__balance_on_l2 = 0,
        .bits.__bucket_base = 0,
        .bits.__bucket_mask = 0xFF
      };
      err = netio_input_group_configure(&ptv->queue, 0, &group, 1);
      if (err != NETIO_NO_ERROR)
        tmc_task_die("group_configure failed: %s", netio_strerror(err));

      netio_bucket_t buckets[256];
      unsigned int next_queue = 0;
      unsigned int num_buckets = sizeof (buckets) / sizeof (buckets[0]);
      for (unsigned int j = 0; j < num_buckets; j++)
      {
        buckets[j] = next_queue++;
        if (next_queue == TileNumPipelines)
          next_queue = 0;
      }

      err = netio_input_bucket_configure(&ptv->queue, 0, buckets, num_buckets);
      if (err != NETIO_NO_ERROR)
        tmc_task_die("bucket_configure failed: %s", netio_strerror(err));

    }

#ifdef NETIO_DEBUG
    SCLogInfo("Before barrier");
#endif
    pthread_barrier_wait(&barrier);
#ifdef NETIO_DEBUG
    SCLogInfo("After barrier");
#endif
#ifdef NOTYET
    /* Have worker 0 start the network driver. */
    tmc_sync_barrier_wait(&shared->work_barrier);
#endif
#ifdef NETIO_DEBUG
    SCLogInfo("Calling netio_input_initialize");
#endif
    if (rank == 0) {
      /*
       * Start the packets flowing.
       */
      err = netio_input_initialize(&ptv->queue);
      if (err != NETIO_NO_ERROR)
        tmc_task_die("input_initialize failed: %s", netio_strerror(err));
    }

#ifdef NETIO_DEBUG
    SCLogInfo("ReceiveNetio initialization complete!!!");
#endif
    *data = (void *)ptv;
    SCReturnInt(TM_ECODE_OK);
}

TmEcode ReceiveNetioInit(void) {
    SCEnter();

    pthread_barrier_init(&barrier, NULL, TileNumPipelines*2);

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function prints stats to the screen at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into NetiohreadVars for ptv
 */
void ReceiveNetioThreadExitStats(ThreadVars *tv, void *data) {
    SCEnter();
    SCReturn;
}

TmEcode DecodeNetioThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter()
    DecodeThreadVars *dtv = NULL;

    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;
#ifdef NETIO_DEBUG
    SCLogInfo("DecodeNetioThreadInit using interface");
#endif

    SCReturnInt(TM_ECODE_OK);

}

TmEcode DecodeNetio(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postq)
{
    SCEnter()
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    /* update counters */
    SCPerfCounterIncr(dtv->counter_pkts, tv->sc_perf_pca);
    SCPerfCounterIncr(dtv->counter_pkts_per_sec, tv->sc_perf_pca);

    SCPerfCounterAddUI64(dtv->counter_bytes, tv->sc_perf_pca, p->pktlen);
    /* pfring skips this too */
    SCPerfCounterAddDouble(dtv->counter_bytes_per_sec, tv->sc_perf_pca, p->pktlen);
    /*
     * takes too much time to compute for each packet
    SCPerfCounterAddDouble(dtv->counter_mbit_per_sec, tv->sc_perf_pca,
                           (p->pktlen * 8)/1000000.0);
    */

    SCPerfCounterAddUI64(dtv->counter_avg_pkt_size, tv->sc_perf_pca, p->pktlen);
    SCPerfCounterSetUI64(dtv->counter_max_pkt_size, tv->sc_perf_pca, p->pktlen);

    /* call the decoder */
    switch(p->datalink) {
    case LINKTYPE_ETHERNET:
        DecodeEthernet(tv, dtv, p, p->pkt, p->pktlen, pq);
        break;
    default:
#ifdef NETIO_DEBUG
        SCLogInfo("Error: datalink type %" PRId32 " not yet supported in module DecodeNetio", p->datalink);
#endif
        break;
    }
 
    SCReturnInt(TM_ECODE_OK);
}

/**
 *  \brief Add a pcap device for monitoring
 *
 *  \param dev string with the device name
 *
 *  \retval 0 on success.
 *  \retval -1 on failure.
 */
int NetioLiveRegisterDevice(char *dev)
{
    NetioDevice *nd = SCMalloc(sizeof(NetioDevice));
    if (nd == NULL) {
        return -1;
    }

    nd->dev = SCStrdup(dev);
    TAILQ_INSERT_TAIL(&netio_devices, nd, next);

    SCLogDebug("Netio device \"%s\" registered.", dev);
    return 0;
}

/**
 *  \brief Get the number of registered devices
 *
 *  \retval cnt the number of registered devices
 */
int NetioLiveGetDeviceCount(void) {
    int i = 0;
    NetioDevice *nd;

    TAILQ_FOREACH(nd, &netio_devices, next) {
        i++;
    }

    return i;
}

#endif
