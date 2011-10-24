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
extern int max_pending_packets;
extern unsigned int NetioNumPipes;

static int netio_max_read_packets = 0;

#define NETIO_FAST_CALLBACK
#define NETIO_MAX_PKTS	32

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

    Packet *in_p;

    /* TBD: is this really necessary? */
    Packet *array[NETIO_MAX_PKTS];
    uint16_t array_idx;
} NetioThreadVars;

TmEcode ReceiveNetio(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode ReceiveNetioThreadInit(ThreadVars *, void *, void **);
void ReceiveNetioThreadExitStats(ThreadVars *, void *);

TmEcode DecodeNetioThreadInit(ThreadVars *, void *, void **);
TmEcode DecodeNetio(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

//========================================
// NetIO configuration.

#define IPP_HUGE_PAGES 12
#if 0
//static char *interface = "xgbe/0";
static int max_receive_packets = 1500;  /* default to largest possible value */
static int max_small_packets = 8, max_large_packets = 8, max_jumbo_packets = 8;
static int opt_huge_ipp_pages = 8;
static int work_size = 1;
static int work_rank = 0;
static int hash_mac = 1;
static int hash_ip = 1;
static int hash_ports = 1;
static int flows = 1;
//static netio_queue_t queue;
#endif
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

#if 0
// Configure a queue.
// For a shared queue, we are careful to register workers serially.
//
static void
queue_config(netio_queue_t *queue, int qid, char *interface)
{
  netio_input_config_t config = {
    .queue_id = 0,
    .num_receive_packets = 128 /* 1500 on xgbe */,
    .interface = interface,

    .total_buffer_size = 2 * (16 * 1024 * 1024),
    .buffer_node_weights[0] = 0,
    .buffer_node_weights[1] = 1,
    .buffer_node_weights[2] = 1,
    .buffer_node_weights[3] = 0,
    .flags = /*NETIO_NOREQUIRE_LINK_UP|*/NETIO_STRICT_HOMING,
  };

  // Register workers in turn.
  //
#ifdef NOTYET
  tmc_sync_barrier_wait(&shared->work_barrier);
#endif
  // Loop on netio_input_register() in case the link is down.
  while (1)
  {
    netio_error_t err = netio_input_register(&config, queue);
    if (err == NETIO_NO_ERROR)
      break;
    else if (err == NETIO_LINK_DOWN)
    {
      fprintf(stderr, "Link %s is down, retrying.\n", interface);
      sleep(2);
      continue;
    }
    else
      tmc_task_die("netio input_register %d failed, status %d(%s)\n",
                   work_rank, err, netio_strerror(err));
  }
#ifdef NOTYET
    tmc_sync_barrier_wait(&shared->work_barrier);
#endif
}

// Define a flow hash across a set of buckets.
// Map the buckets to our worker queues.
// There should be at least as many buckets as workers.
//
static inline void
flow_config(netio_queue_t *queue, netio_group_t* flowtbl,
            int base, unsigned count)
{
    netio_bucket_t map[1024];
    for (unsigned b = 0; b < count; ++b)
        map[b] = b % work_size;
    netio_error_t err = netio_input_bucket_configure(queue, base, map, count);
    if (err != NETIO_NO_ERROR)
        tmc_task_die("netio_input_bucket_configure(%d) returned: %d(%s)\n",
                count, err, netio_strerror(err));

    flowtbl->word = 0;
    flowtbl->bits.__balance_on_l4 = hash_ports; // Hash on ports? (hashing on ports breaks things like ftp tracking)
    flowtbl->bits.__balance_on_l3 = hash_ip;    // Hash on IP addresses?
    flowtbl->bits.__balance_on_l2 = hash_mac;   // Hash on Ethernet Mac address
    flowtbl->bits.__bucket_base = base;   // Hash table
    flowtbl->bits.__bucket_mask = count-1;
}

// Configure a flow for a range of VLANs.
//
static void
vlan_config(netio_queue_t *queue, netio_group_t* flowtbl,
            int base, int count)
{
  for (int v = base; v < count; ++v)
  {
    netio_error_t err = netio_input_group_configure(queue, v, flowtbl, 1);
    if (err != NETIO_NO_ERROR)
      tmc_task_die("netio_input_group_configure(%d) failed, status: %d(%s)\n",
        v, err, netio_strerror(err));
  }
}
#endif

/**
 * \brief Registration Function for ReceiveNetio.
 * \todo Unit tests are needed for this module.
 */
void TmModuleReceiveNetioRegister (void) {
    tmm_modules[TMM_RECEIVENETIO].name = "ReceiveNetio";
    tmm_modules[TMM_RECEIVENETIO].ThreadInit = ReceiveNetioThreadInit;
    tmm_modules[TMM_RECEIVENETIO].Func = ReceiveNetio;
    tmm_modules[TMM_RECEIVENETIO].ThreadExitPrintStats = ReceiveNetioThreadExitStats;
    tmm_modules[TMM_RECEIVENETIO].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVENETIO].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVENETIO].cap_flags = SC_CAP_NET_RAW;
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
#if 1
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
#else
    return netio_get_packet(queue, packet) == NETIO_PKT;
#endif
}

/**
 * \brief Netio "callback" function.
 *
 * This function fills in our packet structure from libpcap.
 * From here the packets are picked up by the  DecodePcap thread.
 *
 * \param user pointer to PcapThreadVars passed from pcap_dispatch
 * \param h pointer to pcap packet header
 * \param pkt pointer to raw packet data
 */
#ifndef NETIO_FAST_CALLBACK
void NetioCallback(u_char *user,  netio_queue_t *queue, netio_pkt_t *packet) {
    SCEnter();
    NetioThreadVars *ptv = (NetioThreadVars *)user;
    netio_pkt_metadata_t *mda = NETIO_PKT_METADATA(packet);
    int caplen = NETIO_PKT_L2_LENGTH_M(mda, packet);
    u_char *pkt = NETIO_PKT_L2_DATA_M(mda, packet);
    //SCLogDebug("user %p, q %p, pkt %p", user, queue, packet);
    static uint32_t bad_cnt = 0;

    if (NETIO_PKT_BAD(packet) != 0) {
	if (++bad_cnt > 1024) {
           SCLogInfo("Dumped 1K bad packets");
           bad_cnt = 0;
	}
        SCReturn;
    }
    bad_cnt = 0;

    /*
     * Invalidate any previously cached version of the packet 
     */
    netio_pkt_inv(pkt, caplen);

    Packet *p = NULL;
    if (ptv->array_idx == 0) {
        p = ptv->in_p;
    } else {
        p = PacketGetFromQueueOrAlloc();
       SCLogInfo("Allocated p %p\n", p);
    }

    if (p == NULL) {
        SCReturn;
    }

    tilera_fast_gettimeofday(&p->ts);
    /*
    p->ts.tv_sec = h->ts.tv_sec;
    p->ts.tv_usec = h->ts.tv_usec;
    */

    ptv->pkts++;
    ptv->bytes += caplen;

    p->datalink = ptv->datalink;

    //SCLogInfo("copying to pkt %p ext_pkt %p size %d\n", p->pkt, p->ext_pkt, sizeof(Packet));
#if 0
int i;
for (i = 0; i < caplen; i++) {
  if ((i % 16) == 0) printf("\n%x ", i);
  printf("%02x ", pkt[i]);
}
printf("\n");
#endif
    if (PacketCopyData(p, pkt, caplen) == -1)
      SCReturn;

    //SCLogDebug("p->pktlen: %" PRIu32 " (pkt %02x, p->pkt %02x)", p->pktlen, *pkt, *p->pkt);
    //SCLogInfo("p->pktlen: %" PRIu32 " (pkt %02x, p->pkt %02x)", p->pktlen, *pkt, *p->pkt);

    /* store the packet in our array */
    ptv->array[ptv->array_idx] = p;
    ptv->array_idx++;

    SCReturn;
}
#endif

#ifdef NETIO_FAST_CALLBACK
static inline int NetioFastCallback(u_char *user,  netio_queue_t *queue, Packet *p) {
    SCEnter();
    netio_pkt_t *packet = &p->netio_packet;
    NetioThreadVars *ptv = (NetioThreadVars *)user;
    netio_pkt_metadata_t *mda = NETIO_PKT_METADATA(packet);
    int caplen = NETIO_PKT_L2_LENGTH_M(mda, packet);
    u_char *pkt = NETIO_PKT_L2_DATA_M(mda, packet);
    //SCLogDebug("user %p, q %p, pkt %p", user, queue, packet);
    static uint32_t bad_cnt = 0;

    if (NETIO_PKT_BAD(packet) != 0) {
        netio_free_buffer(&ptv->queue, packet);
	if (++bad_cnt > 1024) {
           SCLogInfo("Dumped 1K bad packets");
           bad_cnt = 0;
	}
        SCReturnInt(0);
    }
    bad_cnt = 0;

    /*
     * Invalidate any previously cached version of the packet 
     */
    netio_pkt_inv(pkt, caplen);

#if 0
    Packet *p = NULL;
    if (ptv->array_idx == 0) {
        p = ptv->in_p;
    } else {
        p = PacketGetFromQueueOrAlloc();
       SCLogInfo("Allocated p %p\n", p);
    }

    if (p == NULL) {
        SCReturn;
    }
#endif

    tilera_fast_gettimeofday(&p->ts);
    /*
    p->ts.tv_sec = h->ts.tv_sec;
    p->ts.tv_usec = h->ts.tv_usec;
    */

    ptv->pkts++;
    ptv->bytes += caplen;

    p->datalink = ptv->datalink;
    p->flags |= PKT_NETIO;
    //p->netio_queue = queue;

    //SCLogInfo("copying to pkt %p ext_pkt %p size %d\n", p->pkt, p->ext_pkt, sizeof(Packet));
#if 0
int i;
for (i = 0; i < caplen; i++) {
  if ((i % 16) == 0) printf("\n%x ", i);
  printf("%02x ", pkt[i]);
}
printf("\n");
#endif
    SET_PKT_LEN(p, caplen);
    p->pkt = pkt;

    //SCLogDebug("p->pktlen: %" PRIu32 " (pkt %02x, p->pkt %02x)", p->pktlen, *pkt, *p->pkt);
    //SCLogInfo("p->pktlen: %" PRIu32 " (pkt %02x, p->pkt %02x)", p->pktlen, *pkt, *p->pkt);

    /* store the packet in our array */
    ptv->array[ptv->array_idx] = p;
    ptv->array_idx++;

    SCReturnInt(1);
}
#endif

/**
 * \brief Receivews packets from an interface via netio.
 */
TmEcode ReceiveNetio(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq) {
    //netio_pkt_t packet;
    SCEnter();
    uint16_t packet_q_len = 0;
#ifdef __TILERAP__
    int pool = p->pool;
#endif

    NetioThreadVars *ptv = (NetioThreadVars *)data;

    /* make sure we have at least one packet in the packet pool, to prevent
     * us from alloc'ing packets at line rate */
    while (packet_q_len == 0) {
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
    }

    if (postpq == NULL)
        netio_max_read_packets = 1;

    ptv->array_idx = 0;
    ptv->in_p = p;
    //SCLogInfo("ReceiveNetio p %p", p);

    //SCLogInfo("ReceiveNetio!!!");

#ifdef NETIO_FAST_CALLBACK
#if 0
    Packet *p = NULL;
    if (ptv->array_idx == 0) {
        p = ptv->in_p;
    } else {
        p = PacketGetFromQueueOrAlloc();
    }

    if (p == NULL) {
        SCReturnInt(TM_ECODE_FAILED);
    }
#endif
    /* Right now we just support reading packets one at a time. */
    int r = 0;
    while (r == 0) {
        if (packet_pull(&ptv->queue, &p->netio_packet)) {
            r = NetioFastCallback((u_char *)ptv,  &ptv->queue, p);
            //r = 1;
	} else {
            r = 0;
	}
        if (suricata_ctl_flags != 0) {
            break;
        }
    }
#else
    /* Right now we just support reading packets one at a time. */
    int r = 0;
    while (r == 0) {
        if (packet_pull(&ptv->queue, &packet)) {
            NetioCallback((u_char *)ptv,  &ptv->queue, &packet);
            netio_free_buffer(&ptv->queue, &packet);
            r = 1;
	} else {
            //r = 1;
            r = 0;
	}
        if (suricata_ctl_flags != 0) {
            break;
        }
    }
#endif

    uint16_t cnt = 0;
    for (cnt = 0; cnt < ptv->array_idx; cnt++) {
        Packet *pp = ptv->array[cnt];

        /* enqueue all but the first in the postpq, the first
         * pkt is handled by the tv "out handler" */
        if (cnt > 0) {
            //SCLogInfo("PacketEnqueue packet p %p", pp);
            PacketEnqueue(postpq, pp);
        }
    }

    if (suricata_ctl_flags != 0) {
        SCReturnInt(TM_ECODE_FAILED);
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

#if 1
    int cpu = tmc_cpus_get_my_cpu();
    //int rank = (cpu-1)/6;
    int rank = (cpu-1)/TILES_PER_PIPELINE;
    SCLogInfo("cpu %d rank %d interface %s\n", cpu, rank, (char *)initdata);

    //
    // Register for packets.
    // Note that by ensuring the queue is located on this thread's stack,
    // we guarantee that references to it will be cached locally.
    //
    netio_input_config_t config = {
      .flags = NETIO_RECV | NETIO_NO_XMIT | NETIO_TAG_NONE,
      .num_receive_packets = 1024,
      //.interface = "xgbe/0",
      .interface = (char *)initdata,
      .num_send_buffers_small_total = 8,
      .num_send_buffers_large_total = 8,
      .num_send_buffers_jumbo_total = 8,
      .queue_id = rank
    };

    //netio_queue_t queue;
    netio_error_t err = netio_input_register(&config, &ptv->queue);
    if (err != NETIO_NO_ERROR)
      tmc_task_die("input_register failed: %s", netio_strerror(err));

    if (rank == 0) {
      //
      // Set up packet distribution; we do flow hashing so that we have a chance
      // of getting packets delivered back-to-back to one tile.
      //
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
        if (next_queue == NetioNumPipes)
          next_queue = 0;
      }

      err = netio_input_bucket_configure(&ptv->queue, 0, buckets, num_buckets);
      if (err != NETIO_NO_ERROR)
        tmc_task_die("bucket_configure failed: %s", netio_strerror(err));

    }
#else
    /*
     * TBD: put all of the netio initialization stuff here
     */
    if (flows) {
        // Configure one queue to each worker.
        //
        queue_config(&queue, work_rank, (char *)initdata);
        //SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED, "netio queue_config done");
        SCLogInfo("netio queue_config done");

        // Only one worker configures the flow
        //
        if (work_rank == 0) {
            netio_group_t flowtbl;
            flow_config(&queue, &flowtbl, 0, flows);
            vlan_config(&queue, &flowtbl, 0, 0x1000);
        }
    } else {
        // Configure all workers to the same queue.
        //
        queue_config(&queue, 0, (char *)initdata);
    }
#endif

    SCLogInfo("Before barrier");
    pthread_barrier_wait(&barrier);
    SCLogInfo("After barrier");
#ifdef NOTYET
    // Have worker 0 start the network driver.
    //
    tmc_sync_barrier_wait(&shared->work_barrier);
#endif
    //SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED, "Calling netio_input_initialize");
    SCLogInfo("Calling netio_input_initialize");
    //if (work_rank == 0)
    if (rank == 0) {
      //
      // Start the packets flowing.
      //
      err = netio_input_initialize(&ptv->queue);
      if (err != NETIO_NO_ERROR)
        tmc_task_die("input_initialize failed: %s", netio_strerror(err));
    }
    //    netio_input_initialize(&queue);

    //SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED, "ReceiveNetio initialization complete!!!");
    SCLogInfo("ReceiveNetio initialization complete!!!");
    *data = (void *)ptv;
    SCReturnInt(TM_ECODE_OK);
}

TmEcode ReceiveNetioInit(void) {
    SCEnter();

    pthread_barrier_init(&barrier, NULL, NetioNumPipes*2);

#if 0
    //
    // Register a queue so we can configure the IPP.
    //
    netio_error_t err;
    netio_queue_t queue;
    netio_input_config_t config = {
      .flags = NETIO_RECV | NETIO_NO_XMIT | NETIO_TAG_NONE,
      .num_receive_packets = 16,
      .interface = "xgbe/0", /* FIXME */
      .queue_id = NETIO_MAX_QUEUE_ID,
    };

    //
    // Loop on netio_input_register() until the link is up.
    //
    while (1)
    {
      err = netio_input_register(&config, &queue);
      if (err == NETIO_NO_ERROR)
        break;
      if (err == NETIO_LINK_DOWN)
      {
        fprintf(stderr, "Link %s is down, retrying.\n", config.interface);
        sleep(2);
      }
      else
      {
        tmc_task_die("input_register failed: %s", netio_strerror(err));
      }
    }
  
    //
    // Set up packet distribution; we do flow hashing so that we have a chance
    // of getting packets delivered back-to-back to one tile.
    //
    netio_group_t group = {
      .bits.__balance_on_l4 = 1,
      .bits.__balance_on_l3 = 1,
      .bits.__balance_on_l2 = 0,
      .bits.__bucket_base = 0,
      .bits.__bucket_mask = 0xFF
    };
    err = netio_input_group_configure(&queue, 0, &group, 1);
    if (err != NETIO_NO_ERROR)
      tmc_task_die("group_configure failed: %s", netio_strerror(err));

    netio_bucket_t buckets[256];
    unsigned int next_queue = 0;
    unsigned int num_buckets = sizeof (buckets) / sizeof (buckets[0]);
    for (int j = 0; j < num_buckets; j++)
    {
      buckets[j] = next_queue++;
      if (next_queue == NetioNumPipes)
        next_queue = 0;
    }

    err = netio_input_bucket_configure(&queue, 0, buckets, num_buckets);
    if (err != NETIO_NO_ERROR)
      tmc_task_die("bucket_configure failed: %s", netio_strerror(err));
#endif
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function prints stats to the screen at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into NetiohreadVars for ptv
 */
void ReceiveNetioThreadExitStats(ThreadVars *tv, void *data) {
    SCEnter();
#if 0
    NetioThreadVars *ptv = (NetioThreadVars *)data;
#endif
    SCReturn;
}

TmEcode DecodeNetioThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter()
    DecodeThreadVars *dtv = NULL;

    dtv = DecodeThreadVarsAlloc();

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;
    SCLogInfo("DecodeNetioThreadInit using interface");

    SCReturnInt(TM_ECODE_OK);

}

TmEcode DecodeNetio(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postq)
{
    SCEnter()
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    //SCLogInfo("DecodeNetio p %p", p);
    /* update counters */
    SCPerfCounterIncr(dtv->counter_pkts, tv->sc_perf_pca);
    SCPerfCounterIncr(dtv->counter_pkts_per_sec, tv->sc_perf_pca);

    SCPerfCounterAddUI64(dtv->counter_bytes, tv->sc_perf_pca, p->pktlen);
#if 1
    /* pfring skips this too */
    SCPerfCounterAddDouble(dtv->counter_bytes_per_sec, tv->sc_perf_pca, p->pktlen);
#endif
#if 0
    SCPerfCounterAddDouble(dtv->counter_mbit_per_sec, tv->sc_perf_pca,
                           (p->pktlen * 8)/1000000.0);
#endif

    SCPerfCounterAddUI64(dtv->counter_avg_pkt_size, tv->sc_perf_pca, p->pktlen);
    SCPerfCounterSetUI64(dtv->counter_max_pkt_size, tv->sc_perf_pca, p->pktlen);

    /* call the decoder */
    switch(p->datalink) {
    case LINKTYPE_ETHERNET:
        //SCLogInfo("DecodeNetio Decode Ethernet p %p", p);
        DecodeEthernet(tv, dtv, p, p->pkt, p->pktlen, pq);
        break;
    default:
        SCLogInfo("Error: datalink type %" PRId32 " not yet supported in module DecodeNetio", p->datalink);
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
