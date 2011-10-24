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
//#include "tm-modules.h"
#include "tm-threads.h"
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

//#define ROUND_UP(n, align) (((n) + (align) - 1) & -(align))

#define VERIFY(VAL, WHAT)                                       \
  do {                                                          \
    int __val = (VAL);                                          \
    if (__val < 0)                                              \
      tmc_task_die("Failure in '%s': %d: %s.",                  \
                   (WHAT), __val, gxio_strerror(__val));        \
  } while (0)



extern uint8_t suricata_ctl_flags;
extern int max_pending_packets;

static int mpipe_max_read_packets = 0;

#define MPIPE_MAX_PKTS	256

/** storage for mpipe device names */
typedef struct MpipeDevice_ {
    char *dev;  /**< the device (e.g. "gbe/0") */
    TAILQ_ENTRY(MpipeDevice_) next;
} MpipeDevice;

/** private device list */
static TAILQ_HEAD(, MpipeDevice_) mpipe_devices =
    TAILQ_HEAD_INITIALIZER(mpipe_devices);


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

    Packet *in_p;

    /* TBD: is this really necessary? */
    Packet *array[MPIPE_MAX_PKTS];
    uint16_t array_idx;
} MpipeThreadVars;

TmEcode ReceiveMpipe(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode ReceiveMpipeThreadInit(ThreadVars *, void *, void **);
void ReceiveMpipeThreadExitStats(ThreadVars *, void *);

TmEcode DecodeMpipeThreadInit(ThreadVars *, void *, void **);
TmEcode DecodeMpipe(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

//========================================
// NetIO configuration.

#define IPP_HUGE_PAGES 12
//static char *interface = "xgbe/0";
#if 0
static int max_receive_packets = 1500;  /* default to largest possible value */
static int max_small_packets = 8, max_large_packets = 8, max_jumbo_packets = 8;
static int opt_huge_ipp_pages = 8;
static int work_size = 1;
static int work_rank = 0;
static int hash_mac = 1;
static int hash_ip = 1;
static int hash_ports = 1;
static int flows = 1;
#endif
static gxio_mpipe_context_t context_body;
static gxio_mpipe_context_t* context = &context_body;
static gxio_mpipe_iqueue_t iqueue_body;
static gxio_mpipe_iqueue_t* iqueue = &iqueue_body;

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
 * \brief Registration Function for ReceiveMpipe.
 * \todo Unit tests are needed for this module.
 */
void TmModuleReceiveMpipeRegister (void) {
    tmm_modules[TMM_RECEIVEMPIPE].name = "ReceiveMpipe";
    tmm_modules[TMM_RECEIVEMPIPE].ThreadInit = ReceiveMpipeThreadInit;
    tmm_modules[TMM_RECEIVEMPIPE].Func = ReceiveMpipe;
    tmm_modules[TMM_RECEIVEMPIPE].ThreadExitPrintStats = ReceiveMpipeThreadExitStats;
    tmm_modules[TMM_RECEIVEMPIPE].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEMPIPE].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEMPIPE].cap_flags = SC_CAP_NET_RAW;
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

#if 1
/*
static __attribute__((always_inline)) int
packet_pull(gxio_mpipe_iqueue_t *iqueue,  gxio_mpipe_idesc_t *idesc)
{
    int result;

    result = gxio_mpipe_iqueue_get(iqueue, idesc);

    return (result == 0);   
}
*/
#else
static __attribute__((always_inline)) int
packet_pull(netio_queue_t *queue, netio_pkt_t *packet)
{
    return netio_get_packet(queue, packet) == NETIO_PKT;
}
#endif

void MpipeFreePacket(Packet *p) {
#ifdef __TILEGX_SIMULATION__
    static uint32_t packet_count = 0;
#endif
#ifdef MPIPE_DEBUG
    SCLogInfo("MpipeFreePacket %p", p);
#endif
    gxio_mpipe_push_buffer(context, p->idesc.stack_idx, (void *)(intptr_t)p->idesc.va);

#ifdef __TILEGX_SIMULATION__
    // disable profiling at end of input
    if (++packet_count == 10000) {
        SCLogInfo("Mpipe disabling profiler\n");
        sim_profiler_disable();
        SCLogInfo("Mpipe exiting\n");
        EngineStop();
    }
#endif
}

/**
 * \brief Mpipe "callback" function.
 *
 * This function fills in our packet structure from libpcap.
 * From here the packets are picked up by the  DecodePcap thread.
 *
 * \param user pointer to PcapThreadVars passed from pcap_dispatch
 * \param h pointer to pcap packet header
 * \param pkt pointer to raw packet data
 */
//void MpipeCallback(u_char *user,  netio_queue_t *queue, netio_pkt_t *packet) {
void MpipeCallback(u_char *user,   gxio_mpipe_idesc_t *idesc, Packet *p) {
    //netio_pkt_metadata_t *mda = NETIO_PKT_METADATA(packet);
    //int caplen = NETIO_PKT_L2_LENGTH_M(mda, packet);
    //u_char *pkt = NETIO_PKT_L2_DATA_M(mda, packet);
    int caplen = idesc->l2_size;
    u_char *pkt = (void *)(intptr_t)idesc->va;
    SCLogDebug("user %p, q %p, pkt %p", user, queue, packet);
    MpipeThreadVars *ptv = (MpipeThreadVars *)user;

#if 0
    Packet *p = NULL;
    if (ptv->array_idx == 0) {
        p = ptv->in_p;
    } else {
        p = PacketGetFromQueueOrAlloc();
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
    p->flags |= PKT_MPIPE;
#if 1
    SET_PKT_LEN(p, caplen);
#if 1
    p->pkt = pkt;
#else
    if (PacketCopyData(p, pkt, GET_PKT_LEN(p)) == -1)
        SCReturn;
#endif
#else
    p->pktlen = caplen;
    //memcpy(p->pkt, pkt, p->pktlen);
    p->pkt = pkt;
    p->ext_pkt = NULL;
#endif
    //SCLogDebug("p->pktlen: %" PRIu32 " (pkt %02x, p->pkt %02x)", p->pktlen, *pkt, *p->pkt);
#ifdef MPIPE_DEBUG
    SCLogInfo("p->pktlen: %" PRIu32 " (pkt %02x, p->pkt %02x)", p->pktlen, *pkt, *p->pkt);
#endif

    /* store the packet in our array */
    ptv->array[ptv->array_idx] = p;
    ptv->array_idx++;

    SCReturn;
}

/**
 * \brief Receives packets from an interface via gxio mpipe.
 */
TmEcode ReceiveMpipe(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq) {
    //gxio_mpipe_idesc_t idesc;
    SCEnter();
    uint16_t packet_q_len = 0;

    MpipeThreadVars *ptv = (MpipeThreadVars *)data;

    /* make sure we have at least one packet in the packet pool, to prevent
     * us from alloc'ing packets at line rate */
    while (packet_q_len == 0) {
        packet_q_len = PacketPoolSize();
        if (packet_q_len == 0) {
            PacketPoolWait();
        }
    }

    if (postpq == NULL)
        mpipe_max_read_packets = 1;

    ptv->array_idx = 0;
    ptv->in_p = p;

#ifdef MPIPE_DEBUG
    SCLogInfo("ReceiveMpipe!!!");
#endif

    /* Right now we just support reading packets one at a time. */
    int r = 0;
    while (r == 0) {
        int result = gxio_mpipe_iqueue_try_get(iqueue, &p->idesc);
        if (result == 0) {
#ifdef MPIPE_DEBUG
            char buf[128];
            sprintf(buf, "Got a packet size: %d", p->idesc.l2_size);
            SCLogInfo(buf);
#endif
            if (!p->idesc.be) {
                MpipeCallback((u_char *)ptv,  &p->idesc, p);
                r = 1;
            }
	}
        if (suricata_ctl_flags != 0) {
            break;
        }
    }

    uint16_t cnt = 0;
    for (cnt = 0; cnt < ptv->array_idx; cnt++) {
        Packet *pp = ptv->array[cnt];

        /* enqueue all but the first in the postpq, the first
         * pkt is handled by the tv "out handler" */
        if (cnt > 0) {
            SCLogInfo("PacketEnqueue packet p %p", pp);
            PacketEnqueue(postpq, pp);
        }
    }

    if (suricata_ctl_flags != 0) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode ReceiveMpipeThreadInit(ThreadVars *tv, void *initdata, void **data) {
    SCEnter()
#ifdef MPIPE_DEBUG
    SCLogInfo("ReceiveMpipeThreadInit\n");
#endif

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

#if 1

  int result;
  char *link_name = (char *)initdata;
  
  // Bind to a single cpu.
  cpu_set_t cpus;
  result = tmc_cpus_get_my_affinity(&cpus);
  VERIFY(result, "tmc_cpus_get_my_affinity()");
  result = tmc_cpus_set_my_cpu(tmc_cpus_find_first_cpu(&cpus));
  VERIFY(result, "tmc_cpus_set_my_cpu()");


  // Start the driver.
  //result = gxio_mpipe_init(context, 0);
  result = gxio_mpipe_init(context, gxio_mpipe_link_instance(link_name));
//printf("gxio_mpipe_init returned: %d\n", result);
  VERIFY(result, "gxio_mpipe_init()");

  gxio_mpipe_link_t link;
  result = gxio_mpipe_link_open(&link, context, link_name, 0);
//printf("gxio_mpipe_link_open returned: %d\n", result);
  VERIFY(result, "gxio_mpipe_link_open()");

  // Allocate one huge page to hold our buffer stack, notif ring, and
  // packets.  This should be more than enough space.
  size_t page_size = (1 << 24);
  tmc_alloc_t alloc = TMC_ALLOC_INIT;
  tmc_alloc_set_huge(&alloc);
  void* page = tmc_alloc_map(&alloc, page_size);
  assert(page);


  void* mem = page;


  // Allocate a NotifRing.
  result = gxio_mpipe_alloc_notif_rings(context, 1, 0, 0);
  VERIFY(result, "gxio_mpipe_alloc_notif_rings()");
  int ring = result;

  // Init the NotifRing.
  size_t notif_ring_entries = 128;
  size_t notif_ring_size = notif_ring_entries * sizeof(gxio_mpipe_idesc_t);
  result = gxio_mpipe_iqueue_init(iqueue, context, ring,
                                  mem, notif_ring_size, 0);
  VERIFY(result, "gxio_mpipe_iqueue_init()");
  //mem += ROUND_UP(notif_ring_size, PAGE_SIZE);
  mem += notif_ring_size;


  // Allocate a NotifGroup.
  result = gxio_mpipe_alloc_notif_groups(context, 1, 0, 0);
  VERIFY(result, "gxio_mpipe_alloc_notif_groups()");
  int group = result;

  // Allocate a bucket.
  result = gxio_mpipe_alloc_buckets(context, 1, 0, 0);
  VERIFY(result, "gxio_mpipe_alloc_buckets()");
  int bucket = result;

  // Init group and bucket.
  gxio_mpipe_bucket_mode_t mode = GXIO_MPIPE_BUCKET_ROUND_ROBIN;
  result = gxio_mpipe_init_notif_group_and_buckets(context, group,
                                                   ring, 1,
                                                   bucket, 1, mode);
  VERIFY(result, "gxio_mpipe_init_notif_group_and_buckets()");


  // Allocate a buffer stack.
  result = gxio_mpipe_alloc_buffer_stacks(context, 1, 0, 0);
  VERIFY(result, "gxio_mpipe_alloc_buffer_stacks()");
  int stack = result;

  // Total number of buffers.
  int num_buffers = 256;

  // Initialize the buffer stack.
  ALIGN(mem, 0x10000);
  size_t stack_bytes = gxio_mpipe_calc_buffer_stack_bytes(num_buffers);
  gxio_mpipe_buffer_size_enum_t buf_size = GXIO_MPIPE_BUFFER_SIZE_1664;
  result = gxio_mpipe_init_buffer_stack(context, stack, buf_size,
                                        mem, stack_bytes, 0);
  VERIFY(result, "gxio_mpipe_init_buffer_stack()");
  //mem += ROUND_UP(stack_bytes, PAGE_SIZE);
  mem += stack_bytes;

  ALIGN(mem, 0x10000);

  // Register the entire huge page of memory which contains all the buffers.
  result = gxio_mpipe_register_page(context, stack, page, page_size, 0);
  VERIFY(result, "gxio_mpipe_register_page()");

  // Push some buffers onto the stack.
  for (int i = 0; i < num_buffers; i++)
  {
    gxio_mpipe_push_buffer(context, stack, mem);
    mem += 1664;
  }

  // Paranoia.
  assert(mem <= page + page_size);


  // Register for packets.
  gxio_mpipe_rules_t rules;
  gxio_mpipe_rules_init(&rules, context);
  gxio_mpipe_rules_begin(&rules, bucket, 1, NULL);
  result = gxio_mpipe_rules_commit(&rules);
  VERIFY(result, "gxio_mpipe_rules_commit()");

#else
    /*
     * TBD: put all of the netio initialization stuff here
     */
    if (flows) {
        // Configure one queue to each worker.
        //
        queue_config(&queue, work_rank, (char *)initdata);
        SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED, "netio queue_config done");

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

#ifdef NOTYET
    // Have worker 0 start the network driver.
    //
    tmc_sync_barrier_wait(&shared->work_barrier);
#endif
    //SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED, "Calling netio_input_initialize");
    SCLogInfo("Calling netio_input_initialize");
    if (work_rank == 0)
        netio_input_initialize(&queue);
#endif

    //SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED, "ReceiveMpipe initialization complete!!!");
    SCLogInfo("ReceiveMpipe initialization complete!!!");
    *data = (void *)ptv;
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

    //SCLogInfo("DecodeNetio p %p", p);
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
        //SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED, "Error: datalink type %" PRId32 " not yet supported in module DecodeNetio", p->datalink);
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
int MpipeLiveRegisterDevice(char *dev)
{
    //printf("MpipeLiveRegisterDevice(\"%s\")\n", dev);
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
