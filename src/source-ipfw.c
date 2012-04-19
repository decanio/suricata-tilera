/* Copyright (C) 2007-2011 Open Information Security Foundation
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
 * \author Nick Rogness <nick@rogness.net>
 * \author Eric Leblond <eric@regit.org>
 *
 * IPFW packet acquisition support
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-threads.h"
#include "source-ipfw.h"
#include "util-debug.h"
#include "conf.h"
#include "util-byte.h"
#include "util-privs.h"
#include "util-device.h"

#define IPFW_ACCEPT 0
#define IPFW_DROP 1

#define IPFW_SOCKET_POLL_MSEC 300

#ifndef IP_MAXPACKET
#define IP_MAXPACKET 65535
#endif

#ifndef IPFW
/* Handle the case if --enable-ipfw was not used
 *
 */

TmEcode NoIPFWSupportExit(ThreadVars *, void *, void **);

void TmModuleReceiveIPFWRegister (void) {

    tmm_modules[TMM_RECEIVEIPFW].name = "ReceiveIPFW";
    tmm_modules[TMM_RECEIVEIPFW].ThreadInit = NoIPFWSupportExit;
    tmm_modules[TMM_RECEIVEIPFW].Func = NULL;
    tmm_modules[TMM_RECEIVEIPFW].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVEIPFW].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEIPFW].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEIPFW].flags = TM_FLAG_RECEIVE_TM;
}

void TmModuleVerdictIPFWRegister (void) {
    tmm_modules[TMM_VERDICTIPFW].name = "VerdictIPFW";
    tmm_modules[TMM_VERDICTIPFW].ThreadInit = NoIPFWSupportExit;
    tmm_modules[TMM_VERDICTIPFW].Func = NULL;
    tmm_modules[TMM_VERDICTIPFW].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_VERDICTIPFW].ThreadDeinit = NULL;
    tmm_modules[TMM_VERDICTIPFW].RegisterTests = NULL;
}

void TmModuleDecodeIPFWRegister (void) {
    tmm_modules[TMM_DECODEIPFW].name = "DecodeIPFW";
    tmm_modules[TMM_DECODEIPFW].ThreadInit = NoIPFWSupportExit;
    tmm_modules[TMM_DECODEIPFW].Func = NULL;
    tmm_modules[TMM_DECODEIPFW].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEIPFW].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEIPFW].RegisterTests = NULL;
    tmm_modules[TMM_DECODEIPFW].cap_flags = 0;
}

TmEcode NoIPFWSupportExit(ThreadVars *tv, void *initdata, void **data) {

    SCLogError(SC_ERR_IPFW_NOSUPPORT,"Error creating thread %s: you do not have support for ipfw "
           "enabled please recompile with --enable-ipfw", tv->name);
    exit(EXIT_FAILURE);
}

#else /* We have IPFW compiled in */

extern int max_pending_packets;

/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct IPFWThreadVars_
{
    /* data link type for the thread, probably not needed */
    int datalink;

    /* this one should be not changing after init */
    uint16_t port_num;
    /* position into the NFQ queue var array */
    uint16_t ipfw_index;

    /* counters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;
    uint32_t accepted;
    uint32_t dropped;
} IPFWThreadVars;

static IPFWThreadVars ipfw_t[IPFW_MAX_QUEUE];
static IPFWQueueVars ipfw_q[IPFW_MAX_QUEUE];
static uint16_t receive_port_num = 0;
static SCMutex ipfw_init_lock;

/* IPFW Prototypes */
void *IPFWGetQueue(int number);
TmEcode ReceiveIPFWThreadInit(ThreadVars *, void *, void **);
TmEcode ReceiveIPFW(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode ReceiveIPFWLoop(ThreadVars *tv, void *data, void *slot);
void ReceiveIPFWThreadExitStats(ThreadVars *, void *);
TmEcode ReceiveIPFWThreadDeinit(ThreadVars *, void *);

TmEcode IPFWSetVerdict(ThreadVars *, IPFWThreadVars *, Packet *);
TmEcode VerdictIPFW(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode VerdictIPFWThreadInit(ThreadVars *, void *, void **);
void VerdictIPFWThreadExitStats(ThreadVars *, void *);
TmEcode VerdictIPFWThreadDeinit(ThreadVars *, void *);

TmEcode DecodeIPFWThreadInit(ThreadVars *, void *, void **);
TmEcode DecodeIPFW(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

/**
 * \brief Registration Function for RecieveIPFW.
 * \todo Unit tests are needed for this module.
 */
void TmModuleReceiveIPFWRegister (void) {
    SCMutexInit(&ipfw_init_lock, NULL);

    tmm_modules[TMM_RECEIVEIPFW].name = "ReceiveIPFW";
    tmm_modules[TMM_RECEIVEIPFW].ThreadInit = ReceiveIPFWThreadInit;
    tmm_modules[TMM_RECEIVEIPFW].Func = ReceiveIPFW;
    tmm_modules[TMM_RECEIVEIPFW].PktAcqLoop = ReceiveIPFWLoop;
    tmm_modules[TMM_RECEIVEIPFW].ThreadExitPrintStats = ReceiveIPFWThreadExitStats;
    tmm_modules[TMM_RECEIVEIPFW].ThreadDeinit = ReceiveIPFWThreadDeinit;
    tmm_modules[TMM_RECEIVEIPFW].cap_flags = SC_CAP_NET_ADMIN | SC_CAP_NET_RAW |
                                             SC_CAP_NET_BIND_SERVICE |
                                             SC_CAP_NET_BROADCAST; /** \todo untested */
    tmm_modules[TMM_RECEIVEIPFW].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEIPFW].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Registration Function for VerdictIPFW.
 * \todo Unit tests are needed for this module.
 */
void TmModuleVerdictIPFWRegister (void) {
    tmm_modules[TMM_VERDICTIPFW].name = "VerdictIPFW";
    tmm_modules[TMM_VERDICTIPFW].ThreadInit = VerdictIPFWThreadInit;
    tmm_modules[TMM_VERDICTIPFW].Func = VerdictIPFW;
    tmm_modules[TMM_VERDICTIPFW].ThreadExitPrintStats = VerdictIPFWThreadExitStats;
    tmm_modules[TMM_VERDICTIPFW].ThreadDeinit = VerdictIPFWThreadDeinit;
    tmm_modules[TMM_VERDICTIPFW].cap_flags = SC_CAP_NET_ADMIN | SC_CAP_NET_RAW |
                                             SC_CAP_NET_BIND_SERVICE; /** \todo untested */
    tmm_modules[TMM_VERDICTIPFW].RegisterTests = NULL;
}

/**
 * \brief Registration Function for DecodeIPFW.
 * \todo Unit tests are needed for this module.
 */
void TmModuleDecodeIPFWRegister (void) {
    tmm_modules[TMM_DECODEIPFW].name = "DecodeIPFW";
    tmm_modules[TMM_DECODEIPFW].ThreadInit = DecodeIPFWThreadInit;
    tmm_modules[TMM_DECODEIPFW].Func = DecodeIPFW;
    tmm_modules[TMM_DECODEIPFW].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEIPFW].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEIPFW].RegisterTests = NULL;
}

static inline void IPFWMutexInit(IPFWQueueVars *nq)
{
    char *active_runmode = RunmodeGetActive();

    if (active_runmode && !strcmp("worker", active_runmode)) {
        nq->use_mutex = 0;
        SCLogInfo("IPFW running in 'worker' runmode, will not use mutex.");
    } else {
        nq->use_mutex = 1;
    }
    if (nq->use_mutex)
        SCMutexInit(&nq->socket_lock, NULL);
}

static inline void IPFWMutexLock(IPFWQueueVars *nq)
{
    if (nq->use_mutex)
        SCMutexLock(&nq->socket_lock);
}

static inline void IPFWMutexUnlock(IPFWQueueVars *nq)
{
    if (nq->use_mutex)
        SCMutexUnlock(&nq->socket_lock);
}



/**
 * \brief Recieves packets from an interface via ipfw divert socket.
 * \todo Unit tests are needed for this module.
 *
 *  This function recieves packets from an ipfw divert socket and passes
 *  the packet on to the queue
 *
 * \param tv pointer to ThreadVars
 * \param p pointer to Packet
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 * \param pq pointer to the PacketQueue (not used here but part of the api)
 * \retval TM_ECODE_FAILED on failure and TM_ECODE_OK on success
 */
TmEcode ReceiveIPFW(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    IPFWThreadVars *ptv = (IPFWThreadVars *)data;
    IPFWQueueVars *nq = IPFWGetQueue(ptv->ipfw_index);
    uint8_t pkt[IP_MAXPACKET];
    int pktlen=0;
    int r = 0;
    struct pollfd IPFWpoll;
    struct timeval IPFWts;
    SCEnter();

    //printf("Entering RecieveIPFW\n");

    IPFWpoll.fd = nq->fd;
    IPFWpoll.events = POLLRDNORM;

    /* Read packets from divert socket */
    while (r == 0) {

       /* Did we receive a signal to shutdown */
        if ( TmThreadsCheckFlag(tv, THV_KILL) || TmThreadsCheckFlag(tv, THV_PAUSE)) {
            SCLogInfo("Received ThreadShutdown: IPFW divert socket polling interrupted");
            SCReturnInt(TM_ECODE_OK);
        }

        /* Poll the socket for status */
        if ( (poll(&IPFWpoll,1,IPFW_SOCKET_POLL_MSEC)) > 0) {
            if ( IPFWpoll.revents & (POLLRDNORM | POLLERR) )
                r++;
        }

    } /* end while */

    if ((pktlen = recvfrom(nq->fd, pkt, sizeof(pkt), 0,(struct sockaddr *)&nq->ipfw_sin, &nq->ipfw_sinlen)) == -1) {
        /* We received an error on socket read */
        if (errno == EINTR || errno == EWOULDBLOCK) {
            /* Nothing for us to process */
            SCReturnInt(TM_ECODE_OK);

        } else {
            SCLogWarning(SC_WARN_IPFW_RECV,"Read from IPFW divert socket failed: %s",strerror(errno));
            SCReturnInt(TM_ECODE_FAILED);
        }
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* We have a packet to process */
    memset (&IPFWts, 0, sizeof(struct timeval));
    gettimeofday(&IPFWts, NULL);
    r++;

    SCLogDebug("Received Packet Len: %d",pktlen);

    /* Setup packet */
    p = tv->tmqh_in(tv);

    p->ts.tv_sec = IPFWts.tv_sec;
    p->ts.tv_usec = IPFWts.tv_usec;

    ptv->pkts++;
    ptv->bytes += pktlen;

    p->datalink = ptv->datalink;

    p->ipfw_v.ipfw_index = ptv->ipfw_index;

    PacketCopyData(p, pkt, pktlen);
    SCLogDebug("Packet info: pkt_len: %" PRIu32 " (pkt %02x, pkt_data %02x)", GET_PKT_LEN(p), *pkt, GET_PKT_DATA(p));

    /* pass on... */
    tv->tmqh_out(tv, p);

    SCReturnInt(TM_ECODE_OK);

}


TmEcode ReceiveIPFWLoop(ThreadVars *tv, void *data, void *slot)
{
    IPFWThreadVars *ptv = (IPFWThreadVars *)data;
    IPFWQueueVars *nq = NULL;
    uint8_t pkt[IP_MAXPACKET];
    int pktlen=0;
    struct pollfd IPFWpoll;
    struct timeval IPFWts;
    Packet *p = NULL;
    uint16_t packet_q_len = 0;
    SCEnter();


    if (ptv == NULL) {
        SCLogWarning(SC_ERR_INVALID_ARGUMENT, "Null data pointer");
        SCReturnInt(TM_ECODE_FAILED);
    }
    nq = IPFWGetQueue(ptv->ipfw_index);
    if (nq == NULL) {
        SCLogWarning(SC_ERR_INVALID_ARGUMENT, "Can't get thread variable");
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCLogInfo("Thread '%s' will run on port %d (item %d)",
              tv->name,
              nq->port_num,
              ptv->ipfw_index);
    while (1) {
        if (suricata_ctl_flags & SURICATA_STOP ||
            suricata_ctl_flags & SURICATA_KILL)
        {
            SCReturnInt(TM_ECODE_OK);
        }

        IPFWpoll.fd = nq->fd;
        IPFWpoll.events = POLLRDNORM;
        /* Poll the socket for status */
        if ( (poll(&IPFWpoll, 1, IPFW_SOCKET_POLL_MSEC)) > 0) {
            if (!(IPFWpoll.revents & (POLLRDNORM | POLLERR)))
                continue;
        }

        if ((pktlen = recvfrom(nq->fd, pkt, sizeof(pkt), 0,
                               (struct sockaddr *)&nq->ipfw_sin,
                               &nq->ipfw_sinlen)) == -1) {
            /* We received an error on socket read */
            if (errno == EINTR || errno == EWOULDBLOCK) {
                /* Nothing for us to process */
                continue;
            } else {
                SCLogWarning(SC_WARN_IPFW_RECV,
                             "Read from IPFW divert socket failed: %s",
                             strerror(errno));
                SCReturnInt(TM_ECODE_FAILED);
            }
            SCReturnInt(TM_ECODE_FAILED);
        }
        /* We have a packet to process */
        memset (&IPFWts, 0, sizeof(struct timeval));
        gettimeofday(&IPFWts, NULL);

        /* make sure we have at least one packet in the packet pool, to prevent
         * us from alloc'ing packets at line rate */
        do {
            packet_q_len = PacketPoolSize();
            if (unlikely(packet_q_len == 0)) {
                PacketPoolWait();
            }
        } while (packet_q_len == 0);

        p = PacketGetFromQueueOrAlloc();
        if (p == NULL) {
            SCReturnInt(TM_ECODE_FAILED);
        }

        SCLogDebug("Received Packet Len: %d", pktlen);

        p->ts.tv_sec = IPFWts.tv_sec;
        p->ts.tv_usec = IPFWts.tv_usec;

        ptv->pkts++;
        ptv->bytes += pktlen;

        p->datalink = ptv->datalink;

        p->ipfw_v.ipfw_index = ptv->ipfw_index;

        PacketCopyData(p, pkt, pktlen);
        SCLogDebug("Packet info: pkt_len: %" PRIu32 " (pkt %02x, pkt_data %02x)",
                   GET_PKT_LEN(p), *pkt, GET_PKT_DATA(p));

        if (TmThreadsSlotProcessPkt(tv, ((TmSlot *) slot)->slot_next, p)
                != TM_ECODE_OK) {
            TmqhOutputPacketpool(tv, p);
            SCReturnInt(TM_ECODE_FAILED);
        }

        SCPerfSyncCountersIfSignalled(tv, 0);
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Init function for RecieveIPFW.
 *
 * This is a setup function for recieving packets
 * via ipfw divert, binds a socket, and prepares to
 * to read from it.
 *
 * \param tv pointer to ThreadVars
 * \param initdata pointer to the divert port passed from the user
 * \param data pointer gets populated with IPFWThreadVars
 *
 */
TmEcode ReceiveIPFWThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    struct timeval timev;
    IPFWThreadVars *ntv = (IPFWThreadVars *) initdata;
    IPFWQueueVars *nq = IPFWGetQueue(ntv->ipfw_index);

    sigset_t sigs;
    sigfillset(&sigs);
    pthread_sigmask(SIG_UNBLOCK, &sigs, NULL);

    SCEnter();

    IPFWMutexInit(nq);
    /* We need a divert socket to play with */
    if ((nq->fd = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT)) == -1) {
        SCLogError(SC_ERR_IPFW_SOCK,"Can't create divert socket: %s", strerror(errno));
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* set a timeout to the socket so we can check for a signal
     * in case we don't get packets for a longer period. */
    timev.tv_sec = 1;
    timev.tv_usec = 0;

    if (setsockopt(nq->fd, SOL_SOCKET, SO_RCVTIMEO, &timev, sizeof(timev)) == -1) {
        SCLogWarning(SC_WARN_IPFW_SETSOCKOPT,"Can't set IPFW divert socket timeout: %s", strerror(errno));
        SCReturnInt(TM_ECODE_FAILED);
    }

    nq->ipfw_sinlen=sizeof(nq->ipfw_sin);
    memset(&nq->ipfw_sin, 0, nq->ipfw_sinlen);
    nq->ipfw_sin.sin_family = PF_INET;
    nq->ipfw_sin.sin_addr.s_addr = INADDR_ANY;
    nq->ipfw_sin.sin_port = htons(nq->port_num);

    /* Bind that SOB */
    if (bind(nq->fd, (struct sockaddr *)&nq->ipfw_sin, nq->ipfw_sinlen) == -1) {
        SCLogError(SC_ERR_IPFW_BIND,"Can't bind divert socket on port %d: %s",nq->port_num,strerror(errno));
        SCReturnInt(TM_ECODE_FAILED);
    }

    ntv->datalink = DLT_RAW;

    *data = (void *)ntv;

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function prints stats to the screen at exit.
 * \todo Unit tests are needed for this module.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 */
void ReceiveIPFWThreadExitStats(ThreadVars *tv, void *data)
{
    IPFWThreadVars *ptv = (IPFWThreadVars *)data;

    SCEnter();

    SCLogInfo("(%s) Packets %" PRIu32 ", bytes %" PRIu64 "", tv->name, ptv->pkts, ptv->bytes);

    SCReturn;
}

/**
 * \brief DeInit function closes divert socket at exit.
 * \todo Unit tests are needed for this module.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 */
TmEcode ReceiveIPFWThreadDeinit(ThreadVars *tv, void *data)
{
    IPFWThreadVars *ptv = (IPFWThreadVars *)data;
    IPFWQueueVars *nq = IPFWGetQueue(ptv->ipfw_index);

    SCEnter();

    /* Attempt to shut the socket down...close instead? */
    if (shutdown(nq->fd, SHUT_RD) < 0) {
        SCLogWarning(SC_WARN_IPFW_UNBIND,"Unable to disable ipfw socket: %s",strerror(errno));
        SCReturnInt(TM_ECODE_FAILED);
    }

    data = (void *)ptv;

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function passes off to link type decoders.
 * \todo Unit tests are needed for this module.
 *
 * DecodeIPFW reads packets from the PacketQueue and passes
 * them off to the proper link type decoder.
 *
 * \param tv pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 * \param pq pointer to the PacketQueue
 */
TmEcode DecodeIPFW(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    IPV4Hdr *ip4h = (IPV4Hdr *)GET_PKT_DATA(p);
    IPV6Hdr *ip6h = (IPV6Hdr *)GET_PKT_DATA(p);
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    SCEnter();

    /* update counters */
    SCPerfCounterIncr(dtv->counter_pkts, tv->sc_perf_pca);
    SCPerfCounterAddUI64(dtv->counter_bytes, tv->sc_perf_pca, GET_PKT_LEN(p));
    SCPerfCounterAddUI64(dtv->counter_avg_pkt_size, tv->sc_perf_pca, GET_PKT_LEN(p));
    SCPerfCounterSetUI64(dtv->counter_max_pkt_size, tv->sc_perf_pca, GET_PKT_LEN(p));

    /* Process IP packets */
    if (IPV4_GET_RAW_VER(ip4h) == 4) {
        SCLogDebug("DecodeIPFW ip4 processing");
        DecodeIPV4(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);

    } else if(IPV6_GET_RAW_VER(ip6h) == 6) {
        SCLogDebug("DecodeIPFW ip6 processing");
        DecodeIPV6(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);

    } else {
        /* We don't support anything besides IP packets for now, bridged packets? */
        SCLogInfo("IPFW unknown protocol support %02x", *GET_PKT_DATA(p));
       SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function initializes the DecodeThreadVariables
 *
 *
 * \param tv pointer to ThreadVars
 * \param initdata pointer for passing in args
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 */
TmEcode DecodeIPFWThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    DecodeThreadVars *dtv = NULL;
    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function sets the Verdict and processes the packet
 *
 *
 * \param tv pointer to ThreadVars
 * \param p pointer to the Packet
 */
TmEcode IPFWSetVerdict(ThreadVars *tv, IPFWThreadVars *ptv, Packet *p)
{
    uint32_t verdict;
    struct pollfd IPFWpoll;
    IPFWQueueVars *nq = NULL;

    SCEnter();

    if (p == NULL) {
        SCLogWarning(SC_ERR_INVALID_ARGUMENT, "Packet is NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    nq = IPFWGetQueue(p->ipfw_v.ipfw_index);
    if (nq == NULL) {
        SCLogWarning(SC_ERR_INVALID_ARGUMENT, "No thread found");
        SCReturnInt(TM_ECODE_FAILED);
    }

    IPFWpoll.fd = nq->fd;
    IPFWpoll.events = POLLWRNORM;

    if (p->action & ACTION_DROP) {
        verdict = IPFW_DROP;
    } else {
        verdict = IPFW_ACCEPT;
    }

    if (verdict == IPFW_ACCEPT) {
        SCLogDebug("IPFW Verdict is to Accept");
        ptv->accepted++;

        /* For divert sockets, accepting means writing the
         * packet back to the socket for ipfw to pick up
         */
        SCLogDebug("IPFWSetVerdict writing to socket %d, %p, %u", nq->fd, GET_PKT_DATA(p),GET_PKT_LEN(p));

#if 0
        while ((poll(&IPFWpoll,1,IPFW_SOCKET_POLL_MSEC)) < 1) {
            /* Did we receive a signal to shutdown */
            if (TmThreadsCheckFlag(tv, THV_KILL) || TmThreadsCheckFlag(tv, THV_PAUSE)) {
                SCLogInfo("Received ThreadShutdown: IPFW divert socket writing interrupted");
                SCReturnInt(TM_ECODE_OK);
            }
        }
#endif

        IPFWMutexLock(nq);
        if (sendto(nq->fd, GET_PKT_DATA(p), GET_PKT_LEN(p), 0,(struct sockaddr *)&nq->ipfw_sin, nq->ipfw_sinlen) == -1) {
            SCLogWarning(SC_WARN_IPFW_XMIT,"Write to ipfw divert socket failed: %s",strerror(errno));
            IPFWMutexUnlock(&nq->socket_lock);
            SCReturnInt(TM_ECODE_FAILED);
        }

        IPFWMutexUnlock(nq);

        SCLogDebug("Sent Packet back into IPFW Len: %d",GET_PKT_LEN(p));

    } /* end IPFW_ACCEPT */


    if (verdict == IPFW_DROP) {
        SCLogDebug("IPFW SetVerdict is to DROP");
        ptv->dropped++;

        /** \todo For divert sockets, dropping means not writing the packet back to the socket.
         * Need to see if there is some better way to free the packet from the queue */

    } /* end IPFW_DROP */

    SCReturnInt(TM_ECODE_OK);
}


/**
 * \brief This function handles the Verdict processing
 * \todo Unit tests are needed for this module.
 *
 *
 * \param tv pointer to ThreadVars
 * \param p pointer to the Packet
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 * \param pq pointer for the Packet Queue access (Not used)
 */
TmEcode VerdictIPFW(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    IPFWThreadVars *ptv = (IPFWThreadVars *)data;
    TmEcode retval = TM_ECODE_OK;

    SCEnter();

    /* can't verdict a "fake" packet */
    if (p->flags & PKT_PSEUDO_STREAM_END) {
        SCReturnInt(TM_ECODE_OK);
    }

    /* This came from NFQ.
     *  if this is a tunnel packet we check if we are ready to verdict
     * already. */
    if (IS_TUNNEL_PKT(p)) {
        char verdict = 1;

        SCMutex *m = p->root ? &p->root->tunnel_mutex : &p->tunnel_mutex;
        SCMutexLock(m);

        /* if there are more tunnel packets than ready to verdict packets,
         * we won't verdict this one
         */
        if (TUNNEL_PKT_TPR(p) > TUNNEL_PKT_RTV(p)) {
            SCLogDebug("VerdictIPFW: not ready to verdict yet: "
                    "TUNNEL_PKT_TPR(p) > TUNNEL_PKT_RTV(p) = %" PRId32
                    " > %" PRId32 "", TUNNEL_PKT_TPR(p), TUNNEL_PKT_RTV(p));
            verdict = 0;
        }

        SCMutexUnlock(m);

        /* don't verdict if we are not ready */
        if (verdict == 1) {
            SCLogDebug("Setting verdict on tunnel");
            retval = IPFWSetVerdict(tv, ptv, p->root ? p->root : p);

        } else {
            TUNNEL_INCR_PKT_RTV(p);
        }
    } else {
        /* no tunnel, verdict normally */
        SCLogDebug("Setting verdict on non-tunnel");
        retval = IPFWSetVerdict(tv, ptv, p);
    } /* IS_TUNNEL_PKT end */

    SCReturnInt(retval);
}

/**
 * \brief This function initializes the VerdictThread
 *
 *
 * \param t pointer to ThreadVars
 * \param initdata pointer for passing in args
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 */
TmEcode VerdictIPFWThreadInit(ThreadVars *tv, void *initdata, void **data)
{

    IPFWThreadVars *ptv = NULL;

    SCEnter();

    /* Setup Thread vars */
    if ( (ptv = SCMalloc(sizeof(IPFWThreadVars))) == NULL)
        SCReturnInt(TM_ECODE_FAILED);
    memset(ptv, 0, sizeof(IPFWThreadVars));


    *data = (void *)ptv;

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function deinitializes the VerdictThread
 *
 *
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 */
TmEcode VerdictIPFWThreadDeinit(ThreadVars *tv, void *data)
{

    SCEnter();

    /* We don't need to do anything...not sure quite yet */


    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function prints stats for the VerdictThread
 *
 *
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 */
void VerdictIPFWThreadExitStats(ThreadVars *tv, void *data)
{
    IPFWThreadVars *ptv = (IPFWThreadVars *)data;
    SCLogInfo("IPFW Processing: - (%s) Pkts accepted %" PRIu32 ", dropped %" PRIu32 "", tv->name, ptv->accepted, ptv->dropped);
}

/**
 *  \brief Add an IPFW divert
 *
 *  \param string with the queue name
 *
 *  \retval 0 on success.
 *  \retval -1 on failure.
 */
int IPFWRegisterQueue(char *queue)
{
    IPFWThreadVars *ntv = NULL;
    IPFWQueueVars *nq = NULL;
    /* Extract the queue number from the specified command line argument */
    uint16_t port_num = 0;
    if ((ByteExtractStringUint16(&port_num, 10, strlen(queue), queue)) < 0)
    {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "specified queue number %s is not "
                                        "valid", queue);
        return -1;
    }

    SCMutexLock(&ipfw_init_lock);
    if (receive_port_num >= IPFW_MAX_QUEUE) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                   "too much IPFW divert port registered (%d)",
                   receive_port_num);
        SCMutexUnlock(&ipfw_init_lock);
        return -1;
    }
    if (receive_port_num == 0) {
        memset(&ipfw_t, 0, sizeof(ipfw_t));
        memset(&ipfw_q, 0, sizeof(ipfw_q));
    }

    ntv = &ipfw_t[receive_port_num];
    ntv->ipfw_index = receive_port_num;

    nq = &ipfw_q[receive_port_num];
    nq->port_num = port_num;
    receive_port_num++;
    SCMutexUnlock(&ipfw_init_lock);
    LiveRegisterDevice(queue);

    SCLogDebug("Queue \"%s\" registered.", queue);
    return 0;
}

/**
 *  \brief Get a pointer to the IPFW queue at index
 *
 *  \param number idx of the queue in our array
 *
 *  \retval ptr pointer to the IPFWThreadVars at index
 *  \retval NULL on error
 */
void *IPFWGetQueue(int number) {
    if (number >= receive_port_num)
        return NULL;

    return (void *)&ipfw_q[number];
}

/**
 *  \brief Get a pointer to the IPFW thread at index
 *
 *  This function is temporary used as configuration parser.
 *
 *  \param number idx of the queue in our array
 *
 *  \retval ptr pointer to the IPFWThreadVars at index
 *  \retval NULL on error
 */
void *IPFWGetThread(int number) {
    if (number >= receive_port_num)
        return NULL;

    return (void *)&ipfw_t[number];
}

#endif /* End ifdef IPFW */

/* eof */

