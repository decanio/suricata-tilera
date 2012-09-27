/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Flow utility functions
 */

#include "suricata-common.h"
#include "threads.h"

#include "flow.h"
#include "flow-private.h"
#include "flow-util.h"
#include "flow-var.h"
#include "app-layer.h"

#include "util-var.h"
#include "util-debug.h"

#include "detect.h"
#include "detect-engine-state.h"

#ifdef __tile__
#define FLOW_ALLOC_CACHE
#endif

#ifdef FLOW_ALLOC_CACHE
typedef union FlowCache_
{
    union FlowCache_ *next;
    Flow              flow;
} FlowCache;

static union FlowCache_ *FlowAllocList;
static SCMutex flow_alloc_mutex;
#endif

/** \brief allocate a flow
 *
 *  We check against the memuse counter. If it passes that check we increment
 *  the counter first, then we try to alloc.
 *
 *  \retval f the flow or NULL on out of memory
 */
Flow *FlowAlloc(void)
{
    Flow *f;

    if (!(FLOW_CHECK_MEMCAP(sizeof(Flow)))) {
        return NULL;
    }

    (void) SC_ATOMIC_ADD(flow_memuse, sizeof(Flow));

#ifdef FLOW_ALLOC_CACHE
    FlowCache *fc;
    SCMutexLock(&flow_alloc_mutex);
    fc = FlowAllocList;
    FlowAllocList = fc->next;
    SCMutexUnlock(&flow_alloc_mutex);
    f = &fc->flow;
#else
    f = SCMalloc(sizeof(Flow));
#endif
    if (unlikely(f == NULL)) {
        (void)SC_ATOMIC_SUB(flow_memuse, sizeof(Flow));
        return NULL;
    }

    FLOW_INITIALIZE(f);
    return f;
}


/**
 *  \brief cleanup & free the memory of a flow
 *
 *  \param f flow to clear & destroy
 */
void FlowFree(Flow *f)
{
    FLOW_DESTROY(f);
#ifdef FLOW_ALLOC_CACHE
    FlowCache *fc = (FlowCache *)f;
    SCMutexLock(&flow_alloc_mutex);
    fc->next = FlowAllocList;
    FlowAllocList = fc;
    SCMutexUnlock(&flow_alloc_mutex);
#else
    SCFree(f);
#endif

    (void) SC_ATOMIC_SUB(flow_memuse, sizeof(Flow));
}

/**
 *  \brief   Function to map the protocol to the defined FLOW_PROTO_* enumeration.
 *
 *  \param   proto  protocol which is needed to be mapped
 */

uint8_t FlowGetProtoMapping(uint8_t proto) {

    switch (proto) {
        case IPPROTO_TCP:
            return FLOW_PROTO_TCP;
        case IPPROTO_UDP:
            return FLOW_PROTO_UDP;
        case IPPROTO_ICMP:
            return FLOW_PROTO_ICMP;
        case IPPROTO_SCTP:
            return FLOW_PROTO_SCTP;
        default:
            return FLOW_PROTO_DEFAULT;
    }
}

/* initialize the flow from the first packet
 * we see from it. */
void FlowInit(Flow *f, Packet *p)
{
    SCEnter();
    SCLogDebug("flow %p", f);

    f->proto = p->proto;
    f->recursion_level = p->recursion_level;

    if (PKT_IS_IPV4(p)) {
        FLOW_SET_IPV4_SRC_ADDR_FROM_PACKET(p, &f->src);
        FLOW_SET_IPV4_DST_ADDR_FROM_PACKET(p, &f->dst);
        f->flags |= FLOW_IPV4;
    } else if (PKT_IS_IPV6(p)) {
        FLOW_SET_IPV6_SRC_ADDR_FROM_PACKET(p, &f->src);
        FLOW_SET_IPV6_DST_ADDR_FROM_PACKET(p, &f->dst);
        f->flags |= FLOW_IPV6;
    }
#ifdef DEBUG
    /* XXX handle default */
    else {
        printf("FIXME: %s:%s:%" PRId32 "\n", __FILE__, __FUNCTION__, __LINE__);
    }
#endif

    if (p->tcph != NULL) { /* XXX MACRO */
        SET_TCP_SRC_PORT(p,&f->sp);
        SET_TCP_DST_PORT(p,&f->dp);
    } else if (p->udph != NULL) { /* XXX MACRO */
        SET_UDP_SRC_PORT(p,&f->sp);
        SET_UDP_DST_PORT(p,&f->dp);
    } else if (p->icmpv4h != NULL) {
        f->type = p->type;
        f->code = p->code;
    } else if (p->icmpv6h != NULL) {
        f->type = p->type;
        f->code = p->code;
    } else if (p->sctph != NULL) { /* XXX MACRO */
        SET_SCTP_SRC_PORT(p,&f->sp);
        SET_SCTP_DST_PORT(p,&f->dp);
    } /* XXX handle default */
#ifdef DEBUG
    else {
        printf("FIXME: %s:%s:%" PRId32 "\n", __FILE__, __FUNCTION__, __LINE__);
    }
#endif
    COPY_TIMESTAMP(&p->ts, &f->startts);

    f->protomap = FlowGetProtoMapping(f->proto);

    SCReturn;
}

void FlowAllocPoolInit(void)
{
    SCEnter();
#ifdef FLOW_ALLOC_CACHE
    /* TBD: maybe use per thread Flow structures */
    FlowCache *p;
    int NumCachedFlows = flow_config.memcap / sizeof(Flow);
    int i;

    SCLogInfo("Allocating %lu bytes of Flow cache (%d flows)\n", flow_config.memcap, NumCachedFlows);
    p = SCMalloc(flow_config.memcap);
    if (p == NULL) {
        SCLogError(SC_ERR_FATAL, "Fatal error encountered while allocating Flow cache. Exiting...");
        exit(EXIT_FAILURE);
    }
    FlowAllocList = p;
    for (i = 0; i < NumCachedFlows-1; i++) {
        p->next = (p+1);
        ++p;
    }
    p->next = NULL;
    SCMutexInit(&flow_alloc_mutex, NULL);
 
#endif
    SCReturn;
}
