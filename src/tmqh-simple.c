/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * Simple queue handler
 */

#include "suricata.h"
#include "packet-queue.h"
#include "decode.h"
#include "threads.h"
#include "threadvars.h"

#include "tm-queuehandlers.h"

#ifdef __tile__
#include <arch/cycle.h>
#include <tmc/mem.h>
#endif

Packet *TmqhInputSimple(ThreadVars *t);
void TmqhOutputSimple(ThreadVars *t, Packet *p);
void TmqhInputSimpleShutdownHandler(ThreadVars *);

void TmqhSimpleRegister (void) {
    tmqh_table[TMQH_SIMPLE].name = "simple";
    tmqh_table[TMQH_SIMPLE].InHandler = TmqhInputSimple;
    tmqh_table[TMQH_SIMPLE].InShutdownHandler = TmqhInputSimpleShutdownHandler;
    tmqh_table[TMQH_SIMPLE].OutHandler = TmqhOutputSimple;
}

#ifdef __tile__
/* static __attribute__((always_inline))*/ void
cycle_pause(unsigned int delay)
{
  const unsigned int start = get_cycle_count_low();
  while (get_cycle_count_low() - start < delay)
    ;
}
#endif

Packet *TmqhInputSimple(ThreadVars *t)
{
    PacketQueue *q = &trans_q[t->inq->id];

#ifdef __tile__
    tmc_spin_queued_mutex_lock(&q->mutex_q);
#else
    SCMutexLock(&q->mutex_q);
#endif

    if (q->len == 0) {
        /* if we have no packets in queue, wait... */
#ifdef __tile__
#if 1
        do {
            tmc_spin_queued_mutex_unlock(&q->mutex_q);
            while ((q->len == 0) && (q->cond_q == 0)) {
	        cycle_pause(101);
	        //cycle_pause(333);
            }
            tmc_spin_queued_mutex_lock(&q->mutex_q);
        } while ((q->len == 0) && (q->cond_q == 0));
#else
        for (;;) {
            if ((q->len > 0) || q->cond_q)
                break;
            tmc_spin_queued_mutex_unlock(&q->mutex_q);
            cycle_pause(1321);
            tmc_spin_queued_mutex_lock(&q->mutex_q);
        }
#endif
#else
        SCCondWait(&q->cond_q, &q->mutex_q);
#endif
    }

    SCPerfSyncCountersIfSignalled(t, 0);

    if (q->len > 0) {
        Packet *p = PacketDequeue(q);
#ifdef __tile__
        if (q->len == 0) q->cond_q = 0;
        tmc_spin_queued_mutex_unlock(&q->mutex_q);
#else
        SCMutexUnlock(&q->mutex_q);
#endif
        return p;
    } else {
        /* return NULL if we have no pkt. Should only happen on signals. */
#ifdef __tile__
        q->cond_q = 0;
        tmc_spin_queued_mutex_unlock(&q->mutex_q);
#else
        SCMutexUnlock(&q->mutex_q);
#endif
        return NULL;
    }
}

void TmqhInputSimpleShutdownHandler(ThreadVars *tv) {
    int i;

    if (tv == NULL || tv->inq == NULL) {
        return;
    }

    for (i = 0; i < (tv->inq->reader_cnt + tv->inq->writer_cnt); i++)
#ifdef __tile__
        trans_q[tv->inq->id].cond_q = 1;
#else
        SCCondSignal(&trans_q[tv->inq->id].cond_q);
#endif
}

void TmqhOutputSimple(ThreadVars *t, Packet *p)
{
    SCLogDebug("Packet %p, p->root %p, alloced %s", p, p->root, p->flags & PKT_ALLOC ? "true":"false");

    PacketQueue *q = &trans_q[t->outq->id];

#ifdef __tile__
    tmc_spin_queued_mutex_lock(&q->mutex_q);
#else
    SCMutexLock(&q->mutex_q);
#endif
    PacketEnqueue(q, p);
#ifdef __tile__
    q->cond_q = 1;
    tmc_mem_fence();
    tmc_spin_queued_mutex_unlock(&q->mutex_q);
#else
    SCCondSignal(&q->cond_q);
    SCMutexUnlock(&q->mutex_q);
#endif
}

/*******************************Generic-Q-Handlers*****************************/

/**
 * \brief Public version of TmqhInputSimple from the tmqh-simple queue
 *        handler, except that it is a generic version that is directly
 *        tied to a "SCDQDataQueue" instance(sent as an arg).
 *
 *        Retrieves a data_instance from the queue.  If the queue is empty, it
 *        waits on the queue, till a data_instance is enqueued into the queue
 *        by some other module.
 *
 *        All references to "data_instance" means a reference to a data structure
 *        instance that implements the template "struct SCDQGenericQData_".
 *
 * \param q The SCDQDataQueue instance to wait on.
 *
 * \retval p The returned packet from the queue.
 * \retval data The returned data_instance from the queue.
 */
SCDQGenericQData *TmqhInputSimpleOnQ(SCDQDataQueue *q)
{
#ifdef __tile__
    tmc_spin_queued_mutex_lock(&q->mutex_q);
#else
    SCMutexLock(&q->mutex_q);
#endif
    if (q->len == 0) {
        /* if we have no packets in queue, wait... */
#ifdef __tile__
        for (;;) {
            if ((q->len > 0) || q->cond_q)
                break;
            tmc_spin_queued_mutex_unlock(&q->mutex_q);
            cycle_pause(4300);
            tmc_spin_queued_mutex_lock(&q->mutex_q);
        }
#else
        SCCondWait(&q->cond_q, &q->mutex_q);
#endif
    }

    if (q->len > 0) {
        SCDQGenericQData *data = SCDQDataDequeue(q);
#ifdef __tile__
        if (q->len == 0) q->cond_q = 0;
        tmc_spin_queued_mutex_unlock(&q->mutex_q);
#else
        SCMutexUnlock(&q->mutex_q);
#endif
        return data;
    } else {
        /* return NULL if we have no data in the queue. Should only happen
         * on signals. */
#ifdef __tile__
        q->cond_q = 0;
        tmc_spin_queued_mutex_unlock(&q->mutex_q);
#else
        SCMutexUnlock(&q->mutex_q);
#endif
        return NULL;
    }
}

/**
 * \brief Public version of TmqhOutputSimple from the tmqh-simple queue
 *        handler, except that it is a generic version that is directly
 *        tied to a SCDQDataQueue instance(sent as an arg).
 *
 *        Pumps out a data_instance into the queue.  If the queue is empty, it
 *        waits on the queue, till a data_instance is enqueued into the queue.
 *
 *        All references to "data_instance" means a reference to a data structure
 *        instance that implements the template "struct SCDQGenericQData_".
 *
 * \param q    The SCDQDataQueue instance to pump the data into.
 * \param data The data instance to be enqueued.
 */
void TmqhOutputSimpleOnQ(SCDQDataQueue *q, SCDQGenericQData *data)
{
#ifdef __tile__
    tmc_spin_queued_mutex_lock(&q->mutex_q);
#else
    SCMutexLock(&q->mutex_q);
#endif
    SCDQDataEnqueue(q, data);
#ifdef __tile__
    q->cond_q = 0;
    tmc_spin_queued_mutex_unlock(&q->mutex_q);
#else
    SCCondSignal(&q->cond_q);
    SCMutexUnlock(&q->mutex_q);
#endif

    return;
}
