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
 * \author Tom DeCanio <decanio.tom@gmail.com>
 *
 * TMC queue handler
 */

#include "suricata.h"
#include "packet-queue.h"
#include "decode.h"
#include "threads.h"
#include "threadvars.h"

#include "tm-queuehandlers.h"

#ifdef __tile__

/* modeled after Tilera TMC queue */
#define LOG2_PACKETQ_ENTRIES 10 /* 2048 entries */
typedef struct TmcPacketQueue_ {
    tmc_spin_queued_mutex_t enqueue_mutex;
    unsigned int enqueue_count;

    tmc_spin_queued_mutex_t dequeue_mutex __attribute__((aligned(64)));
    unsigned int dequeue_count;

    Packet *array[1<<LOG2_PACKETQ_ENTRIES] __attribute__((aligned(64)));
} TmcPacketQueue;


static TmcPacketQueue *tmcqueues[256];

Packet *TmqhInputTmcQueueMrSw(ThreadVars *t);
void TmqhOutputTmcQueueMrSw(ThreadVars *t, Packet *p);
Packet *TmqhInputTmcQueueSrSw(ThreadVars *t);
void TmqhOutputTmcQueueSrSw(ThreadVars *t, Packet *p);
Packet *TmqhInputTmcQueueSrMw(ThreadVars *t);
void TmqhOutputTmcQueueSrMw(ThreadVars *t, Packet *p);
void TmqhInputTmcQueueShutdownHandler(ThreadVars *);

TmcPacketQueue *TmqhTmcQueueInit(void) {
    TmcPacketQueue *q = SCMalloc(sizeof(TmcPacketQueue));
    if (q == NULL) {
        return NULL;
    }

    memset(q, 0x00, sizeof(TmcPacketQueue));

    tmc_spin_queued_mutex_init(&q->enqueue_mutex); 
    tmc_spin_queued_mutex_init(&q->dequeue_mutex); 

    q->enqueue_count = q->dequeue_count = 0;

    return q;
}

/**
 * \brief TmqhTmcQueueRegister
 * \initonly
 */
void TmqhTmcQueueRegister (void) {
    tmqh_table[TMQH_RINGBUFFER_MRSW].name = "tmc_mrsw";
    tmqh_table[TMQH_RINGBUFFER_MRSW].InHandler = TmqhInputTmcQueueMrSw;
    tmqh_table[TMQH_RINGBUFFER_MRSW].InShutdownHandler = TmqhInputTmcQueueShutdownHandler;
    tmqh_table[TMQH_RINGBUFFER_MRSW].OutHandler = TmqhOutputTmcQueueMrSw;

    tmqh_table[TMQH_RINGBUFFER_SRSW].name = "tmc_srsw";
    tmqh_table[TMQH_RINGBUFFER_SRSW].InHandler = TmqhInputTmcQueueSrSw;
    tmqh_table[TMQH_RINGBUFFER_SRSW].InShutdownHandler = TmqhInputTmcQueueShutdownHandler;
    tmqh_table[TMQH_RINGBUFFER_SRSW].OutHandler = TmqhOutputTmcQueueSrSw;

    tmqh_table[TMQH_RINGBUFFER_SRMW].name = "tmc_srmw";
    tmqh_table[TMQH_RINGBUFFER_SRMW].InHandler = TmqhInputTmcQueueSrMw;
    tmqh_table[TMQH_RINGBUFFER_SRMW].InShutdownHandler = TmqhInputTmcQueueShutdownHandler;
    tmqh_table[TMQH_RINGBUFFER_SRMW].OutHandler = TmqhOutputTmcQueueSrMw;

    memset(tmcqueues, 0, sizeof(tmcqueues));

    int i;
    for (i = 0; i < 256; i++) {
        tmcqueues[i] = TmqhTmcQueueInit();
        if (tmcqueues[i] == NULL) {
            SCLogError(SC_ERR_FATAL, "Error allocating memory to register TmcQueue. Exiting...");
            exit(EXIT_FAILURE);
        }

    }
}

void TmqhInputTmcQueueShutdownHandler(ThreadVars *tv) {
    if (tv == NULL || tv->inq == NULL) {
        return;
    }

    TmcPacketQueue *q = tmcqueues[tv->inq->id];
    if (q == NULL) {
        return;
    }

    //RingBuffer8Shutdown(rb);
}

static void Enqueue (TmcPacketQueue *q, Packet *p) {
    //SCLogInfo("PacketEnqueue %d %d %p", q->enqueue_count, q->dequeue_count, p);
    while ((q->enqueue_count - atomic_access_once(q->dequeue_count)) >=
        (1 << LOG2_PACKETQ_ENTRIES)) {
        ;
    }
    unsigned int enqueue_count = q->enqueue_count;
    unsigned int i = enqueue_count & ((1 << LOG2_PACKETQ_ENTRIES) - 1);
    q->array[i] = p;
    __insn_mf();
    q->enqueue_count = enqueue_count + 1;
    //SCLogInfo("PacketEnqueue done %d %d", q->enqueue_count, q->dequeue_count);
}

static Packet *Dequeue (TmcPacketQueue *q) {
    Packet *p = NULL;
    //SCLogInfo("PacketDequeue %d %d", q->enqueue_count, q->dequeue_count);
    if (atomic_access_once(q->enqueue_count) == q->dequeue_count) {
        return p;
    } else {
      unsigned int dequeue_count = q->dequeue_count;
      unsigned int i = dequeue_count & ((1 << LOG2_PACKETQ_ENTRIES) - 1);
      p = q->array[i];
      __insn_mf(); /* Make sure loads are back. */
      q->dequeue_count = dequeue_count + 1;
    }
    //SCLogInfo("PacketDequeue %d %d %p", q->enqueue_count, q->dequeue_count, p);
    return p;
}


Packet *TmqhInputTmcQueueMrSw(ThreadVars *t)
{
    TmcPacketQueue *q = tmcqueues[t->inq->id];

    tmc_spin_queued_mutex_lock(&q->dequeue_mutex);
    Packet *p = (Packet *)Dequeue(q);
    tmc_spin_queued_mutex_unlock(&q->dequeue_mutex);

    SCPerfSyncCountersIfSignalled(t, 0);

    return p;
}

void TmqhOutputTmcQueueMrSw(ThreadVars *t, Packet *p)
{
    TmcPacketQueue *q = tmcqueues[t->outq->id];
    Enqueue(q, (void *)p);
}

Packet *TmqhInputTmcQueueSrSw(ThreadVars *t)
{
    TmcPacketQueue *q = tmcqueues[t->inq->id];

    Packet *p = (Packet *)Dequeue(q);

    SCPerfSyncCountersIfSignalled(t, 0);

    return p;
}

void TmqhOutputTmcQueueSrSw(ThreadVars *t, Packet *p)
{
    TmcPacketQueue *q = tmcqueues[t->outq->id];
    Enqueue(q, (void *)p);
}

Packet *TmqhInputTmcQueueSrMw(ThreadVars *t)
{
    TmcPacketQueue *q = tmcqueues[t->inq->id];

    Packet *p = (Packet *)Dequeue(q);

    SCPerfSyncCountersIfSignalled(t, 0);

    return p;
}

void TmqhOutputTmcQueueSrMw(ThreadVars *t, Packet *p)
{
    TmcPacketQueue *q = tmcqueues[t->outq->id];
    tmc_spin_queued_mutex_lock(&q->dequeue_mutex);
    Enqueue(q, (void *)p);
    tmc_spin_queued_mutex_unlock(&q->dequeue_mutex);
}
#endif
