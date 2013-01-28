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
 * Ringbuffer implementation that is lockless for the most part IF atomic
 * operations are available.
 *
 * Two sizes are implemented currently: 256 and 65536. Those sizes are chosen
 * for simplicity when working with the read and write indexes. Both can just
 * wrap around.
 *
 * Implemented are:
 * Single reader, single writer (lockless)
 * Single reader, multi writer (partly locked)
 * Multi reader, single writer (lockless)
 * Multi reader, multi writer (partly locked)
 */
#include "suricata-common.h"
#include "suricata.h"
#include "util-ringbuffer.h"
#include "util-atomic.h"
#include "util-unittest.h"

#ifdef __tile__
#include <arch/cycle.h>

static inline void
cycle_pause(unsigned int delay)
{
  const unsigned int start = get_cycle_count_low();
  while (get_cycle_count_low() - start < delay)
    ;
}
#endif

#define USLEEP_TIME 5

/** \brief wait function for condition where ringbuffer is either
 *         full or empty.
 *
 *  \param rb ringbuffer
 *
 *  Based on RINGBUFFER_MUTEX_WAIT define, we either sleep and spin
 *  or use thread condition to wait.
 */
static inline void RingBuffer8DoWait(RingBuffer8 *rb) {
#ifdef RINGBUFFER_MUTEX_WAIT
    SCMutexLock(&rb->wait_mutex);
    SCCondWait(&rb->wait_cond, &rb->wait_mutex);
    SCMutexUnlock(&rb->wait_mutex);
#else
#ifdef __tile__
    cycle_pause(50);
#else
    usleep(USLEEP_TIME);
#endif
#endif
}

/** \brief wait function for condition where ringbuffer is either
 *         full or empty.
 *
 *  \param rb ringbuffer
 *
 *  Based on RINGBUFFER_MUTEX_WAIT define, we either sleep and spin
 *  or use thread condition to wait.
 */
static inline void RingBufferDoWait(RingBuffer16 *rb) {
#ifdef RINGBUFFER_MUTEX_WAIT
    SCMutexLock(&rb->wait_mutex);
    SCCondWait(&rb->wait_cond, &rb->wait_mutex);
    SCMutexUnlock(&rb->wait_mutex);
#else
#ifdef __tile__
    cycle_pause(50);
#else
    usleep(USLEEP_TIME);
#endif
#endif
}

/** \brief wait function for condition where ringbuffer is either
 *         full or empty.
 *
 *  \param rb ringbuffer
 *
 *  Based on RINGBUFFER_MUTEX_WAIT define, we either sleep and spin
 *  or use thread condition to wait.
 */
void RingBufferWait(RingBuffer16 *rb) {
    RingBufferDoWait(rb);
}

/** \brief tell the ringbuffer to shut down
 *
 *  \param rb ringbuffer
 */
void RingBuffer8Shutdown(RingBuffer8 *rb) {
    rb->shutdown = 1;
#ifdef RINGBUFFER_MUTEX_WAIT
    SCCondSignal(&rb->wait_cond);
#endif
}

/** \brief check the ringbuffer is empty (no data in it)
 *
 *  \param rb ringbuffer
 *
 *  \retval 1 empty
 *  \retval 0 not empty
 */
int RingBuffer8IsEmpty(RingBuffer8 *rb) {
#ifdef __tile__
    tmc_spin_queued_mutex_lock(&rb->spin);
    if (rb->write == rb->read) {
        tmc_spin_queued_mutex_unlock(&rb->spin);
        return 1;
    }
    tmc_spin_queued_mutex_unlock(&rb->spin);
#else
    if (SC_ATOMIC_GET(rb->write) == SC_ATOMIC_GET(rb->read)) {
        return 1;
    }
#endif

    return 0;
}

/** \brief check the ringbuffer is full (no more data will fit)
 *
 *  \param rb ringbuffer
 *
 *  \retval 1 empty
 *  \retval 0 not empty
 */
int RingBuffer8IsFull(RingBuffer8 *rb) {
#ifdef __tile__
    tmc_spin_queued_mutex_lock(&rb->spin);
    if ((unsigned char)(rb->write + 1) == rb->read) {
        tmc_spin_queued_mutex_unlock(&rb->spin);
        return 1;
    }
    tmc_spin_queued_mutex_unlock(&rb->spin);
#else
    if ((unsigned char)(SC_ATOMIC_GET(rb->write) + 1) == SC_ATOMIC_GET(rb->read)) {
        return 1;
    }
#endif

    return 0;
}

/** \brief tell the ringbuffer to shut down
 *
 *  \param rb ringbuffer
 */
void RingBufferShutdown(RingBuffer16 *rb) {
    rb->shutdown = 1;
#ifdef RINGBUFFER_MUTEX_WAIT
    SCCondSignal(&rb->wait_cond);
#endif
}

/** \brief get number of items in the ringbuffer */
uint16_t RingBufferSize(RingBuffer16 *rb) {
    SCEnter();
#ifdef __tile__
    tmc_spin_queued_mutex_lock(&rb->spin);
    uint16_t size = (uint16_t)(rb->write - rb->read);
    tmc_spin_queued_mutex_unlock(&rb->spin);
#else
    uint16_t size = (uint16_t)(SC_ATOMIC_GET(rb->write) - SC_ATOMIC_GET(rb->read));
#endif
    SCReturnUInt(size);
}

/** \brief check the ringbuffer is empty (no data in it)
 *
 *  \param rb ringbuffer
 *
 *  \retval 1 empty
 *  \retval 0 not empty
 */
int RingBufferIsEmpty(RingBuffer16 *rb) {
#ifdef __tile__
    tmc_spin_queued_mutex_lock(&rb->spin);
    if (rb->write == rb->read) {
        tmc_spin_queued_mutex_unlock(&rb->spin);
        return 1;
    }
    tmc_spin_queued_mutex_unlock(&rb->spin);
#else
    if (SC_ATOMIC_GET(rb->write) == SC_ATOMIC_GET(rb->read)) {
        return 1;
    }
#endif

    return 0;
}

/** \brief check the ringbuffer is full (no more data will fit)
 *
 *  \param rb ringbuffer
 *
 *  \retval 1 empty
 *  \retval 0 not empty
 */
int RingBufferIsFull(RingBuffer16 *rb) {
#ifdef __tile__
    tmc_spin_queued_mutex_lock(&rb->spin);
    if ((unsigned short)(rb->write + 1) == rb->read) {
        tmc_spin_queued_mutex_unlock(&rb->spin);
        return 1;
    }
    tmc_spin_queued_mutex_unlock(&rb->spin);
#else
    if ((unsigned short)(SC_ATOMIC_GET(rb->write) + 1) == SC_ATOMIC_GET(rb->read)) {
        return 1;
    }
#endif

    return 0;
}

/* Single Reader, Single Writer, 8 bits */

void *RingBufferSrSw8Get(RingBuffer8 *rb) {
    void *ptr = NULL;

#ifdef __tile__
    for (;;) {
        tmc_spin_queued_mutex_lock(&rb->spin);
        if (rb->write == rb->read) {
#else
    /* buffer is empty, wait... */
         while (SC_ATOMIC_GET(rb->write) == SC_ATOMIC_GET(rb->read)) {
#endif
            /* break out if the engine wants to shutdown */
            if (rb->shutdown != 0) {
#ifdef __tile__
                tmc_spin_queued_mutex_unlock(&rb->spin);
#endif
                return NULL;
            }
#ifdef __tile__
            tmc_spin_queued_mutex_unlock(&rb->spin);
#endif

            RingBuffer8DoWait(rb);
        }
#ifdef __tile__
        else
            break;
    }
#endif

#ifdef __tile__
    ptr = rb->array[rb->read];
    rb->read += 1;
#else
    ptr = rb->array[SC_ATOMIC_GET(rb->read)];
    (void) SC_ATOMIC_ADD(rb->read, 1);
#endif
#ifdef __tile__
    tmc_spin_queued_mutex_unlock(&rb->spin);
#endif

#ifdef RINGBUFFER_MUTEX_WAIT
    SCCondSignal(&rb->wait_cond);
#endif
    return ptr;
}

int RingBufferSrSw8Put(RingBuffer8 *rb, void *ptr) {
    /* buffer is full, wait... */
#ifdef __tile__
    for (;;) {
        tmc_spin_queued_mutex_lock(&rb->spin);
        if ((unsigned char)(rb->write + 1) == rb->read) {
#else
        while ((unsigned char)(SC_ATOMIC_GET(rb->write) + 1) == SC_ATOMIC_GET(rb->read)) {
#endif
            /* break out if the engine wants to shutdown */
            if (rb->shutdown != 0) {
#ifdef __tile__
                tmc_spin_queued_mutex_unlock(&rb->spin);
#endif
                return -1;
            }
#ifdef __tile__
            tmc_spin_queued_mutex_unlock(&rb->spin);
#endif
            RingBuffer8DoWait(rb);
        }
#ifdef __tile__
        else
            break;
    }
#endif

#ifdef __tile__
    rb->array[rb->write] = ptr;
    rb->write += 1;
#else
    rb->array[SC_ATOMIC_GET(rb->write)] = ptr;
    (void) SC_ATOMIC_ADD(rb->write, 1);
#endif

#ifdef __tile__
    tmc_spin_queued_mutex_unlock(&rb->spin);
#endif

#ifdef RINGBUFFER_MUTEX_WAIT
    SCCondSignal(&rb->wait_cond);
#endif
    return 0;
}

/* Single Reader, Multi Writer, 8 bites */

void *RingBufferSrMw8Get(RingBuffer8 *rb) {
    void *ptr = NULL;

    /* buffer is empty, wait... */
#ifdef __tile__
    for (;;) {
        tmc_spin_queued_mutex_lock(&rb->spin);
        if (rb->write == rb->read) {
#else
        while (SC_ATOMIC_GET(rb->write) == SC_ATOMIC_GET(rb->read)) {
#endif
            /* break out if the engine wants to shutdown */
            if (rb->shutdown != 0) {
#ifdef __tile__
                 tmc_spin_queued_mutex_unlock(&rb->spin);
#endif
                return NULL;
            }
#ifdef __tile__
            tmc_spin_queued_mutex_unlock(&rb->spin);
#endif

            RingBuffer8DoWait(rb);
        }
#ifdef __tile__
        else
            break;
    }
#endif

#ifdef __tile__
    ptr = rb->array[rb->read];
    rb->read += 1;
#else
    ptr = rb->array[SC_ATOMIC_GET(rb->read)];
    (void) SC_ATOMIC_ADD(rb->read, 1);
#endif
#ifdef __tile__
    tmc_spin_queued_mutex_unlock(&rb->spin);
#endif

#ifdef RINGBUFFER_MUTEX_WAIT
    SCCondSignal(&rb->wait_cond);
#endif
    return ptr;
}

/**
 *  \brief put a ptr in the RingBuffer.
 *
 *  As we support multiple writers we need to protect 2 things:
 *   1. writing the ptr to the array
 *   2. incrementing the rb->write idx
 *
 *  We can't do both at the same time in one atomic operation, so
 *  we need to (spin) lock it. We do increment rb->write atomically
 *  after that, so that we don't need to use the lock in our *Get
 *  function.
 *
 *  \param rb the ringbuffer
 *  \param ptr ptr to store
 *
 *  \retval 0 ok
 *  \retval -1 wait loop interrupted because of engine flags
 */
int RingBufferSrMw8Put(RingBuffer8 *rb, void *ptr) {
    SCLogDebug("ptr %p", ptr);

    /* buffer is full, wait... */
retry:
#ifdef __tile__
    while ((unsigned char)(rb->write + 1) == rb->read) {
#else
    while ((unsigned char)(SC_ATOMIC_GET(rb->write) + 1) == SC_ATOMIC_GET(rb->read)) {
#endif
        /* break out if the engine wants to shutdown */
        if (rb->shutdown != 0)
            return -1;

        RingBuffer8DoWait(rb);
    }

    /* get our lock */
#ifdef __tile__
    tmc_spin_queued_mutex_lock(&rb->spin);
#else
    SCSpinLock(&rb->spin);
#endif
    /* if while we got our lock the buffer changed, we need to retry */
#ifdef __tile__
    if ((unsigned char)(rb->write + 1) == rb->read) {
#else
    if ((unsigned char)(SC_ATOMIC_GET(rb->write) + 1) == SC_ATOMIC_GET(rb->read)) {
#endif
#ifdef __tile__
        tmc_spin_queued_mutex_lock(&rb->spin);
#else
        SCSpinUnlock(&rb->spin);
#endif
        goto retry;
    }

    SCLogDebug("rb->write %u, ptr %p", SC_ATOMIC_GET(rb->write), ptr);

    /* update the ring buffer */
#ifdef __tile__
    rb->array[rb->write] = ptr;
    rb->write += 1;
#else
    rb->array[SC_ATOMIC_GET(rb->write)] = ptr;
    (void) SC_ATOMIC_ADD(rb->write, 1);
#endif
#ifdef __tile__
    tmc_spin_queued_mutex_unlock(&rb->spin);
#else
    SCSpinUnlock(&rb->spin);
#endif
    SCLogDebug("ptr %p, done", ptr);

#ifdef RINGBUFFER_MUTEX_WAIT
    SCCondSignal(&rb->wait_cond);
#endif
    return 0;
}

/* Multi Reader, Single Writer, 8 bits */

/**
 *  \brief get the next ptr from the ring buffer
 *
 *  Because we allow for multiple readers we take great care in making sure
 *  that the threads don't interfere with one another.
 *
 */
void *RingBufferMrSw8Get(RingBuffer8 *rb) {
    void *ptr;
    /** local pointer for data races. If SCAtomicCompareAndSwap (CAS)
     *  fails we increase our local array idx to try the next array member
     *  until we succeed. Or when the buffer is empty again we jump back
     *  to the waiting loop. */
    unsigned char readp;

    /* buffer is empty, wait... */
retry:
#ifdef __tile__
    for (;;) {
        tmc_spin_queued_mutex_lock(&rb->spin);
        if (rb->write == rb->read) {
#else
        while (SC_ATOMIC_GET(rb->write) == SC_ATOMIC_GET(rb->read)) {
#endif
            /* break out if the engine wants to shutdown */
            if (rb->shutdown != 0) {
#ifdef __tile__
                tmc_spin_queued_mutex_unlock(&rb->spin);
#endif
                return NULL;
            }
#ifdef __tile__
            tmc_spin_queued_mutex_unlock(&rb->spin);
#endif

            RingBuffer8DoWait(rb);
        }
#ifdef __tile__
        else
            break;
    }
#endif

    /* atomically update rb->read */
#ifdef __tile__
    readp = rb->read - 1;
#else
    readp = SC_ATOMIC_GET(rb->read) - 1;
#endif
    do {
        /* with multiple readers we can get in the situation that we exitted
         * from the wait loop but the rb is empty again once we get here. */
#ifdef __tile__
        if (rb->write == rb->read) {
            tmc_spin_queued_mutex_unlock(&rb->spin);
            goto retry;
        }
#else
        if (SC_ATOMIC_GET(rb->write) == SC_ATOMIC_GET(rb->read))
            goto retry;
#endif

        readp++;
        ptr = rb->array[readp];
#ifdef __tile__
    } while (0);
    rb->read = readp + 1;
    tmc_spin_queued_mutex_unlock(&rb->spin);
#else
    } while (!(SC_ATOMIC_CAS(&rb->read, readp, (readp + 1))));
#endif

    SCLogDebug("ptr %p", ptr);

#ifdef RINGBUFFER_MUTEX_WAIT
    SCCondSignal(&rb->wait_cond);
#endif
    return ptr;
}

/**
 *  \brief put a ptr in the RingBuffer
 */
int RingBufferMrSw8Put(RingBuffer8 *rb, void *ptr) {
    SCLogDebug("ptr %p", ptr);

    /* buffer is full, wait... */
#ifdef __tile__
    for (;;) {
        tmc_spin_queued_mutex_lock(&rb->spin);
        if ((unsigned char)(rb->write + 1) == rb->read) {

#else
        while ((unsigned char)(SC_ATOMIC_GET(rb->write) + 1) == SC_ATOMIC_GET(rb->read)) {
#endif
            /* break out if the engine wants to shutdown */
            if (rb->shutdown != 0) {
#ifdef __tile__
                tmc_spin_queued_mutex_unlock(&rb->spin);
#endif
                return -1;
            }
#ifdef __tile__
            tmc_spin_queued_mutex_unlock(&rb->spin);
#endif
            RingBuffer8DoWait(rb);
        }
#ifdef __tile__
        else
            break;
    }
#endif

#ifdef __tile__
    rb->array[rb->write] = ptr;
    rb->write += 1;
#else
    rb->array[SC_ATOMIC_GET(rb->write)] = ptr;
    (void) SC_ATOMIC_ADD(rb->write, 1);
#endif
#ifdef __tile__
    tmc_spin_queued_mutex_unlock(&rb->spin);
#endif

#ifdef RINGBUFFER_MUTEX_WAIT
    SCCondSignal(&rb->wait_cond);
#endif
    return 0;
}


/* Multi Reader, Single Writer */

/**
 *  \brief get the next ptr from the ring buffer
 *
 *  Because we allow for multiple readers we take great care in making sure
 *  that the threads don't interfere with one another.
 *
 */
void *RingBufferMrSwGet(RingBuffer16 *rb) {
    void *ptr;
    /** local pointer for data races. If SCAtomicCompareAndSwap (CAS)
     *  fails we increase our local array idx to try the next array member
     *  until we succeed. Or when the buffer is empty again we jump back
     *  to the waiting loop. */
    unsigned short readp;

    /* buffer is empty, wait... */
retry:
#ifdef __tile__
    for (;;) {
        tmc_spin_queued_mutex_lock(&rb->spin);
        if (rb->write == rb->read) {
#else
        while (SC_ATOMIC_GET(rb->write) == SC_ATOMIC_GET(rb->read)) {
#endif
            /* break out if the engine wants to shutdown */
            if (rb->shutdown != 0) {
#ifdef __tile__
                tmc_spin_queued_mutex_unlock(&rb->spin);
#endif
                return NULL;
            }
#ifdef __tile__
            tmc_spin_queued_mutex_unlock(&rb->spin);
#endif

            RingBufferDoWait(rb);
        }
#ifdef __tile__
        else
            break;
    }
#endif

    /* atomically update rb->read */
#ifdef __tile__
    readp = rb->read - 1;
#else
    readp = SC_ATOMIC_GET(rb->read) - 1;
#endif
    do {
        /* with multiple readers we can get in the situation that we exitted
         * from the wait loop but the rb is empty again once we get here. */
#ifdef __tile__
        if (rb->write == rb->read) {
            tmc_spin_queued_mutex_unlock(&rb->spin);
            goto retry;
        }
#else
        if (SC_ATOMIC_GET(rb->write) == SC_ATOMIC_GET(rb->read))
            goto retry;
#endif

        readp++;
        ptr = rb->array[readp];
#ifdef __tile__
    } while (0);
    rb->read = readp + 1;
    tmc_spin_queued_mutex_unlock(&rb->spin);
#else
    } while (!(SC_ATOMIC_CAS(&rb->read, readp, (readp + 1))));
#endif

    SCLogDebug("ptr %p", ptr);

#ifdef RINGBUFFER_MUTEX_WAIT
    SCCondSignal(&rb->wait_cond);
#endif
    return ptr;
}

/**
 *  \brief put a ptr in the RingBuffer
 */
int RingBufferMrSwPut(RingBuffer16 *rb, void *ptr) {
    SCLogDebug("ptr %p", ptr);

    /* buffer is full, wait... */
#ifdef __tile__
     for (;;) {
         tmc_spin_queued_mutex_lock(&rb->spin);
         if ((unsigned short)(rb->write + 1) == rb->read) {
#else
         while ((unsigned short)(SC_ATOMIC_GET(rb->write) + 1) == SC_ATOMIC_GET(rb->read)) {
#endif
            /* break out if the engine wants to shutdown */
            if (rb->shutdown != 0) {
#ifdef __tile__
                tmc_spin_queued_mutex_unlock(&rb->spin);
#endif
                return -1;
            }
#ifdef __tile__
            tmc_spin_queued_mutex_unlock(&rb->spin);
#endif
            RingBufferDoWait(rb);
        }
#ifdef __tile__
        else
            break;
    }
#endif

#ifdef __tile__
    rb->array[rb->write] = ptr;
    rb->write += 1;
#else
    rb->array[SC_ATOMIC_GET(rb->write)] = ptr;
    (void) SC_ATOMIC_ADD(rb->write, 1);
#endif

#ifdef __tile__
    tmc_spin_queued_mutex_unlock(&rb->spin);
#endif
#ifdef RINGBUFFER_MUTEX_WAIT
    SCCondSignal(&rb->wait_cond);
#endif
    return 0;
}


/* Single Reader, Single Writer */

void *RingBufferSrSwGet(RingBuffer16 *rb) {
    void *ptr = NULL;

    /* buffer is empty, wait... */
#ifdef __tile__
     for (;;) {
         tmc_spin_queued_mutex_lock(&rb->spin);
         if ((unsigned short)(rb->write + 1) == rb->read) {
#else
        while (SC_ATOMIC_GET(rb->write) == SC_ATOMIC_GET(rb->read)) {
#endif
            /* break out if the engine wants to shutdown */
            if (rb->shutdown != 0) {
#ifdef __tile__
                tmc_spin_queued_mutex_unlock(&rb->spin);
#endif
                return NULL;
            }
#ifdef __tile__
            tmc_spin_queued_mutex_unlock(&rb->spin);
#endif
            RingBufferDoWait(rb);
        }
#ifdef __tile__
        else
            break;
    }
#endif

#ifdef __tile__
    ptr = rb->array[rb->read];
    rb->read += 1;
#else
    ptr = rb->array[SC_ATOMIC_GET(rb->read)];
    (void) SC_ATOMIC_ADD(rb->read, 1);
#endif

#ifdef __tile__
    tmc_spin_queued_mutex_unlock(&rb->spin);
#endif

#ifdef RINGBUFFER_MUTEX_WAIT
    SCCondSignal(&rb->wait_cond);
#endif
    return ptr;
}

int RingBufferSrSwPut(RingBuffer16 *rb, void *ptr) {
    /* buffer is full, wait... */
#ifdef __tile__
    for (;;) {
        tmc_spin_queued_mutex_lock(&rb->spin);
        if (rb->write == rb->read) {
#else
        while ((unsigned short)(SC_ATOMIC_GET(rb->write) + 1) == SC_ATOMIC_GET(rb->read)) {
#endif
            /* break out if the engine wants to shutdown */
            if (rb->shutdown != 0) {
#ifdef __tile__
                tmc_spin_queued_mutex_unlock(&rb->spin);
#endif
                return -1;
            }
#ifdef __tile__
            tmc_spin_queued_mutex_unlock(&rb->spin);
#endif
            RingBufferDoWait(rb);
        }
#ifdef __tile__
        else
            break;
    }
#endif

#ifdef __tile__
    rb->array[rb->write] = ptr;
    rb->write += 1;
#else
    rb->array[SC_ATOMIC_GET(rb->write)] = ptr;
    (void) SC_ATOMIC_ADD(rb->write, 1);
#endif

#ifdef __tile__
    tmc_spin_queued_mutex_unlock(&rb->spin);
#endif
#ifdef RINGBUFFER_MUTEX_WAIT
    SCCondSignal(&rb->wait_cond);
#endif
    return 0;
}

/* Multi Reader, Multi Writer, 8 bits */

RingBuffer8 *RingBuffer8Init(void) {
    RingBuffer8 *rb = SCMalloc(sizeof(RingBuffer8));
    if (unlikely(rb == NULL)) {
        return NULL;
    }

    memset(rb, 0x00, sizeof(RingBuffer8));

#ifdef __tile__
    rb->write = 0;
    rb->read = 0;
#else
    SC_ATOMIC_INIT(rb->write);
    SC_ATOMIC_INIT(rb->read);
#endif

#ifdef __tile__
    tmc_spin_queued_mutex_init(&rb->spin);
#else
    SCSpinInit(&rb->spin, 0);
#endif
#ifdef RINGBUFFER_MUTEX_WAIT
    SCMutexInit(&rb->wait_mutex, NULL);
    SCCondInit(&rb->wait_cond, NULL);
#endif
    return rb;
}

void RingBuffer8Destroy(RingBuffer8 *rb) {
    if (rb != NULL) {
#ifndef __tile__
        SC_ATOMIC_DESTROY(rb->write);
        SC_ATOMIC_DESTROY(rb->read);

        SCSpinDestroy(&rb->spin);
#endif

#ifdef RINGBUFFER_MUTEX_WAIT
        SCMutexDestroy(&rb->wait_mutex);
        SCCondDestroy(&rb->wait_cond);
#endif
        SCFree(rb);
    }
}

/**
 *  \brief get the next ptr from the ring buffer
 *
 *  Because we allow for multiple readers we take great care in making sure
 *  that the threads don't interfere with one another.
 *
 */
void *RingBufferMrMw8Get(RingBuffer8 *rb) {
    void *ptr;
    /** local pointer for data races. If SCAtomicCompareAndSwap (CAS)
     *  fails we increase our local array idx to try the next array member
     *  until we succeed. Or when the buffer is empty again we jump back
     *  to the waiting loop. */
    unsigned char readp;

    /* buffer is empty, wait... */
retry:
#ifdef __tile__
    for (;;) {
        tmc_spin_queued_mutex_lock(&rb->spin);
        if (rb->write == rb->read) {
#else
        while (SC_ATOMIC_GET(rb->write) == SC_ATOMIC_GET(rb->read)) {
#endif
            /* break out if the engine wants to shutdown */
            if (rb->shutdown != 0) {
#ifdef __tile__
                tmc_spin_queued_mutex_unlock(&rb->spin);
#endif
                return NULL;
            }
#ifdef __tile__
            tmc_spin_queued_mutex_unlock(&rb->spin);
#endif
            RingBuffer8DoWait(rb);
        }
#ifdef __tile__
        else
            break;
    }
#endif

    /* atomically update rb->read */
#ifdef __tile__
    readp = rb->read - 1;
#else
    readp = SC_ATOMIC_GET(rb->read) - 1;
#endif
    do {
        /* with multiple readers we can get in the situation that we exitted
         * from the wait loop but the rb is empty again once we get here. */
#ifdef __tile__
        if (rb->write == rb->read) {
            tmc_spin_queued_mutex_unlock(&rb->spin);
            goto retry;
        }
#else
        if (SC_ATOMIC_GET(rb->write) == SC_ATOMIC_GET(rb->read))
            goto retry;
#endif

        readp++;
        ptr = rb->array[readp];
#ifdef __tile__
    } while (0);
    rb->read = readp + 1;
    tmc_spin_queued_mutex_unlock(&rb->spin);
#else
    } while (!(SC_ATOMIC_CAS(&rb->read, readp, (readp + 1))));
#endif

    SCLogDebug("ptr %p", ptr);
#ifdef RINGBUFFER_MUTEX_WAIT
    SCCondSignal(&rb->wait_cond);
#endif
    return ptr;
}

/**
 *  \brief put a ptr in the RingBuffer.
 *
 *  As we support multiple writers we need to protect 2 things:
 *   1. writing the ptr to the array
 *   2. incrementing the rb->write idx
 *
 *  We can't do both at the same time in one atomic operation, so
 *  we need to (spin) lock it. We do increment rb->write atomically
 *  after that, so that we don't need to use the lock in our *Get
 *  function.
 *
 *  \param rb the ringbuffer
 *  \param ptr ptr to store
 *
 *  \retval 0 ok
 *  \retval -1 wait loop interrupted because of engine flags
 */
int RingBufferMrMw8Put(RingBuffer8 *rb, void *ptr) {
    SCLogDebug("ptr %p", ptr);

    /* buffer is full, wait... */
retry:
#ifdef __tile__
    while ((unsigned char)(rb->write + 1) == rb->read) {
#else
    while ((unsigned char)(SC_ATOMIC_GET(rb->write) + 1) == SC_ATOMIC_GET(rb->read)) {
#endif
        /* break out if the engine wants to shutdown */
        if (rb->shutdown != 0)
            return -1;

        RingBuffer8DoWait(rb);
    }

    /* get our lock */
#ifdef __tile__
    tmc_spin_queued_mutex_lock(&rb->spin);
#else
    SCSpinLock(&rb->spin);
#endif
    /* if while we got our lock the buffer changed, we need to retry */
#ifdef __tile__
    if ((unsigned char)(rb->write + 1) == rb->read) {
#else
    if ((unsigned char)(SC_ATOMIC_GET(rb->write) + 1) == SC_ATOMIC_GET(rb->read)) {
#endif
#ifdef __tile__
        tmc_spin_queued_mutex_unlock(&rb->spin);
#else
        SCSpinUnlock(&rb->spin);
#endif
        goto retry;
    }

    SCLogDebug("rb->write %u, ptr %p", SC_ATOMIC_GET(rb->write), ptr);

    /* update the ring buffer */
#ifdef __tile__
    rb->array[rb->write] = ptr;
    rb->write += 1;
#else
    rb->array[SC_ATOMIC_GET(rb->write)] = ptr;
    (void) SC_ATOMIC_ADD(rb->write, 1);
#endif
#ifdef __tile__
    tmc_spin_queued_mutex_unlock(&rb->spin);
#else
    SCSpinUnlock(&rb->spin);
#endif
    SCLogDebug("ptr %p, done", ptr);

#ifdef RINGBUFFER_MUTEX_WAIT
    SCCondSignal(&rb->wait_cond);
#endif
    return 0;
}

/* Multi Reader, Multi Writer, 16 bits */

RingBuffer16 *RingBufferInit(void) {
    RingBuffer16 *rb = SCMalloc(sizeof(RingBuffer16));
    if (unlikely(rb == NULL)) {
        return NULL;
    }

    memset(rb, 0x00, sizeof(RingBuffer16));

#ifdef __tile__
    rb->write = 0;
    rb->read = 0;
#else
    SC_ATOMIC_INIT(rb->write);
    SC_ATOMIC_INIT(rb->read);
#endif

#ifdef __tile__
    tmc_spin_queued_mutex_init(&rb->spin);
#else
    SCSpinInit(&rb->spin, 0);
#endif
#ifdef RINGBUFFER_MUTEX_WAIT
    SCMutexInit(&rb->wait_mutex, NULL);
    SCCondInit(&rb->wait_cond, NULL);
#endif
    return rb;
}

void RingBufferDestroy(RingBuffer16 *rb) {
    if (rb != NULL) {
#ifndef __tile__
        SC_ATOMIC_DESTROY(rb->write);
        SC_ATOMIC_DESTROY(rb->read);

        SCSpinDestroy(&rb->spin);
#endif

#ifdef RINGBUFFER_MUTEX_WAIT
        SCMutexDestroy(&rb->wait_mutex);
        SCCondDestroy(&rb->wait_cond);
#endif

        SCFree(rb);
    }
}

/**
 *  \brief get the next ptr from the ring buffer
 *
 *  Because we allow for multiple readers we take great care in making sure
 *  that the threads don't interfere with one another.
 *
 */
void *RingBufferMrMwGet(RingBuffer16 *rb) {
    void *ptr;
    /** local pointer for data races. If SCAtomicCompareAndSwap (CAS)
     *  fails we increase our local array idx to try the next array member
     *  until we succeed. Or when the buffer is empty again we jump back
     *  to the waiting loop. */
    unsigned short readp;

    /* buffer is empty, wait... */
retry:
#ifdef __tile__
    for (;;) {
        tmc_spin_queued_mutex_lock(&rb->spin);
        if (rb->write == rb->read) {
#else
        while (SC_ATOMIC_GET(rb->write) == SC_ATOMIC_GET(rb->read)) {
#endif
            /* break out if the engine wants to shutdown */
            if (rb->shutdown != 0) {
#ifdef __tile__
                tmc_spin_queued_mutex_unlock(&rb->spin);
#endif
                return NULL;
            }
#ifdef __tile__
            tmc_spin_queued_mutex_unlock(&rb->spin);
#endif
            RingBufferDoWait(rb);
        }
#ifdef __tile__
        else
            break;
    }
#endif

    /* atomically update rb->read */
#ifdef __tile__
    readp = rb->read - 1;
#else
    readp = SC_ATOMIC_GET(rb->read) - 1;
#endif
    do {
        /* with multiple readers we can get in the situation that we exitted
         * from the wait loop but the rb is empty again once we get here. */
#ifdef __tile__
        if (rb->write == rb->read) {
            tmc_spin_queued_mutex_unlock(&rb->spin);
            goto retry;
        }
#else
        if (SC_ATOMIC_GET(rb->write) == SC_ATOMIC_GET(rb->read))
            goto retry;
#endif

        readp++;
        ptr = rb->array[readp];
#ifdef __tile__
    } while (0);
    rb->read = readp + 1;
    tmc_spin_queued_mutex_unlock(&rb->spin);
#else
    } while (!(SC_ATOMIC_CAS(&rb->read, readp, (readp + 1))));
#endif

    SCLogDebug("ptr %p", ptr);

#ifdef RINGBUFFER_MUTEX_WAIT
    SCCondSignal(&rb->wait_cond);
#endif
    return ptr;
}

/**
 *  \brief get the next ptr from the ring buffer
 *
 *  Because we allow for multiple readers we take great care in making sure
 *  that the threads don't interfere with one another.
 *
 *  This version does NOT enter a wait if the buffer is empty loop.
 *
 *  \retval ptr pointer to the data, or NULL if buffer is empty
 */
void *RingBufferMrMwGetNoWait(RingBuffer16 *rb) {
    void *ptr;
    /** local pointer for data races. If SCAtomicCompareAndSwap (CAS)
     *  fails we increase our local array idx to try the next array member
     *  until we succeed. Or when the buffer is empty again we jump back
     *  to the waiting loop. */
    unsigned short readp;

    /* buffer is empty, wait... */
retry:
#ifdef __tile__
    tmc_spin_queued_mutex_lock(&rb->spin);
    if (rb->write == rb->read) {
        tmc_spin_queued_mutex_unlock(&rb->spin);
#else
    while (SC_ATOMIC_GET(rb->write) == SC_ATOMIC_GET(rb->read)) {
#endif
        /* break if buffer is empty */
        return NULL;
    }

    /* atomically update rb->read */
#ifdef __tile__
    readp = rb->read - 1;
#else
    readp = SC_ATOMIC_GET(rb->read) - 1;
#endif
    do {
        /* with multiple readers we can get in the situation that we exitted
         * from the wait loop but the rb is empty again once we get here. */
#ifdef __tile__
        if (rb->write == rb->read) {
            tmc_spin_queued_mutex_unlock(&rb->spin);
            goto retry;
        }
#else
        if (SC_ATOMIC_GET(rb->write) == SC_ATOMIC_GET(rb->read))
            goto retry;
#endif

        readp++;
        ptr = rb->array[readp];
#ifdef __tile__
    } while (0);
    rb->read = readp + 1;
    tmc_spin_queued_mutex_unlock(&rb->spin);
#else
    } while (!(SC_ATOMIC_CAS(&rb->read, readp, (readp + 1))));
#endif

    SCLogDebug("ptr %p", ptr);

#ifdef RINGBUFFER_MUTEX_WAIT
    SCCondSignal(&rb->wait_cond);
#endif
    return ptr;
}

/**
 *  \brief put a ptr in the RingBuffer.
 *
 *  As we support multiple writers we need to protect 2 things:
 *   1. writing the ptr to the array
 *   2. incrementing the rb->write idx
 *
 *  We can't do both at the same time in one atomic operation, so
 *  we need to (spin) lock it. We do increment rb->write atomically
 *  after that, so that we don't need to use the lock in our *Get
 *  function.
 *
 *  \param rb the ringbuffer
 *  \param ptr ptr to store
 *
 *  \retval 0 ok
 *  \retval -1 wait loop interrupted because of engine flags
 */
int RingBufferMrMwPut(RingBuffer16 *rb, void *ptr) {
    SCLogDebug("ptr %p", ptr);

    /* buffer is full, wait... */
retry:
#ifdef __tile__
    while ((unsigned short)(rb->write + 1) == rb->read) {
#else
    while ((unsigned short)(SC_ATOMIC_GET(rb->write) + 1) == SC_ATOMIC_GET(rb->read)) {
#endif
        /* break out if the engine wants to shutdown */
        if (rb->shutdown != 0)
            return -1;

        RingBufferDoWait(rb);
    }

    /* get our lock */
#ifdef __tile__
    tmc_spin_queued_mutex_lock(&rb->spin);
#else
    SCSpinLock(&rb->spin);
#endif
    /* if while we got our lock the buffer changed, we need to retry */
#ifdef __tile__
    if ((unsigned short)(rb->write + 1) == rb->read) {
#else
    if ((unsigned short)(SC_ATOMIC_GET(rb->write) + 1) == SC_ATOMIC_GET(rb->read)) {
#endif
#ifdef __tile__
        tmc_spin_queued_mutex_unlock(&rb->spin);
#else
        SCSpinUnlock(&rb->spin);
#endif
        goto retry;
    }

    SCLogDebug("rb->write %u, ptr %p", SC_ATOMIC_GET(rb->write), ptr);

    /* update the ring buffer */
#ifdef __tile__
    rb->array[rb->write] = ptr;
    rb->write += 1;
#else
    rb->array[SC_ATOMIC_GET(rb->write)] = ptr;
    (void) SC_ATOMIC_ADD(rb->write, 1);
#endif
#ifdef __tile__
    tmc_spin_queued_mutex_unlock(&rb->spin);
#else
    SCSpinUnlock(&rb->spin);
#endif

    SCLogDebug("ptr %p, done", ptr);

#ifdef RINGBUFFER_MUTEX_WAIT
    SCCondSignal(&rb->wait_cond);
#endif
    return 0;
}
#ifdef __tilegx__
/* 
 * Remove this temporarily on Tilera
 */
#undef UNITTESTS
#endif

#ifdef UNITTESTS
static int RingBuffer8SrSwInit01 (void) {
    int result = 0;

    RingBuffer8 *rb = NULL;

    rb = RingBuffer8Init();
    if (rb == NULL) {
        printf("rb == NULL: ");
        goto end;
    }

    int r = SCSpinLock(&rb->spin);
    if (r != 0) {
        printf("r = %d, expected %d: ", r, 0);
        goto end;
    }
    SCSpinUnlock(&rb->spin);

    if (SC_ATOMIC_GET(rb->read) != 0) {
        printf("read %u, expected 0: ", SC_ATOMIC_GET(rb->read));
        goto end;
    }

    if (SC_ATOMIC_GET(rb->write) != 0) {
        printf("write %u, expected 0: ", SC_ATOMIC_GET(rb->write));
        goto end;
    }

    result = 1;
end:
    if (rb != NULL) {
        RingBuffer8Destroy(rb);
    }
    return result;
}

static int RingBuffer8SrSwPut01 (void) {
    int result = 0;

    RingBuffer8 *rb = NULL;

    rb = RingBuffer8Init();
    if (rb == NULL) {
        printf("rb == NULL: ");
        goto end;
    }

    if (SC_ATOMIC_GET(rb->read) != 0) {
        printf("read %u, expected 0: ", SC_ATOMIC_GET(rb->read));
        goto end;
    }

    if (SC_ATOMIC_GET(rb->write) != 0) {
        printf("write %u, expected 0: ", SC_ATOMIC_GET(rb->write));
        goto end;
    }

    void *ptr = &result;

    RingBufferSrSw8Put(rb, ptr);

    if (SC_ATOMIC_GET(rb->read) != 0) {
        printf("read %u, expected 0: ", SC_ATOMIC_GET(rb->read));
        goto end;
    }

    if (SC_ATOMIC_GET(rb->write) != 1) {
        printf("write %u, expected 1: ", SC_ATOMIC_GET(rb->write));
        goto end;
    }

    if (rb->array[0] != ptr) {
        printf("ptr is %p, expected %p: ", rb->array[0], ptr);
        goto end;
    }

    result = 1;
end:
    if (rb != NULL) {
        RingBuffer8Destroy(rb);
    }
    return result;
}

static int RingBuffer8SrSwPut02 (void) {
    int result = 0;
    RingBuffer8 *rb = NULL;

    int array[255];
    int cnt = 0;
    for (cnt = 0; cnt < 255; cnt++) {
        array[cnt] = cnt;
    }

    rb = RingBuffer8Init();
    if (rb == NULL) {
        printf("rb == NULL: ");
        goto end;
    }

    for (cnt = 0; cnt < 255; cnt++) {
        RingBufferSrSw8Put(rb, (void *)&array[cnt]);

        if (SC_ATOMIC_GET(rb->read) != 0) {
            printf("read %u, expected 0: ", SC_ATOMIC_GET(rb->read));
            goto end;
        }

        if (SC_ATOMIC_GET(rb->write) != (unsigned char)(cnt+1)) {
            printf("write %u, expected %u: ", SC_ATOMIC_GET(rb->write), (unsigned char)(cnt+1));
            goto end;
        }

        if (rb->array[cnt] != (void *)&array[cnt]) {
            printf("ptr is %p, expected %p: ", rb->array[cnt], (void *)&array[cnt]);
            goto end;
        }
    }

    if (!(RingBuffer8IsFull(rb))) {
        printf("ringbuffer should be full, isn't: ");
        goto end;
    }

    result = 1;
end:
    if (rb != NULL) {
        RingBuffer8Destroy(rb);
    }
    return result;
}

static int RingBuffer8SrSwGet01 (void) {
    int result = 0;

    RingBuffer8 *rb = NULL;

    rb = RingBuffer8Init();
    if (rb == NULL) {
        printf("rb == NULL: ");
        goto end;
    }

    void *ptr = &result;

    RingBufferSrSw8Put(rb, ptr);
    void *ptr2 = RingBufferSrSw8Get(rb);

    if (ptr != ptr2) {
        printf("ptr %p != ptr2 %p: ", ptr, ptr2);
        goto end;
    }

    if (SC_ATOMIC_GET(rb->read) != 1) {
        printf("read %u, expected 1: ", SC_ATOMIC_GET(rb->read));
        goto end;
    }

    if (SC_ATOMIC_GET(rb->write) != 1) {
        printf("write %u, expected 1: ", SC_ATOMIC_GET(rb->write));
        goto end;
    }

    result = 1;
end:
    if (rb != NULL) {
        RingBuffer8Destroy(rb);
    }
    return result;
}

static int RingBuffer8SrSwGet02 (void) {
    int result = 0;
    RingBuffer8 *rb = NULL;

    int array[255];
    int cnt = 0;
    for (cnt = 0; cnt < 255; cnt++) {
        array[cnt] = cnt;
    }

    rb = RingBuffer8Init();
    if (rb == NULL) {
        printf("rb == NULL: ");
        goto end;
    }

    for (cnt = 0; cnt < 255; cnt++) {
        RingBufferSrSw8Put(rb, (void *)&array[cnt]);

        if (SC_ATOMIC_GET(rb->read) != 0) {
            printf("read %u, expected 0: ", SC_ATOMIC_GET(rb->read));
            goto end;
        }

        if (SC_ATOMIC_GET(rb->write) != (unsigned char)(cnt+1)) {
            printf("write %u, expected %u: ", SC_ATOMIC_GET(rb->write), (unsigned char)(cnt+1));
            goto end;
        }

        if (rb->array[cnt] != (void *)&array[cnt]) {
            printf("ptr is %p, expected %p: ", rb->array[cnt], (void *)&array[cnt]);
            goto end;
        }
    }

    if (!(RingBuffer8IsFull(rb))) {
        printf("ringbuffer should be full, isn't: ");
        goto end;
    }

    for (cnt = 0; cnt < 255; cnt++) {
        void *ptr = RingBufferSrSw8Get(rb);

        if (SC_ATOMIC_GET(rb->read) != (unsigned char)(cnt+1)) {
            printf("read %u, expected %u: ", SC_ATOMIC_GET(rb->read), (unsigned char)(cnt+1));
            goto end;
        }

        if (SC_ATOMIC_GET(rb->write) != 255) {
            printf("write %u, expected %u: ", SC_ATOMIC_GET(rb->write), 255);
            goto end;
        }

        if (ptr != (void *)&array[cnt]) {
            printf("ptr is %p, expected %p: ", ptr, (void *)&array[cnt]);
            goto end;
        }
    }

    if (!(RingBuffer8IsEmpty(rb))) {
        printf("ringbuffer should be empty, isn't: ");
        goto end;
    }

    result = 1;
end:
    if (rb != NULL) {
        RingBuffer8Destroy(rb);
    }
    return result;
}

#endif /* UNITTESTS */

void DetectRingBufferRegisterTests(void) {
#ifdef UNITTESTS /* UNITTESTS */
    UtRegisterTest("RingBuffer8SrSwInit01", RingBuffer8SrSwInit01, 1);
    UtRegisterTest("RingBuffer8SrSwPut01", RingBuffer8SrSwPut01, 1);
    UtRegisterTest("RingBuffer8SrSwPut02", RingBuffer8SrSwPut02, 1);
    UtRegisterTest("RingBuffer8SrSwGet01", RingBuffer8SrSwGet01, 1);
    UtRegisterTest("RingBuffer8SrSwGet02", RingBuffer8SrSwGet02, 1);
#endif /* UNITTESTS */
}

