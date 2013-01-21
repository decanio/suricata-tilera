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
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 * Utility Macros for memory management
 *
 * \todo Add wrappers for functions that allocate/free memory here.
 * Currently we have malloc, calloc, realloc, strdup and free,
 * but there are more.
 */

#ifndef __UTIL_MEM_H__
#define __UTIL_MEM_H__

#include "util-atomic.h"

#ifdef __tile__
#include <pcre.h>
#include <sys/mman.h>
#include <tmc/alloc.h>
#include <tmc/mspace.h>
#endif

#if defined(_WIN32) || defined(__WIN32)
#include "mm_malloc.h"
#endif

SC_ATOMIC_EXTERN(unsigned int, engine_stage);

/* Use this only if you want to debug memory allocation and free()
 * It will log a lot of lines more, so think that is a performance killer */

/* Uncomment this if you want to print memory allocations and free's() */
//#define DBG_MEM_ALLOC

#ifdef DBG_MEM_ALLOC

/* Uncomment this if you want to print mallocs at the startup (recommended) */
#define DBG_MEM_ALLOC_SKIP_STARTUP

#define SCMalloc(a) ({ \
    void *ptrmem = NULL; \
    extern size_t global_mem; \
    extern uint8_t print_mem_flag; \
    \
    ptrmem = malloc((a)); \
    if (ptrmem == NULL && (a) > 0) { \
        SCLogError(SC_ERR_MEM_ALLOC, "SCMalloc failed: %s, while trying " \
            "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)(a)); \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    \
    global_mem += (a); \
    if (print_mem_flag == 1) {                               \
        SCLogInfo("SCMalloc return at %p of size %"PRIuMAX, \
            ptrmem, (uintmax_t)(a)); \
    }                                \
    (void*)ptrmem; \
})

#define SCMpmMalloc(tv a) SCMalloc(a)

#define SCThreadMalloc(tv a) SCMalloc(a)

#define SCRealloc(x, a) ({ \
    void *ptrmem = NULL; \
    extern size_t global_mem; \
    extern uint8_t print_mem_flag; \
    \
    ptrmem = realloc((x), (a)); \
    if (ptrmem == NULL && (a) > 0) { \
        SCLogError(SC_ERR_MEM_ALLOC, "SCRealloc failed: %s, while trying " \
            "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)(a)); \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    \
    global_mem += (a); \
    if (print_mem_flag == 1) {                                         \
        SCLogInfo("SCRealloc return at %p (old:%p) of size %"PRIuMAX, \
            ptrmem, (x), (uintmax_t)(a)); \
    }                                     \
    (void*)ptrmem; \
})

#define SCCalloc(nm, a) ({ \
    void *ptrmem = NULL; \
    extern size_t global_mem; \
    extern uint8_t print_mem_flag; \
    \
    ptrmem = calloc((nm), (a)); \
    if (ptrmem == NULL && (a) > 0) { \
        SCLogError(SC_ERR_MEM_ALLOC, "SCCalloc failed: %s, while trying " \
            "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)a); \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    \
    global_mem += (a)*(nm); \
    if (print_mem_flag == 1) {                                          \
        SCLogInfo("SCCalloc return at %p of size %"PRIuMAX" (nm) %"PRIuMAX, \
            ptrmem, (uintmax_t)(a), (uintmax_t)(nm)); \
    }                                                 \
    (void*)ptrmem; \
})

#define SCStrdup(a) ({ \
    char *ptrmem = NULL; \
    extern size_t global_mem; \
    extern uint8_t print_mem_flag; \
    size_t len = strlen((a)); \
    \
    ptrmem = strdup((a)); \
    if (ptrmem == NULL) { \
        SCLogError(SC_ERR_MEM_ALLOC, "SCStrdup failed: %s, while trying " \
            "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)len); \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    \
    global_mem += len; \
    if (print_mem_flag == 1) {                              \
        SCLogInfo("SCStrdup return at %p of size %"PRIuMAX, \
            ptrmem, (uintmax_t)len); \
    }                                \
    (void*)ptrmem; \
})

#define SCFree(a) ({ \
    extern uint8_t print_mem_flag; \
    if (print_mem_flag == 1) {          \
        SCLogInfo("SCFree at %p", (a)); \
    }                                   \
    free((a)); \
})

#else /* !DBG_MEM_ALLOC */

#ifndef __tile__

#define SCMallocInit()

#define SCMalloc(a) ({ \
    void *ptrmem = NULL; \
    \
    ptrmem = malloc((a)); \
    if (ptrmem == NULL) { \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            uintmax_t scmalloc_size_ = (uintmax_t)(a); \
            SCLogError(SC_ERR_MEM_ALLOC, "SCMalloc failed: %s, while trying " \
                "to allocate %"PRIuMAX" bytes", strerror(errno), scmalloc_size_); \
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    (void*)ptrmem; \
})

#define SCMpmMalloc(a) SCMalloc(a)

#define SCThreadMalloc(tv, a) SCMalloc(a)

#define SCRealloc(x, a) ({ \
    void *ptrmem = NULL; \
    \
    ptrmem = realloc((x), (a)); \
    if (ptrmem == NULL) { \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_MEM_ALLOC, "SCRealloc failed: %s, while trying " \
                "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)(a)); \
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    (void*)ptrmem; \
})

#define SCCalloc(nm, a) ({ \
    void *ptrmem = NULL; \
    \
    ptrmem = calloc((nm), (a)); \
    if (ptrmem == NULL) { \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_MEM_ALLOC, "SCCalloc failed: %s, while trying " \
                "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)(a)); \
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    (void*)ptrmem; \
})

#define SCStrdup(a) ({ \
    char *ptrmem = NULL; \
    \
    ptrmem = strdup((a)); \
    if (ptrmem == NULL) { \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            size_t len = strlen((a)); \
            SCLogError(SC_ERR_MEM_ALLOC, "SCStrdup failed: %s, while trying " \
                "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)len); \
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    (void*)ptrmem; \
})

#define SCFree(a) ({ \
    free(a); \
})

#if defined(__WIN32) || defined(_WIN32)

/** \brief wrapper for allocing aligned mem
 *  \param a size
 *  \param b alignement
 */
#define SCMallocAligned(a, b) ({ \
    void *ptrmem = NULL; \
    \
	ptrmem = _mm_malloc((a), (b)); \
    if (ptrmem == NULL) { \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_MEM_ALLOC, "SCMallocAligned(posix_memalign) failed: %s, while trying " \
                "to allocate %"PRIuMAX" bytes, alignment %"PRIuMAX, strerror(errno), (uintmax_t)(a), (uintmax_t)(b)); \
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    (void*)ptrmem; \
})

/** \brief Free aligned memory
 *
 * Not needed for mem alloc'd by posix_memalign,
 * but for possible future use of _mm_malloc needing
 * _mm_free.
 */
#define SCFreeAligned(a) ({ \
    _mm_free(a); \
})

#else /* !win */

/** \brief wrapper for allocing aligned mem
 *  \param a size
 *  \param b alignement
 */
#define SCMallocAligned(a, b) ({ \
    void *ptrmem = NULL; \
    \
    ptrmem = _mm_malloc((a), (b)); \
    if (ptrmem == NULL) { \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_MEM_ALLOC, "SCMallocAligned(posix_memalign) failed: %s, while trying " \
                "to allocate %"PRIuMAX" bytes, alignment %"PRIuMAX, strerror(errno), (uintmax_t)a, (uintmax_t)b); \
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    (void*)ptrmem; \
})

/** \brief Free aligned memory
 *
 * Not needed for mem alloc'd by posix_memalign,
 * but for possible future use of _mm_malloc needing
 * _mm_free.
 */
#define SCFreeAligned(a) ({ \
    _mm_free((a)); \
})

#endif /* __WIN32 */

#else /* __tile__ */

/*
 * Tilera specific code to utilize a separate mspace for menaging memory
 * using huge pages and hash-for-home caching
 */
extern tmc_mspace global_mspace;
extern tmc_mspace mpm_mspace;

#if 0
    int pagesize = tmc_alloc_get_pagesize(&attr); \
    char *p, *p1; \
    p = tmc_mspace_malloc(global_mspace, global_capacity/2); \
    printf("SCMallocInit malloc %p\n", p); \
    for (p1 = p; p1 <= p + global_capacity-4096; \
         p1 += pagesize) { \
        *p1 = 0; \
    } \
    printf("SCMallocInit free %p\n", p); \
    tmc_mspace_free(p); \

#endif

#define SCMallocInit() ({ \
    extern void *tile_pcre_malloc(size_t size); \
    extern void tile_pcre_free(void *ptr); \
    extern void *tile_packet_page; \
    /*size_t global_capacity = 8ULL*1024ULL*1024ULL*1024ULL;*/ \
    size_t global_capacity = 4ULL*1024ULL*1024ULL*1024ULL; \
    unsigned long pagesizes = tmc_alloc_get_pagesizes(); \
    char log[64]; char str[8]; \
    log[0] = '\0'; \
    for (int i = 0; i < sizeof(pagesizes)*8; i++) { \
        unsigned long size = 1UL<<i; \
        if (pagesizes & size) { \
            if (size >= 1024UL*1024UL*1024UL) { \
                sprintf(str, "%luGB ", size / (1024UL*1024UL*1024UL)); \
            } else if (size >= 1024UL*1024UL) { \
                sprintf(str, "%luMB ", size / (1024UL*1024UL)); \
            } else { \
                sprintf(str, "%luKB ", size / 1024UL);  \
            } \
            strcat(log, str); \
            tile_vhuge_size = (size_t)size; \
        } \
    } \
    /*printf("Tilera Huge Page Sizes %s\n", log);*/ \
    for (int i = 0; i < sizeof(tile_vhuge_size)*8; i++) { \
        unsigned long size = 1UL<<i; \
        if (tile_vhuge_size & size) { \
            if (size >= 1024UL*1024UL*1024UL) { \
                sprintf(log, "%luGB", size / (1024UL*1024UL*1024UL)); \
            } else if (size >= 1024UL*1024UL) { \
                sprintf(log, "%luMB", size / (1024UL*1024UL)); \
            } else { \
                sprintf(log, "%luKB", size / 1024UL); \
            } \
            break; \
        } \
    } \
    /* Allocate one very huge page to hold our buffer stack, notif ring, and \
     * packets.  This should be more than enough space. */ \
    tmc_alloc_t alloc = TMC_ALLOC_INIT; \
    tmc_alloc_set_huge(&alloc); \
    tmc_alloc_set_home(&alloc, TMC_ALLOC_HOME_HASH); \
    if (tmc_alloc_set_pagesize_exact(&alloc, tile_vhuge_size) == NULL) { \
        SCLogInfo("Could not allocate packet buffers from very huge page."); \
        tmc_alloc_set_pagesize(&alloc, tile_vhuge_size); \
    } \
    tile_packet_page = tmc_alloc_map(&alloc, tile_vhuge_size); \
    /*printf("Tilera Very Huge Page Size %s\n", log);*/ \
    tmc_alloc_t attr = TMC_ALLOC_INIT; \
    tmc_alloc_set_huge(&attr); \
    tmc_alloc_set_home(&attr, TMC_ALLOC_HOME_HASH); \
    /*printf("SCMallocInit %ld\n", global_capacity);*/ \
    global_mspace = \
        tmc_mspace_create_special(global_capacity, \
                                  TMC_MSPACE_LOCKED|TMC_MSPACE_NOGROW, \
                                  &attr); \
    /*printf("SCMallocInit mspace %p\n", global_mspace);*/ \
    if (global_mspace == NULL) { \
        SCLogError(SC_ERR_MEM_ALLOC, \
                   "Failed to create global mspace"); \
        exit(EXIT_FAILURE); \
    } \
    tmc_alloc_t mpm_attr = TMC_ALLOC_INIT; \
    tmc_alloc_set_huge(&mpm_attr); \
    tmc_alloc_set_home(&mpm_attr, TMC_ALLOC_HOME_HASH); \
    /*tmc_alloc_set_caching(&mpm_attr, MAP_CACHE_NO_L2);*/ \
    mpm_mspace = tmc_mspace_create_special(32ULL*1024ULL*1024ULL, \
                                           0, &mpm_attr); \
    if (mpm_mspace == NULL) { \
        SCLogError(SC_ERR_MEM_ALLOC, \
                   "Failed to create mpm mspace"); \
        exit(EXIT_FAILURE); \
    } \
    /* override the pcre memory allocator to use tmc functions */ \
    pcre_malloc = tile_pcre_malloc; \
    pcre_free = tile_pcre_free; \
})

#define SCMalloc(a) ({ \
    void *ptrmem = NULL; \
    \
    ptrmem = tmc_mspace_malloc(global_mspace, (a)); \
    if (ptrmem == NULL) { \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_MEM_ALLOC, "SCMalloc failed: %s, while trying " \
                "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)(a)); \
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    (void*)ptrmem; \
})

#define SCMpmMalloc(a) ({ \
    void *ptrmem = NULL; \
    \
    ptrmem = tmc_mspace_malloc(mpm_mspace, (a)); \
    if (ptrmem == NULL) { \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_MEM_ALLOC, "SCMalloc failed: %s, while trying " \
                "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)(a)); \
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    (void*)ptrmem; \
})

#define SCThreadMalloc(tv, a) ({ \
    void *ptrmem = NULL; \
    \
    if (tv==NULL) { \
        ptrmem = SCMalloc(a); \
    } else { \
    ptrmem = tmc_mspace_malloc(tv->mspace, (a)); \
    if (ptrmem == NULL) { \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_MEM_ALLOC, "SCMalloc failed: %s, while trying " \
                "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)(a)); \
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    } \
    (void*)ptrmem; \
})

#define SCRealloc(x, a) ({ \
    void *ptrmem = NULL; \
    \
    ptrmem = tmc_mspace_realloc(global_mspace, (x), (a)); \
    if (ptrmem == NULL) { \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_MEM_ALLOC, "SCRealloc failed: %s, while trying " \
                "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)(a)); \
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    (void*)ptrmem; \
})

#define SCMpmRealloc(x, a) ({ \
    void *ptrmem = NULL; \
    \
    ptrmem = tmc_mspace_realloc(mpm_mspace, (x), (a)); \
    if (ptrmem == NULL) { \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_MEM_ALLOC, "SCRealloc failed: %s, while trying " \
                "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)(a)); \
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    (void*)ptrmem; \
})

#define SCCalloc(nm, a) ({ \
    void *ptrmem = NULL; \
    \
    ptrmem = tmc_mspace_calloc(global_mspace, (nm), (a)); \
    if (ptrmem == NULL) { \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_MEM_ALLOC, "SCCalloc failed: %s, while trying " \
                "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)(a)); \
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    (void*)ptrmem; \
})

#define SCStrdup(a) ({ \
    char *ptrmem = NULL; \
    \
    /* ptrmem = strdup((a)); */ \
    ptrmem = SCMalloc(strlen((a))+1); \
    if (ptrmem == NULL) { \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            size_t len = strlen((a)); \
            SCLogError(SC_ERR_MEM_ALLOC, "SCStrdup failed: %s, while trying " \
                "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)len); \
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    strcpy(ptrmem, (a)); \
    (void*)ptrmem; \
})

/** \brief wrapper for allocing aligned mem
 *  \param a size
 *  \param b alignement
 */
#define SCMallocAligned(a, b) ({ \
    void *ptrmem = NULL; \
    \
    if (ptrmem = tmc_mspace_memalign(global_mspace, (b), (a)) != 0) { \
        if (SC_ATOMIC_GET(engine_stage) == SURICATA_INIT) {\
            SCLogError(SC_ERR_MEM_ALLOC, "SCMallocAligned(posix_memalign) failed: %s, while trying " \
                "to allocate %"PRIuMAX" bytes, alignment %"PRIuMAX, strerror(errno), (uintmax_t)(a), (uintmax_t)(b)); \
            SCLogError(SC_ERR_FATAL, "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    (void*)ptrmem; \
})

#define SCFree(a) ({ \
    tmc_mspace_free((a)); \
})

/** \brief Free aligned memory
 *
 * Not needed for mem alloc'd by posix_memalign,
 * but for possible future use of _mm_malloc needing
 * _mm_free.
 */
#define SCFreeAligned(a) ({ \
    tmc_mspace_free((a)); \
})

#define SCFreeze() ({ \
})

#define SCMpmFreeze() ({ \
    tmc_mspace_freeze((mpm_mspace)); \
})

#endif /* __tile__ */

#endif /* DBG_MEM_ALLOC */

#endif /* __UTIL_MEM_H__ */

