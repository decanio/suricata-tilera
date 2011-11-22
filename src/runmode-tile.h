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

/** \file
 *
 *  \author Tom DeCanio <decanio.tom@gmail.com>
 */

#ifndef __RUNMODE_TILE_H__
#define __RUNMODE_TILE_H__

#include "suricata-common.h"

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

#define DETECT_THREADS_PER_NETIO_PIPELINE 4
#define DETECT_THREADS_PER_MPIPE_PIPELINE 4
#define TILES_PER_NETIO_PIPELINE (4 + DETECT_THREADS_PER_NETIO_PIPELINE)
#define TILES_PER_MPIPE_PIPELINE (3 + DETECT_THREADS_PER_MPIPE_PIPELINE)
#define NUM_TILERA_NETIO_PIPELINES 7
#define NUM_TILERA_MPIPE_PIPELINES 5

#ifdef __tilegx__
#define TILES_PER_PIPELINE (TILES_PER_MPIPE_PIPELINE)
#define NUM_TILERA_PIPELINES (NUM_TILERA_MPIPE_PIPELINES)
#else
#define TILES_PER_PIPELINE (TILES_PER_NETIO_PIPELINE)
#define NUM_TILERA_PIPELINES (NUM_TILERA_NETIO_PIPELINES)
#endif

int RunModeIdsTileNetioAuto(DetectEngineCtx *);
int RunModeIdsTileNetioAutoFp(DetectEngineCtx *de_ctx);
void RunModeIdsTileNetioRegister(void);
const char *RunModeIdsTileNetioGetDefaultMode(void);

int RunModeIdsTileMpipeAuto(DetectEngineCtx *);
int RunModeIdsTileMpipeAutoFp(DetectEngineCtx *de_ctx);
void RunModeIdsTileMpipeRegister(void);
const char *RunModeIdsTileMpipeGetDefaultMode(void);

extern int TileMpipeUnmapTile(int cpu);

extern void *tile_pcre_malloc(size_t size);
extern void tile_pcre_free(void *ptr);


#endif /* __RUNMODE_TILE_H__ */
