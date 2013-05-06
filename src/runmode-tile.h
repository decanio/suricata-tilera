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

#define DFLT_DETECT_THREADS_PER_NETIO_PIPELINE 4
#define DFLT_DETECT_THREADS_PER_MPIPE_PIPELINE 4
#define DFLT_TILERA_NETIO_PIPELINES 7
#define DFLT_TILERA_MPIPE_PIPELINES 5

#define TILES_PER_NETIO_PIPELINE (4 + TileDetectThreadPerPipeline)
//#define TILES_PER_MPIPE_PIPELINE (3 + TileDetectThreadPerPipeline)
/* NOTE Output stage shared between pairs of pipelines */
//#define TILES_PER_MPIPE_PIPELINE (2 + TileDetectThreadPerPipeline)
/* NOTE Receive + Output stages shared between pairs of pipelines */
#define TILES_PER_MPIPE_PIPELINE (1 + TileDetectThreadPerPipeline)

#ifdef __tilegx__
#define TILES_PER_PIPELINE (TILES_PER_MPIPE_PIPELINE)
#define DFLT_DETECT_THREADS_PER_PIPELINE (DFLT_DETECT_THREADS_PER_MPIPE_PIPELINE)
#define DFLT_TILERA_PIPELINES (DFLT_TILERA_MPIPE_PIPELINES)
#else
#define TILES_PER_PIPELINE (TILES_PER_NETIO_PIPELINE)
#define DFLT_DETECT_THREADS_PER_PIPELINE (DFLT_DETECT_THREADS_PER_NETIO_PIPELINE)
#define DFLT_TILERA_PIPELINES (DFLT_TILERA_NETIO_PIPELINES)
#endif

#define MAX_TILERA_PIPELINES 16

extern unsigned int TileNumPipelines;
extern unsigned int TileNumPipelinesPerRx;
extern unsigned int TileDetectThreadPerPipeline;
extern unsigned int TilesPerPipeline;

int RunModeIdsTileNetioAuto(DetectEngineCtx *);
int RunModeIdsTileNetioAutoFp(DetectEngineCtx *de_ctx);
void RunModeIdsTileNetioRegister(void);
const char *RunModeIdsTileNetioGetDefaultMode(void);

int RunModeIdsTileMpipeAuto(DetectEngineCtx *);
int RunModeIdsTileMpipeWorkers(DetectEngineCtx *de_ctx);
void RunModeIdsTileMpipeRegister(void);
const char *RunModeIdsTileMpipeGetDefaultMode(void);

char *RunModeTileGetPipelineConfig(const char *custom_mode);

extern int TileMpipeUnmapTile(int cpu);
extern void *ParseMpipeConfig(const char *iface);

extern void *tile_pcre_malloc(size_t size);
extern void tile_pcre_free(void *ptr);


#endif /* __RUNMODE_TILE_H__ */
