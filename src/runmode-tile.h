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

#define DETECT_THREADS_PER_PIPELINE 8
#define TILES_PER_PIPELINE (4 + DETECT_THREADS_PER_PIPELINE)
#define NUM_TILERA_PIPELINES 1

int RunModeIdsTileNetioAuto(DetectEngineCtx *);
int RunModeIdsTileNetioAutoFp(DetectEngineCtx *de_ctx);
void RunModeIdsTileNetioRegister(void);
const char *RunModeIdsTileNetioGetDefaultMode(void);

int RunModeIdsTileMpipeAuto(DetectEngineCtx *);
int RunModeIdsTileMpipeAutoFp(DetectEngineCtx *de_ctx);
void RunModeIdsTileMpipeRegister(void);
const char *RunModeIdsTileMpipeGetDefaultMode(void);

#endif /* __RUNMODE_TILE_H__ */
