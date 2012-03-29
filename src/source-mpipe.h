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
 */

#ifndef __SOURCE_MPIPE_H__
#define __SOURCE_MPIPE_H__

#ifdef __tilegx__
#if 1
#define MPIPE_FREE_PACKET(p) MpipeFreePacket((p))
#else
#define MPIPE_FREE_PACKET(p) \
    { \
    if ((p)->flags & PKT_MPIPE) { \
        MpipeFreePacket((p)); \
        (p)->flags &= ~PKT_MPIPE; \
    } \
    }
#endif
#else
#define MPIPE_FREE_PACKET(p)
#endif

void TmModuleReceiveMpipeRegister (void);
void TmModuleDecodeMpipeRegister (void);
TmEcode MpipeRegisterPipeStage(void *td);
int MpipeLiveRegisterDevice(char *);
int MpipeLiveGetDeviceCount(void);
char *MpipeLiveGetDevice(int);
void MpipeFreePacket(Packet *p);
TmEcode ReceiveMpipeGo(void);

/* per packet Netio vars */
typedef struct MpipePacketVars_
{
} MpipePacketVars;

#endif /* __SOURCE_MPIPE_H__ */
