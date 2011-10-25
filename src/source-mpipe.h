/**
 * \file
 *
 * \author Tom DeCanio <decanio.tom@gmail.com>
 */

#ifndef __SOURCE_MPIPE_H__
#define __SOURCE_MPIPE_H__

#ifdef __tilegx__
#define MPIPE_FREE_PACKET(p) \
    { \
    if ((p)->flags & PKT_MPIPE) { \
        MpipeFreePacket((p)); \
        (p)->flags &= ~PKT_MPIPE; \
    } \
    }
#else
#define MPIPE_FREE_PACKET(p)
#endif

void TmModuleReceiveMpipeRegister (void);
void TmModuleDecodeMpipeRegister (void);

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
