/**
 * \file
 *
 * \author Tom DeCanio <decanio.tom@gmail.com>
 */

#ifndef __SOURCE_NETIO_H__
#define __SOURCE_NETIO_H__

void TmModuleReceiveNetioRegister (void);
void TmModuleDecodeNetioRegister (void);

int NetioLiveRegisterDevice(char *);
int NetioLiveGetDeviceCount(void);
char *NeioLiveGetDevice(int);


/* per packet Netio vars */
typedef struct NetioPacketVars_
{
} NetioPacketVars;

#endif /* __SOURCE_NETIO_H__ */
