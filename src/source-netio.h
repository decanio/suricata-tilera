/**
 * \file
 *
 * \author Tom DeCanio <decanio.tom@gmail.com>
 */

#ifndef __SOURCE_NETIO_H__
#define __SOURCE_NETIO_H__

#if defined(__tile__) && !defined(__tilegx__)
#define NETIO_FREE_PACKET(p) \
    { \
    if ((p)->flags & PKT_NETIO) { \
        netio_error_t err; \
        if ((err = netio_free_buffer(&t->netio_queue, &(p)->netio_packet)) != NETIO_NO_ERROR) { \
            SCLogInfo("netio_free_buffer errored %s", netio_strerror(err)); \
        } \
        (p)->flags &= ~PKT_NETIO; \
    } \
    }
#else
#define NETIO_FREE_PACKET(p)
#endif

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
