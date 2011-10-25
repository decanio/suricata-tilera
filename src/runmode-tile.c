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

/** \file
 *
 *  \author Tom DeCanio <decanio.tom@gmail.com>
 *
 *  Tilera tilepro/tilegx runmode support
 */

#include "suricata-common.h"
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-tile.h"
#include "log-httplog.h"
#include "output.h"
#include "cuda-packet-batcher.h"
#ifdef __tilegx__
#include "source-mpipe.h"
#endif
#if defined(__tile__) && !defined(__tilegx__)
#include "source-netio.h"
#endif

#include "alert-fastlog.h"
#include "alert-prelude.h"
#include "alert-unified-log.h"
#include "alert-unified-alert.h"
#include "alert-unified2-alert.h"
#include "alert-debuglog.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"

#ifdef __tile__

/*
 * Compiler is telling us we are building for Tilera
 */

#ifdef __tilegx__

/*
 * runmode support for tilegx
 */

static const char *mpipe_default_mode = NULL;
unsigned int MpipeNumPipes = NUM_TILERA_PIPELINES;

const char *RunModeIdsTileMpipeGetDefaultMode(void)
{
    return mpipe_default_mode;
}

void RunModeIdsTileMpipeRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_TILERA_MPIPE, "auto",
                              "Multi threaded Tilegx mpipe mode",
                              RunModeIdsTileMpipeAuto);
    mpipe_default_mode = "auto";

    return;
}

/**
 * \brief RunModeIdsTileMpipeAuto set up the following thread packet handlers:
 *        - Receive thread (from iface pcap)
 *        - Decode thread
 *        - Stream thread
 *        - Detect: If we have only 1 cpu, it will setup one Detect thread
 *                  If we have more than one, it will setup num_cpus - 1
 *                  starting from the second cpu available.
 *        - Respond/Reject thread
 *        - Outputs thread
 *        By default the threads will use the first cpu available
 *        except the Detection threads if we have more than one cpu
 *
 * \param de_ctx pointer to the Detection Engine
 * \param iface pointer to the name of the interface from which we will
 *              fetch the packets
 * \retval 0 if all goes well. (If any problem is detected the engine will
 *           exit())
 */
int RunModeIdsTileMpipeAuto(DetectEngineCtx *de_ctx) {
    SCEnter();
    char tname[16];
    uint16_t cpu = 0;
    TmModule *tm_module;
    uint16_t thread;
    uint32_t tile = 1;
    int pipe;

    SCLogInfo("RunModeIdsTileMpipeAuto\n");
    RunModeInitialize();

    /* Available cpus */
    uint16_t ncpus = UtilCpuGetNumProcessorsOnline();

    TimeModeSetLive();

    int nmpipe = MpipeLiveGetDeviceCount();

    int pipe_max = MpipeNumPipes;

    for (pipe = 0; pipe < pipe_max; pipe++) {

        if (nmpipe == 1) {
	        char *mpipe_dev = NULL;

            if (ConfGet("netio.single_mpipe_dev", &mpipe_dev) == 0) {
	            SCLogError(SC_ERR_RUNMODE, "Failed retrieving "
                           "netio.single_mpipe_dev from Conf");
                exit(EXIT_FAILURE);
            }

            SCLogDebug("mpipe_dev %s", mpipe_dev);

            char *mpipe_devc = SCStrdup(mpipe_dev);

            /* create the threads */
            ThreadVars *tv_receivempipe =
                 TmThreadCreatePacketHandler("ReceiveMpipe",
                                              "packetpool", "packetpool",
                                              "pickup-queue","simple", 
                                              "pktacqloop");
            if (tv_receivempipe == NULL) {
                printf("ERROR: TmThreadsCreate failed\n");
                exit(EXIT_FAILURE);
            }
            tm_module = TmModuleGetByName("ReceiveMpipe");
            if (tm_module == NULL) {
                printf("ERROR: TmModuleGetByName failed for ReceiveMpipe\n");
                exit(EXIT_FAILURE);
            }
            TmSlotSetFuncAppend(tv_receivempipe,tm_module,(void *)mpipe_devc);

           /* set affinity for mpipe */
           TmThreadSetCPUAffinity(tv_receivempipe, tile++);

            if (TmThreadSpawn(tv_receivempipe) != TM_ECODE_OK) {
                printf("ERROR: TmThreadSpawn failed\n");
                exit(EXIT_FAILURE);
            }
        } else {
        }

        ThreadVars *tv_decode1 =
	        TmThreadCreatePacketHandler("Decode & Stream",
		                    		    "pickup-queue","simple",
                                        "stream-queue1","simple",
                                        "varslot");
        if (tv_decode1 == NULL) {
            printf("ERROR: TmThreadCreate failed for Decode1\n");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName("DecodeMpipe");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName DecodeMpipe failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_decode1,tm_module,NULL);

        tm_module = TmModuleGetByName("StreamTcp");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName StreamTcp failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_decode1,tm_module,NULL);

        TmThreadSetCPUAffinity(tv_decode1, tile++);

        if (TmThreadSpawn(tv_decode1) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }

        int thread_max = DETECT_THREADS_PER_PIPELINE;

        for (thread = 0; thread < thread_max; thread++) {
            snprintf(tname, sizeof(tname),"Detect%"PRIu16, thread+1);
            if (tname == NULL)
                break;

            char *thread_name = SCStrdup(tname);
            SCLogDebug("Assigning %s affinity to cpu %u", thread_name, cpu);

            ThreadVars *tv_detect_ncpu =
                TmThreadCreatePacketHandler(thread_name,
                                            "stream-queue1","simple", 
                                            "verdict-queue","simple",
                                            "1slot");
            if (tv_detect_ncpu == NULL) {
                printf("ERROR: TmThreadsCreate failed\n");
                exit(EXIT_FAILURE);
            }
            tm_module = TmModuleGetByName("Detect");
            if (tm_module == NULL) {
                printf("ERROR: TmModuleGetByName Detect failed\n");
                exit(EXIT_FAILURE);
            }
            TmSlotSetFuncAppend(tv_detect_ncpu,tm_module,(void *)de_ctx);

            TmThreadSetCPUAffinity(tv_detect_ncpu, (int)tile++);

            char *thread_group_name = SCStrdup("Detect");
            if (thread_group_name == NULL) {
                printf("Error allocating memory\n");
                exit(EXIT_FAILURE);
            }
            tv_detect_ncpu->thread_group_name = thread_group_name;

            if (TmThreadSpawn(tv_detect_ncpu) != TM_ECODE_OK) {
                printf("ERROR: TmThreadSpawn failed\n");
                exit(EXIT_FAILURE);
            }

            if ((cpu + 1) == ncpus)
                cpu = 0;
            else
                cpu++;
        }

        ThreadVars *tv_rreject =
            TmThreadCreatePacketHandler("RespondReject",
                                        "verdict-queue","simple", 
                                         "alert-queue","simple",
                                         "1slot");
        if (tv_rreject == NULL) {
            printf("ERROR: TmThreadsCreate failed\n");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName("RespondReject");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName for RespondReject failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_rreject,tm_module,NULL);

        TmThreadSetCPUAffinity(tv_rreject, tile++);

        if (TmThreadSpawn(tv_rreject) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }

        ThreadVars *tv_outputs =
            TmThreadCreatePacketHandler("Outputs",
                                        "alert-queue", "simple", 
                                        "packetpool", "packetpool", 
                                        "varslot");
        SetupOutputs(tv_outputs);

        TmThreadSetCPUAffinity(tv_outputs, tile++);

        if (TmThreadSpawn(tv_outputs) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }

    }

    return 0;
}

#elif defined(__tile__)

/*
 * runmode support for tile64 and tilepro
 */
static const char *netio_default_mode = NULL;
unsigned int NetioNumPipes = NUM_TILERA_PIPELINES;

const char *RunModeIdsTileNetioGetDefaultMode(void)
{
    return netio_default_mode;
}

void RunModeIdsTileNetioRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_TILERA_NETIO, "auto",
                              "Multi threaded TilePro netio",
                              RunModeIdsTileNetioAuto);
    netio_default_mode = "auto";

    return;
}

#define MAX_NETIO_PIPES 12

static char pickup_queue[MAX_NETIO_PIPES][32];
static char stream_queue[MAX_NETIO_PIPES][32];
static char verdict_queue[MAX_NETIO_PIPES][32];
static char alert_queue[MAX_NETIO_PIPES][32];


/**
 * \brief RunModeIdsTileNetioAuto set up the following thread packet handlers:
 *        - Receive thread (from iface pcap)
 *        - Decode thread
 *        - Stream thread
 *        - Detect: If we have only 1 cpu, it will setup one Detect thread
 *                  If we have more than one, it will setup num_cpus - 1
 *                  starting from the second cpu available.
 *        - Respond/Reject thread
 *        - Outputs thread
 *        By default the threads will use the first cpu available
 *        except the Detection threads if we have more than one cpu
 *
 * \param de_ctx pointer to the Detection Engine
 * \param iface pointer to the name of the interface from which we will
 *              fetch the packets
 * \retval 0 if all goes well. (If any problem is detected the engine will
 *           exit())
 */
int RunModeIdsTileNetioAuto(DetectEngineCtx *de_ctx) {
    SCEnter();
    char tname[32];
    char *thread_name;
    uint16_t cpu = 0;
    TmModule *tm_module;
    uint16_t thread;
    uint32_t tile = 1;
    int pipe;
    extern TmEcode ReceiveNetioInit(void); // move this

    RunModeInitialize();

    /* Available cpus */
    uint16_t ncpus = UtilCpuGetNumProcessorsOnline();

    TimeModeSetLive();

    int nnetio = NetioLiveGetDeviceCount();

    int pipe_max = NetioNumPipes;

    ReceiveNetioInit();

    for (pipe = 0; pipe < pipe_max; pipe++) {

        if (nnetio == 1) {
	    char *netio_dev = NULL;

            if (ConfGet("netio.single_netio_dev", &netio_dev) == 0) {
	        SCLogError(SC_ERR_RUNMODE, "Failed retrieving "
                           "netio.single_netio_dev from Conf");
                exit(EXIT_FAILURE);
            }

            SCLogDebug("netio_dev %s", netio_dev);

            char *netio_devc = SCStrdup(netio_dev);

            sprintf(pickup_queue[pipe], "pickup-queue%d", pipe);

            snprintf(tname, sizeof(tname), "ReceiveNetio%"PRIu16, pipe+1);
            thread_name = SCStrdup(tname);

            /* create the threads */
            ThreadVars *tv_receivenetio =
                 TmThreadCreatePacketHandler(thread_name,
                                             "packetpool", "packetpool",
                                             pickup_queue[pipe],"simple", 
                                             "pktacqloop");
            if (tv_receivenetio == NULL) {
                printf("ERROR: TmThreadsCreate failed\n");
                exit(EXIT_FAILURE);
            }
            tm_module = TmModuleGetByName("ReceiveNetio");
            if (tm_module == NULL) {
                printf("ERROR: TmModuleGetByName failed for ReceiveNetio\n");
                exit(EXIT_FAILURE);
            }
            TmSlotSetFuncAppend(tv_receivenetio,tm_module,(void *)netio_devc);

            /* set affinity for netio */
            TmThreadSetCPUAffinity(tv_receivenetio, tile++);

            if (TmThreadSpawn(tv_receivenetio) != TM_ECODE_OK) {
                printf("ERROR: TmThreadSpawn failed\n");
                exit(EXIT_FAILURE);
            }
            SCLogInfo("ReceiveNetio spawned\n");
        } else {
        }

        sprintf(stream_queue[pipe], "stream-queue%d", pipe);

        snprintf(tname, sizeof(tname), "Decode & Stream%"PRIu16, pipe+1);
        thread_name = SCStrdup(tname);

        ThreadVars *tv_decode1 =
            TmThreadCreatePacketHandler(thread_name,
                                        pickup_queue[pipe],"simple",
#if 0
                                        "packetpool","packetpool",
                                        "varslot");
#else
                                        stream_queue[pipe],"simple",
                                        "varslot");
#endif
        if (tv_decode1 == NULL) {
            printf("ERROR: TmThreadCreate failed for Decode1\n");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName("DecodeNetio");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName DecodeNetio failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_decode1,tm_module,NULL);

        tm_module = TmModuleGetByName("StreamTcp");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName StreamTcp failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_decode1,tm_module,NULL);

        TmThreadSetCPUAffinity(tv_decode1, tile++);

        if (TmThreadSpawn(tv_decode1) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }
        SCLogInfo("Decode & Stream spawned\n");

        int thread_max = DETECT_THREADS_PER_PIPELINE;

        for (thread = 0; thread < thread_max; thread++) {

            snprintf(tname, sizeof(tname),"Detect%d-%"PRIu16, pipe+1, thread+1);
            thread_name = SCStrdup(tname);

            SCLogDebug("Assigning %s affinity to cpu %u", thread_name, cpu);

            sprintf(verdict_queue[pipe], "verdict-queue%d", pipe);

            ThreadVars *tv_detect_ncpu =
                TmThreadCreatePacketHandler(thread_name,
                                            stream_queue[pipe],"simple", 
                                            verdict_queue[pipe],"simple",
                                            "1slot");
            if (tv_detect_ncpu == NULL) {
                printf("ERROR: TmThreadsCreate failed\n");
                exit(EXIT_FAILURE);
            }
            tm_module = TmModuleGetByName("Detect");
            if (tm_module == NULL) {
                printf("ERROR: TmModuleGetByName Detect failed\n");
                exit(EXIT_FAILURE);
            }
            TmSlotSetFuncAppend(tv_detect_ncpu,tm_module,(void *)de_ctx);

            TmThreadSetCPUAffinity(tv_detect_ncpu, tile++);

            char *thread_group_name = SCStrdup("Detect");
            if (thread_group_name == NULL) {
                printf("Error allocating memory\n");
                exit(EXIT_FAILURE);
            }
            tv_detect_ncpu->thread_group_name = thread_group_name;

            if (TmThreadSpawn(tv_detect_ncpu) != TM_ECODE_OK) {
                printf("ERROR: TmThreadSpawn failed\n");
                exit(EXIT_FAILURE);
            }
            SCLogInfo("Detect spawned\n");

            if ((cpu + 1) == ncpus)
                cpu = 0;
            else
                cpu++;
        }
#undef SINGLE_OUTPUT

#ifndef SINGLE_OUTPUT
        sprintf(alert_queue[pipe], "alert-queue%d", pipe);
#endif

        snprintf(tname, sizeof(tname), "RespondReject%"PRIu16, pipe+1);
        thread_name = SCStrdup(tname);

        ThreadVars *tv_rreject =
            TmThreadCreatePacketHandler(thread_name,
                                        verdict_queue[pipe],"simple", 
#ifdef SINGLE_OUTPUT
                                        "alert-queue","simple",
#else
                                        alert_queue[pipe],"simple",
#endif
                                        "1slot");
        if (tv_rreject == NULL) {
            printf("ERROR: TmThreadsCreate failed\n");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName("RespondReject");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName for RespondReject failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_rreject,tm_module,NULL);

        TmThreadSetCPUAffinity(tv_rreject, tile++);

        if (TmThreadSpawn(tv_rreject) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }
        SCLogInfo("RespondReject spawned\n");

#ifndef SINGLE_OUTPUT
        snprintf(tname, sizeof(tname), "Outputs%"PRIu16, pipe+1);
        thread_name = SCStrdup(tname);

        ThreadVars *tv_outputs =
            TmThreadCreatePacketHandler(thread_name,
                                        alert_queue[pipe], "simple", 
                                        "packetpool", "packetpool", 
                                        "varslot");
        SetupOutputs(tv_outputs);

        TmThreadSetCPUAffinity(tv_outputs, tile++);

        if (TmThreadSpawn(tv_outputs) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }
        SCLogInfo("Outputs spawned\n");
#endif
    }
#ifdef SINGLE_OUTPUT
    snprintf(tname, sizeof(tname), "Outputs");
    thread_name = SCStrdup(tname);

    ThreadVars *tv_outputs =
        TmThreadCreatePacketHandler(thread_name,
                                    "alert-queue", "simple", 
                                    "packetpool", "packetpool", 
                                    "varslot");
    SetupOutputs(tv_outputs);

    TmThreadSetCPUAffinity(tv_outputs, tile++);

    if (TmThreadSpawn(tv_outputs) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }
    SCLogInfo("Outputs spawned\n");
#endif

    return 0;
}

#endif

#endif
