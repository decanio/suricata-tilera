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
#include <tmc/cpus.h>
#endif
#if defined(__tile__) && !defined(__tilegx__)
#include "source-netio.h"
#endif

#include "alert-fastlog.h"
#include "alert-prelude.h"
#include "alert-unified2-alert.h"
#include "alert-debuglog.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "util-device.h"

#ifdef __tile__

/*
 * Compiler is telling us we are building for Tilera
 */
typedef enum { simple, tmc } queue_t;

unsigned int TileNumPipelines;    /* number of configured parallel pipelines */
unsigned int TileNumPipelinesPerRx; /* pipelines per receive thread */
unsigned int TileDetectThreadPerPipeline; /* detect threads per pipeline */
unsigned int TilesPerPipelines; /* total tiles per pipeline */
static queue_t queue_type = simple;

#ifdef __tilegx__

#define COMBINE_RESPOND_REJECT_AND_OUTPUT
/*
 * runmode support for tilegx
 */

void *tile_pcre_malloc(size_t size)
{
    return SCMalloc(size);
}

void tile_pcre_free(void *ptr)
{
    SCFree(ptr);
}

static const char *mpipe_default_mode = NULL;
//unsigned int MpipeNumPipes = NUM_TILERA_MPIPE_PIPELINES;

const char *RunModeIdsTileMpipeGetDefaultMode(void)
{
    return mpipe_default_mode;
}

void RunModeIdsTileMpipeRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_TILERA_MPIPE, "auto",
                              "Multi threaded tilegx mpipe mode",
                              RunModeIdsTileMpipeAuto);
    RunModeRegisterNewRunMode(RUNMODE_TILERA_MPIPE, "workers",
                              "Workers tilegx mpipe mode, each thread does all"
                              " tasks from acquisition to logging",
                              RunModeIdsTileMpipeWorkers);
    mpipe_default_mode = "workers";

    return;
}

#define MAX_MPIPE_PIPES 72

static char pickup_queue[MAX_MPIPE_PIPES][32];
static char stream_queue[MAX_MPIPE_PIPES][32];
static char verdict_queue[MAX_MPIPE_PIPES][32];
#ifndef COMBINE_RESPOND_REJECT_AND_OUTPUT
static char alert_queue[MAX_MPIPE_PIPES][32];
#endif

#define NO_TILE_MAP
/*
 * This stuff is used to map the linear spwaning
 * of threads to cpu affinity positions on the
 * cores.  The detect cores have been intentionally
 * centrally located in an attempt to minimize latency
 * of hash-for-home cache operations.
 */
#ifndef NO_TILE_MAP
/* order that threads are spawned */
static char *linear[] = {
   "M0", "T0", "D01", "D02", "D03", "D04", "O0",
   "M1", "T1", "D11", "D12", "D13", "D14", "O1",
   "M2", "T2", "D21", "D22", "D23", "D24", "O2",
   "M3", "T3", "D31", "D32", "D33", "D34", "O3",
   "M4", "T4", "D41", "D42", "D43", "D44", "O4",
   NULL
};
/* thread affinity order */
static char *mapped[] = {
   "C",   "O0",  "O1",  "O2",  "O3",  "O4",
   "D01", "D02", "D03", "D04", "D11", "T4",
   "D12", "D13", "D14", "D21", "D22", "T3",
   "D23", "D24", "D31", "D32", "D33", "T2",
   "D34", "D41", "D42", "D43", "D44", "T1",
   "M0",  "M1",  "M2",  "M3",  "M4",  "T0",
   NULL
};
#endif

/* computed mapping */
static int map[100];


/* build the map */
static void RunModeTileMpipeMapCores(void)
{
#ifdef NO_TILE_MAP
    for (int i = 0; i < 100; i++) {
        map[i] = i;
    }
#else
    int i, j;

    for (i = 0; linear[i] != NULL; i++) {
        for (j = 0; mapped[j] != NULL; j++) {
            if (strcmp(linear[i], mapped[j]) == 0) {
                map[i] = j;
                //printf("tile %s at core %d\n", linear[i], j);
            }
        }
    }
#endif
}

#if 0
/* map from spawn order to affinity */
static int MapTile(int cpu)
{
#ifdef NO_TILE_MAP
    return cpu;
#else
#error Tile mapping no longer supported
    return map[cpu-1];
#endif
}
#endif

/* unmap a thread so that source-mpipe can calculate ranks */
int TileMpipeUnmapTile(int cpu)
{
#ifdef NO_TILE_MAP
    return cpu;
#else
    int i;
    char *s = mapped[cpu];
    //printf("unmapping %s\n", s);
    for (i = 0; linear[i] != NULL; i++) {
        if (strcmp(linear[i], s) == 0) {
            //printf("found at %d\n", i);
            return i+1;
        }
    }
    return 0;
#endif
}

char *RunModeTileGetPipelineConfig(const char *custom_mode) {
    intmax_t pipelines;
    intmax_t detect_per_pipe;
    intmax_t value = 0;
    char *s;

    if (custom_mode != NULL) {
        return custom_mode;
    }

    char *runmode = NULL;
    if (ConfGet("runmode", &runmode) == 1) {
        if (strcmp(runmode, "workers") == 0) {
            /* Available cpus */
            cpu_set_t cpus;
            tmc_cpus_get_dataplane_cpus(&cpus);
            uint16_t ncpus = tmc_cpus_count(&cpus);
            TileNumPipelines = ncpus - 1;
            return runmode;
        }
    }
   
    if (ConfGetInt("tile.pipelines", &pipelines) == 1) {
        TileNumPipelines = pipelines;
    } else {
        TileNumPipelines = DFLT_TILERA_PIPELINES;
    }
    SCLogInfo("%d Tilera pipelines", TileNumPipelines);
    if (ConfGetInt("tile.detect-per-pipeline", &detect_per_pipe) == 1) {
        TileDetectThreadPerPipeline = detect_per_pipe;
    } else {
        TileDetectThreadPerPipeline = DFLT_DETECT_THREADS_PER_PIPELINE;
    }
    if ((ConfGetInt("mpipe.poll", &value)) == 1) {
        /* only 1 and 2 are permitted */
        if ((value >= 1) && (value <= 2)) {
            TileNumPipelinesPerRx = (unsigned int) value;
        } else {
            SCLogError(SC_ERR_FATAL, "Illegal mpipe.poll value.");
        }
    }
    if (ConfGet("tile.queue", &s) == 1) {
        if (strcmp(s, "simple") == 0) {
            queue_type = simple;
        } else if (strcmp(s, "tmc") == 0) {
            queue_type = tmc;
        }
    }
    SCLogInfo("%d detect threads per pipeline", TileDetectThreadPerPipeline);
    SCLogInfo("%d utilized dataplane tiles", (TILES_PER_PIPELINE * TileNumPipelines) + (TileNumPipelines / 2));
    SCLogInfo("%s queueing between tiles", (queue_type == simple) ? "simple" : "tmc");
    return NULL;
}

void *ParseMpipeConfig(const char *iface)
{
    ConfNode *if_root;
    ConfNode *mpipe_node;
    MpipeIfaceConfig *aconf = SCMalloc(sizeof(*aconf));
    char *copymodestr;
    char *out_iface = NULL;

    if (aconf == NULL) {
        return NULL;
    }

    if (iface == NULL) {
        SCFree(aconf);
        return NULL;
    }

    strlcpy(aconf->iface, iface, sizeof(aconf->iface));

    /* Find initial node */
    mpipe_node = ConfGetNode("mpipe.inputs");
    if (mpipe_node == NULL) {
        SCLogInfo("Unable to find mpipe config using default value");
        return aconf;
    }

    if_root = ConfNodeLookupKeyValue(mpipe_node, "interface", iface);
    if (if_root == NULL) {
        SCLogInfo("Unable to find mpipe config for "
                  "interface %s, using default value",
                  iface);
        return aconf;
    }

    if (ConfGetChildValue(if_root, "copy-iface", &out_iface) == 1) {
        if (strlen(out_iface) > 0) {
            aconf->out_iface = out_iface;
        }
    }
    aconf->copy_mode = MPIPE_COPY_MODE_NONE;
    if (ConfGetChildValue(if_root, "copy-mode", &copymodestr) == 1) {
        if (aconf->out_iface == NULL) {
            SCLogInfo("Copy mode activated but no destination"
                      " iface. Disabling feature");
        } else if (strlen(copymodestr) <= 0) {
            aconf->out_iface = NULL;
        } else if (strcmp(copymodestr, "ips") == 0) {
            SCLogInfo("MPIPE IPS mode activated %s->%s",
                      iface,
                      aconf->out_iface);
            aconf->copy_mode = MPIPE_COPY_MODE_IPS;
        } else if (strcmp(copymodestr, "tap") == 0) {
            SCLogInfo("MPIPE TAP mode activated %s->%s",
                      iface,
                      aconf->out_iface);
            aconf->copy_mode = MPIPE_COPY_MODE_TAP;
        } else {
            SCLogInfo("Invalid mode (no in tap, ips)");
        }
    }
    return aconf;
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
    char tname[32];
    char *thread_name;
    uint16_t cpu = 0;
    TmModule *tm_module;
    uint16_t thread;
    /*uint32_t tile = 1;*/
    int pipe;
    unsigned int poll_n = TileNumPipelinesPerRx;
    char *detectmode = NULL;
    int pool_detect_threads = 0;
    extern TmEcode ReceiveMpipeInit(void); // move this

    /*SCLogInfo("RunModeIdsTileMpipeAuto\n");*/
    
    if (ConfGet("tile.detect", &detectmode) == 1) {
        if (detectmode) {
        	SCLogInfo("DEBUG: detectmode %s", detectmode);
        	if (strcmp(detectmode, "pooled") == 0) {
        		pool_detect_threads = 1;
        	}
        }   
    }

    RunModeTileMpipeMapCores();

    RunModeInitialize();

    /* Available cpus */
    uint16_t ncpus = UtilCpuGetNumProcessorsOnline();

    TimeModeSetLive();

    int pipe_max = TileNumPipelines;

    ReceiveMpipeInit();

    char *mpipe_dev = NULL;
    int nlive = LiveGetDeviceCount();
    if (nlive > 0) {
        char *link_name;
        int i;
        SCLogInfo("Using %d live device(s).", nlive);
        /*mpipe_dev = LiveGetDevice(0);*/
        for (i = 0; i < nlive; i++) {
            MpipeIfaceConfig *aconf;
            link_name = LiveGetDeviceName(i);
            aconf = ParseMpipeConfig(link_name);
            if (aconf != NULL) 
                SCFree(aconf);
        }
    } else {
        /*
         * Attempt to get interface from config file
         * overrides -i from command line.
         */
        if (ConfGet("mpipe.interface", &mpipe_dev) == 0) {
            if (ConfGet("mpipe.single_mpipe_dev", &mpipe_dev) == 0) {
	            SCLogError(SC_ERR_RUNMODE, "Failed retrieving "
                           "mpipe.single_mpipe_dev from Conf");
                exit(EXIT_FAILURE);
            }
        }
    }

    /*
     * Careful.  All of the pickup_queues must be created
     * prior to building to pipeline so that the queues
     * are adjacent in the lookup table.  This lets the
     * demux2 queue handler work.
     */
    for (pipe = 0; pipe < pipe_max; pipe++) {
        sprintf(pickup_queue[pipe], "pickup-queue%d", pipe);
        if (TmqCreateQueue(pickup_queue[pipe]) == NULL) {
            SCLogError(SC_ERR_RUNMODE, "Could not create pickup queue");
            exit(EXIT_FAILURE);
        }
    }

    for (pipe = 0; pipe < pipe_max; pipe++) {

        char *mpipe_devc;

        /* HACK: Receive Threads are shared between pairs of
         * pipelines.  So for every other pipeline create two
         * queues and spawn only one thread.
         */

        if (nlive > 0) {
            mpipe_devc = SCStrdup("multi");
        } else {
            mpipe_devc = SCStrdup(mpipe_dev);
        }

        //sprintf(pickup_queue[pipe], "pickup-queue%d", pipe);

        snprintf(tname, sizeof(tname), "ReceiveMpipe%d", pipe+1);
        thread_name = SCStrdup(tname);

        /* create the threads */
        ThreadVars *tv_receivempipe =
             TmThreadCreatePacketHandler(thread_name,
                                         "packetpool", "packetpool",
                                         //pickup_queue[pipe],"simple", 
                                         pickup_queue[pipe],(poll_n == 2)?"demux2":"simple", 
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
        TmSlotSetFuncAppend(tv_receivempipe, tm_module, (void *)mpipe_devc);

        if ((pipe % poll_n) == 0) {
            /* set affinity for mpipe */
            TmThreadSetCPUAffinity(tv_receivempipe, 1+(pipe/poll_n));

            SCLogInfo("Thread %s pipe_max %d pipe %d cpu %d",
                      thread_name, pipe_max, pipe,
                      1+(pipe/poll_n));

            if (TmThreadSpawn(tv_receivempipe) != TM_ECODE_OK) {
                printf("ERROR: TmThreadSpawn failed\n");
                exit(EXIT_FAILURE);
            }
        }

        sprintf(stream_queue[pipe], "stream-queue%d", pipe);

        snprintf(tname, sizeof(tname), "Decode&Stream%d", pipe+1);
        thread_name = SCStrdup(tname);

        ThreadVars *tv_decode1 =
	        TmThreadCreatePacketHandler(thread_name,
                                            //pickup_queue[pipe],"simple",
                                            pickup_queue[pipe],(poll_n==2)?"demux2":"simple",
                                            stream_queue[(pool_detect_threads) ? 0 : pipe], (queue_type == simple) ? "simple" : "tmc_mrsw",
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

        //TmThreadSetCPUAffinity(tv_decode1, MapTile(tile++));
        TmThreadSetCPUAffinity(tv_decode1,
                               1+((pipe_max+1)/poll_n)+(pipe*TILES_PER_PIPELINE));

        SCLogInfo("Thread %s pipe_max %d pipe %d cpu %d",
                  thread_name, pipe_max, pipe,
                  1+((pipe_max+1)/poll_n)+(pipe*TILES_PER_PIPELINE));

        if (TmThreadSpawn(tv_decode1) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }

        int thread_max = TileDetectThreadPerPipeline;

        for (thread = 0; thread < thread_max; thread++) {
            snprintf(tname, sizeof(tname),"Detect%d-%"PRIu16, pipe+1, thread+1);
            if (tname == NULL)
                break;

            thread_name = SCStrdup(tname);
            SCLogDebug("Assigning %s affinity to cpu %u", thread_name, cpu);

            sprintf(verdict_queue[pipe], "verdict-queue%d", pipe);

//#define PIPELINES_PER_OUTPUT 2
#define PIPELINES_PER_OUTPUT 1
            ThreadVars *tv_detect_ncpu =
                TmThreadCreatePacketHandler(thread_name,
                                            stream_queue[(pool_detect_threads) ? 0 : pipe], (queue_type == simple) ? "simple" : "tmc_mrsw", 
#if 1
                                            verdict_queue[pipe/PIPELINES_PER_OUTPUT], (queue_type == simple) ? "simple" : "tmc_srmw",
#else
                                            "packetpool", "packetpool", 
#endif
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

            //TmThreadSetCPUAffinity(tv_detect_ncpu, MapTile(tile++));
            TmThreadSetCPUAffinity(tv_detect_ncpu,
                               1+((pipe_max+1)/poll_n)+(pipe*TILES_PER_PIPELINE)+thread+1);
SCLogInfo("Thread %s pipe_max %d pipe %d cpu %d", thread_name, pipe_max, pipe,
                               1+((pipe_max+1)/poll_n)+(pipe*TILES_PER_PIPELINE)+thread+1);

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

#ifdef COMBINE_RESPOND_REJECT_AND_OUTPUT
	//if ((pipe % PIPELINES_PER_OUTPUT) == 0) {
	if (1) {
        snprintf(tname, sizeof(tname), "RR&Output%d", pipe+1);
        thread_name = SCStrdup(tname);
        ThreadVars *tv_outputs =
            TmThreadCreatePacketHandler(thread_name,
                                        verdict_queue[pipe/PIPELINES_PER_OUTPUT], (queue_type == simple) ? "simple" : "tmc_srmw", 
                                        "packetpool", "packetpool", 
                                        "varslot");
        if (tv_outputs == NULL) {
            printf("ERROR: TmThreadsCreate failed\n");
            exit(EXIT_FAILURE);
        }
        //TmThreadSetCPUAffinity(tv_outputs, MapTile(tile++));
        //TmThreadSetCPUAffinity(tv_outputs, MapTile((pipe_max * TILES_PER_PIPELINE) + (pipe / 2) + 1));
        TmThreadSetCPUAffinity(tv_outputs,
                               1+((pipe_max+1)/poll_n)+(pipe_max*TILES_PER_PIPELINE)+(pipe/PIPELINES_PER_OUTPUT));

        tm_module = TmModuleGetByName("RespondReject");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName for RespondReject failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_outputs,tm_module,NULL);

        SetupOutputs(tv_outputs);

        if (TmThreadSpawn(tv_outputs) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }
	}
#else
        sprintf(alert_queue[pipe], "alert-queue%d", pipe);

        snprintf(tname, sizeof(tname), "RespondReject%"PRIu16, pipe+1);
        thread_name = SCStrdup(tname);
        ThreadVars *tv_rreject =
            TmThreadCreatePacketHandler(thread_name,
                                        verdict_queue[pipe],"simple", 
                                        alert_queue[pipe],"simple",
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

        TmThreadSetCPUAffinity(tv_rreject, MapTile(tile++));

        if (TmThreadSpawn(tv_rreject) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }

        snprintf(tname, sizeof(tname), "Outputs%"PRIu16, pipe+1);
        thread_name = SCStrdup(tname);

        ThreadVars *tv_outputs =
            TmThreadCreatePacketHandler(thread_name,
                                        alert_queue[pipe], "simple", 
                                        "packetpool", "packetpool", 
                                        "varslot");
        SetupOutputs(tv_outputs);

        TmThreadSetCPUAffinity(tv_outputs, MapTile(tile++));

        if (TmThreadSpawn(tv_outputs) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }
#endif
    }

    return 0;
}
/**
 * \brief RunModeIdsTileMpipeWorkers set up the following thread packet handlers:
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
int RunModeIdsTileMpipeWorkers(DetectEngineCtx *de_ctx) {
    SCEnter();
    char tname[32];
    char *thread_name;
    TmModule *tm_module;
    int pipe;
    char *detectmode = NULL;
    int pool_detect_threads = 0;
    extern TmEcode ReceiveMpipeInit(void); // move this

    if (ConfGet("tile.detect", &detectmode) == 1) {
        if (detectmode) {
        	SCLogInfo("DEBUG: detectmode %s", detectmode);
        	if (strcmp(detectmode, "pooled") == 0) {
        		pool_detect_threads = 1;
        	}
        }   
    }

    RunModeTileMpipeMapCores();

    RunModeInitialize();

    /* Available cpus */
    cpu_set_t cpus;
    tmc_cpus_get_dataplane_cpus(&cpus);
    uint16_t ncpus = tmc_cpus_count(&cpus);

    TimeModeSetLive();

    int pipe_max = ncpus - 1;
    TileNumPipelines = pipe_max;
    TileNumPipelinesPerRx = 1;

    ReceiveMpipeInit();

    char *mpipe_dev = NULL;
    int nlive = LiveGetDeviceCount();
    if (nlive > 0) {
        SCLogInfo("Using %d live device(s).", nlive);
        /*mpipe_dev = LiveGetDevice(0);*/
    } else {
        /*
         * Attempt to get interface from config file
         * overrides -i from command line.
         */
        if (ConfGet("mpipe.interface", &mpipe_dev) == 0) {
            if (ConfGet("mpipe.single_mpipe_dev", &mpipe_dev) == 0) {
	            SCLogError(SC_ERR_RUNMODE, "Failed retrieving "
                           "mpipe.single_mpipe_dev from Conf");
                exit(EXIT_FAILURE);
            }
        }
    }

    /*
     * Careful.  All of the pickup_queues must be created
     * prior to building to pipeline so that the queues
     * are adjacent in the lookup table.  This lets the
     * demux2 queue handler work.
     */
    for (pipe = 0; pipe < pipe_max; pipe++) {
        sprintf(pickup_queue[pipe], "pickup-queue%d", pipe);
        if (TmqCreateQueue(pickup_queue[pipe]) == NULL) {
            SCLogError(SC_ERR_RUNMODE, "Could not create pickup queue");
            exit(EXIT_FAILURE);
        }
    }

    for (pipe = 0; pipe < pipe_max; pipe++) {

        char *mpipe_devc;

        /* HACK: Receive Threads are shared between pairs of
         * pipelines.  So for every other pipeline create two
         * queues and spawn only one thread.
         */

        if (nlive > 0) {
            mpipe_devc = SCStrdup("multi");
        } else {
            mpipe_devc = SCStrdup(mpipe_dev);
        }

        snprintf(tname, sizeof(tname), "Worker%d", pipe+1);
        thread_name = SCStrdup(tname);

        /* create the threads */
        ThreadVars *tv_worker =
             TmThreadCreatePacketHandler(thread_name,
                                         "packetpool", "packetpool",
                                         "packetpool", "packetpool", 
                                         "pktacqloop");
        if (tv_worker == NULL) {
            printf("ERROR: TmThreadsCreate failed\n");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName("ReceiveMpipe");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName failed for ReceiveMpipe\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_worker, tm_module, (void *)mpipe_devc);

        /* set affinity for worker */
        TmThreadSetCPUAffinity(tv_worker, 1+pipe);

        SCLogInfo("Thread %s pipe_max %d pipe %d cpu %d",
                  thread_name, pipe_max, pipe,
                  1+pipe);

        tm_module = TmModuleGetByName("DecodeMpipe");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName DecodeMpipe failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_worker,tm_module,NULL);

        tm_module = TmModuleGetByName("StreamTcp");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName StreamTcp failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_worker,tm_module,NULL);

        tm_module = TmModuleGetByName("Detect");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName Detect failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_worker,tm_module,(void *)de_ctx);

        tm_module = TmModuleGetByName("RespondReject");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName for RespondReject failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_worker,tm_module,NULL);

        SetupOutputs(tv_worker);

        if (TmThreadSpawn(tv_worker) != TM_ECODE_OK) {
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
//unsigned int NetioNumPipes = NUM_TILERA_NETIO_PIPELINES;

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

    int pipe_max = TileNumPipelines;

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

        int thread_max = TileDetectThreadsPerPipeline;

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
