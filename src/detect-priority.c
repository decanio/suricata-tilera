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
 * \author Victor Julien <victor@inliniac.net>
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Implements the priority keyword
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "util-error.h"
#include "util-debug.h"
#include "util-unittest.h"

#define DETECT_PRIORITY_REGEX "^\\s*(\\d+|\"\\d+\")\\s*$"

static pcre *regex = NULL;
static pcre_extra *regex_study = NULL;

static int DetectPrioritySetup (DetectEngineCtx *, Signature *, char *);
void SCPriorityRegisterTests(void);

/**
 * \brief Registers the handler functions for the "priority" keyword
 */
void DetectPriorityRegister (void)
{
    const char *eb = NULL;
    int eo;
    int opts = 0;

    sigmatch_table[DETECT_PRIORITY].name = "priority";
    sigmatch_table[DETECT_PRIORITY].Match = NULL;
    sigmatch_table[DETECT_PRIORITY].Setup = DetectPrioritySetup;
    sigmatch_table[DETECT_PRIORITY].Free = NULL;
    sigmatch_table[DETECT_PRIORITY].RegisterTests = SCPriorityRegisterTests;

    regex = pcre_compile(DETECT_PRIORITY_REGEX, opts, &eb, &eo, NULL);
    if (regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at offset %" PRId32 ": %s",
                   DETECT_PRIORITY_REGEX, eo, eb);
        goto end;
    }

    regex_study = pcre_study(regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto end;
    }

 end:
    return;
}

static int DetectPrioritySetup (DetectEngineCtx *de_ctx, Signature *s, char *rawstr)
{
    const char *prio_str = NULL;

#define MAX_SUBSTRINGS 30
    int ret = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(regex, regex_study, rawstr, strlen(rawstr), 0, 0, ov, 30);
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_MATCH, "Invalid Priority in Signature "
                     "- %s", rawstr);
        return -1;
    }

    ret = pcre_get_substring((char *)rawstr, ov, 30, 1, &prio_str);
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        return -1;
    }

    long prio = 0;
    char *endptr = NULL;
    prio = strtol(rawstr, &endptr, 10);
    if (endptr == NULL || *endptr != '\0') {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Saw an invalid character as arg "
                   "to priority keyword");
        goto error;
    }
    /* if we have reached here, we have had a valid priority.  Assign it */
    s->prio = prio;

    return 0;
 error:
    return -1;
}

/*------------------------------Unittests-------------------------------------*/

#ifdef UNITTESTS

int DetectPriorityTest01()
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Priority test\"; priority:2; sid:1;)");
    if (de_ctx->sig_list != NULL)
        result = 1;

    DetectEngineCtxFree(de_ctx);

end:
    return result;
}

int DetectPriorityTest02()
{
    int result = 0;
    Signature *last = NULL;
    Signature *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    sig = SigInit(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Priority test\"; priority:1; sid:1;)");
    de_ctx->sig_list = last = sig;
    if (sig == NULL) {
        result = 0;
    } else {
        result = 1;
        result &= (sig->prio == 1);
    }

    sig = SigInit(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Priority test\"; priority:boo; sid:1;)");
    if (last != NULL)
        last->next = sig;
    result &= (sig == NULL);

    sig = SigInit(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Priority test\"; priority:10boo; sid:1;)");
    if (last != NULL)
        last->next = sig;
    result &= (sig == NULL);

    sig = SigInit(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Priority test\"; priority:b10oo; sid:1;)");
    if (last != NULL)
        last->next = sig;
    result &= (sig == NULL);

    sig = SigInit(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Priority test\"; priority:boo10; sid:1;)");
    if (last != NULL)
        last->next = sig;
    result &= (sig == NULL);

    sig = SigInit(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Priority test\"; priority:-1; sid:1;)");
    if (last != NULL)
        last->next = sig;
    result &= (sig == NULL);

    sig = SigInit(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Priority test\"; sid:1;)");
    if (last != NULL)
        last->next = sig;
    if (sig == NULL) {
        result &= 0;
    } else {
        result &= (sig->prio == 3);
    }

    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

end:
    return result;
}


#endif /* UNITTESTS */

/**
 * \brief This function registers unit tests for Classification Config API.
 */
void SCPriorityRegisterTests(void)
{

#ifdef UNITTESTS

    UtRegisterTest("DetectPriorityTest01", DetectPriorityTest01, 1);
    UtRegisterTest("DetectPriorityTest02", DetectPriorityTest02, 1);

#endif /* UNITTESTS */

}
