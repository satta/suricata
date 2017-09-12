/* Copyright (C) 2007-2017 Open Information Security Foundation
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
 * \author XXX
 *
 */

#include "suricata-common.h"
#include "stream-tcp.h"
#include "util-unittest.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter-common.h"

#include "detect-coverage2.h"
#include "util-debug.h"

/**
 * \brief Regex for parsing our options
 */
#define PARSE_REGEX  "^\\s*([0-9]*)?\\s*([<>=-]+)?\\s*([0-9]+)?\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

/* prototypes */
static int DetectCoverage2Match (ThreadVars *, DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectCoverage2Setup (DetectEngineCtx *, Signature *, const char *);
void DetectCoverage2Free (void *);
void DetectCoverage2RegisterTests (void);

static int PrefilterSetupCoverage2(SigGroupHead *sgh);
static _Bool PrefilterCoverage2IsPrefilterable(const Signature *s);

/**
 * \brief Registration function for coverage2: keyword
 */

void DetectCoverage2Register(void)
{
    sigmatch_table[DETECT_COVERAGE2].name = "coverage2";
    sigmatch_table[DETECT_COVERAGE2].desc = "Just like coverage but with prefiltering.";
    sigmatch_table[DETECT_COVERAGE2].url = DOC_URL DOC_VERSION "/rules/header-keywords.html#coverage2";
    sigmatch_table[DETECT_COVERAGE2].Match = DetectCoverage2Match;
    sigmatch_table[DETECT_COVERAGE2].Setup = DetectCoverage2Setup;
    sigmatch_table[DETECT_COVERAGE2].Free = DetectCoverage2Free;
    sigmatch_table[DETECT_COVERAGE2].RegisterTests = DetectCoverage2RegisterTests;

    sigmatch_table[DETECT_COVERAGE2].SupportsPrefilter = PrefilterCoverage2IsPrefilterable;
    sigmatch_table[DETECT_COVERAGE2].SetupPrefilter = PrefilterSetupCoverage2;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);
    return;
}

static inline int Coverage2Match(const uint8_t parg2, const uint8_t mode,
        const uint8_t darg21, const uint8_t darg22)
{
    if (mode == DETECT_COVERAGE2_EQ && parg2 == darg21)
        return 1;
    else if (mode == DETECT_COVERAGE2_LT && parg2 < darg21)
        return 1;
    else if (mode == DETECT_COVERAGE2_GT && parg2 > darg21)
        return 1;
    else if (mode == DETECT_COVERAGE2_RA && (parg2 >= darg21 && parg2 <= darg22))
        return 1;

    return 0;
}

/**
 * \brief This function is used to match COVERAGE2 rule option on a packet with those passed via coverage2:
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectCoverage2Data
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectCoverage2Match (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{

    if (PKT_IS_PSEUDOPKT(p))
        return 0;

    /* TODO replace this */
    uint16_t pcoverage2;
    if (PKT_IS_IPV4(p)) {
      if (!p->udplitehdr) {
        return 0;
      }
      pcoverage2 = ntohs(p->udplitehdr->checksum_coverage);
    } else {
        SCLogDebug("Packet is of not IPv4 or IPv6");
        return 0;
    }

    const DetectCoverage2Data *coverage2d = (const DetectCoverage2Data *)ctx;
    return Coverage2Match(pcoverage2, coverage2d->mode, coverage2d->arg1, coverage2d->arg2);
}

/**
 * \brief This function is used to parse coverage2 options passed via coverage2: keyword
 *
 * \param coverage2str Pointer to the user provided coverage2 options
 *
 * \retval coverage2d pointer to DetectCoverage2Data on success
 * \retval NULL on failure
 */

static DetectCoverage2Data *DetectCoverage2Parse (const char *coverage2str)
{
    DetectCoverage2Data *coverage2d = NULL;
    char *arg1 = NULL;
    char *arg2 = NULL;
    char *arg3 = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, coverage2str, strlen(coverage2str), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 2 || ret > 4) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        goto error;
    }
    const char *str_ptr;

    res = pcre_get_substring((char *) coverage2str, ov, MAX_SUBSTRINGS, 1, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }
    arg1 = (char *) str_ptr;
    SCLogDebug("Arg1 \"%s\"", arg1);

    if (ret >= 3) {
        res = pcre_get_substring((char *) coverage2str, ov, MAX_SUBSTRINGS, 2, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }
        arg2 = (char *) str_ptr;
        SCLogDebug("Arg2 \"%s\"", arg2);

        if (ret >= 4) {
            res = pcre_get_substring((char *) coverage2str, ov, MAX_SUBSTRINGS, 3, &str_ptr);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                goto error;
            }
            arg3 = (char *) str_ptr;
            SCLogDebug("Arg3 \"%s\"", arg3);
        }
    }

    coverage2d = SCMalloc(sizeof (DetectCoverage2Data));
    if (unlikely(coverage2d == NULL))
        goto error;
    coverage2d->arg1 = 0;
    coverage2d->arg2 = 0;

    if (arg2 != NULL) {
        /*set the values*/
        switch(arg2[0]) {
            case '<':
                if (arg3 == NULL)
                    goto error;

                coverage2d->mode = DETECT_COVERAGE2_LT;
                coverage2d->arg1 = (uint8_t) atoi(arg3);

                SCLogDebug("coverage2 is %"PRIu16"",coverage2d->arg1);
                if (strlen(arg1) > 0)
                    goto error;

                break;
            case '>':
                if (arg3 == NULL)
                    goto error;

                coverage2d->mode = DETECT_COVERAGE2_GT;
                coverage2d->arg1 = (uint8_t) atoi(arg3);

                SCLogDebug("coverage2 is %"PRIu16"",coverage2d->arg1);
                if (strlen(arg1) > 0)
                    goto error;

                break;
            case '-':
                if (arg1 == NULL || strlen(arg1)== 0)
                    goto error;
                if (arg3 == NULL || strlen(arg3)== 0)
                    goto error;

                coverage2d->mode = DETECT_COVERAGE2_RA;
                coverage2d->arg1 = (uint8_t) atoi(arg1);

                coverage2d->arg2 = (uint8_t) atoi(arg3);
                SCLogDebug("coverage2 is %"PRIu16" to %"PRIu16"",coverage2d->arg1, coverage2d->arg2);
                if (coverage2d->arg1 >= coverage2d->arg2) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid coverage2 range. ");
                    goto error;
                }
                break;
            default:
                coverage2d->mode = DETECT_COVERAGE2_EQ;

                if ((arg2 != NULL && strlen(arg2) > 0) ||
                    (arg3 != NULL && strlen(arg3) > 0) ||
                    (arg1 == NULL ||strlen(arg1) == 0))
                    goto error;

                coverage2d->arg1 = (uint8_t) atoi(arg1);
                break;
        }
    } else {
        coverage2d->mode = DETECT_COVERAGE2_EQ;

        if ((arg3 != NULL && strlen(arg3) > 0) ||
            (arg1 == NULL ||strlen(arg1) == 0))
            goto error;

        coverage2d->arg1 = (uint8_t) atoi(arg1);
    }

    SCFree(arg1);
    SCFree(arg2);
    SCFree(arg3);
    return coverage2d;

error:
    if (coverage2d)
        SCFree(coverage2d);
    if (arg1)
        SCFree(arg1);
    if (arg2)
        SCFree(arg2);
    if (arg3)
        SCFree(arg3);
    return NULL;
}

/**
 * \brief this function is used to acoverage2d the parsed coverage2 data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param coverage2str pointer to the user provided coverage2 options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectCoverage2Setup (DetectEngineCtx *de_ctx, Signature *s, const char *coverage2str)
{
    DetectCoverage2Data *coverage2d = NULL;
    SigMatch *sm = NULL;

    coverage2d = DetectCoverage2Parse(coverage2str);
    if (coverage2d == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_COVERAGE2;
    sm->ctx = (SigMatchCtx *)coverage2d;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (coverage2d != NULL)
        DetectCoverage2Free(coverage2d);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectCoverage2Data
 *
 * \param ptr pointer to DetectCoverage2Data
 */
void DetectCoverage2Free(void *ptr)
{
    DetectCoverage2Data *coverage2d = (DetectCoverage2Data *)ptr;
    SCFree(coverage2d);
}

/* prefilter code */

static void
PrefilterPacketCoverage2Match(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    if (PKT_IS_PSEUDOPKT(p)) {
        SCReturn;
    }

    uint8_t pcoverage2;
    if (PKT_IS_IPV4(p)) {
      if (!p->udplitehdr) {
        return;
      }
      pcoverage2 = ntohs(p->udplitehdr->checksum_coverage);
    } else {
        SCLogDebug("Packet is of not IPv4 or IPv6");
        return;
    }

    const PrefilterPacketHeaderCtx *ctx = pectx;
    if (PrefilterPacketHeaderExtraMatch(ctx, p) == FALSE)
        return;

    if (Coverage2Match(pcoverage2, ctx->v1.u16[0], ctx->v1.u16[1], ctx->v1.u16[2]))
    {
        SCLogDebug("packet matches coverage2/hl %u", pcoverage2);
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static void
PrefilterPacketCoverage2Set(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectCoverage2Data *a = smctx;
    v->u16[0] = a->mode;
    v->u16[1] = a->arg1;
    v->u16[2] = a->arg2;
}

static _Bool
PrefilterPacketCoverage2Compare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectCoverage2Data *a = smctx;
    if (v.u16[0] == a->mode &&
        v.u16[1] == a->arg1 &&
        v.u16[2] == a->arg2)
        return TRUE;
    return FALSE;
}

static int PrefilterSetupCoverage2(SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(sgh, DETECT_COVERAGE2,
            PrefilterPacketCoverage2Set,
            PrefilterPacketCoverage2Compare,
            PrefilterPacketCoverage2Match);
}

static _Bool PrefilterCoverage2IsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_COVERAGE2:
                return TRUE;
        }
    }
    return FALSE;
}

#ifdef UNITTESTS

/**
 * \test DetectCoverage2ParseTest01 is a test for setting up an valid coverage2 value.
 */

static int DetectCoverage2ParseTest01 (void)
{
    DetectCoverage2Data *coverage2d = DetectCoverage2Parse("10");

    FAIL_IF_NULL(coverage2d);
    FAIL_IF_NOT(coverage2d->arg1 == 10);
    FAIL_IF_NOT(coverage2d->mode == DETECT_COVERAGE2_EQ);

    DetectCoverage2Free(coverage2d);

    PASS;
}

/**
 * \test DetectCoverage2ParseTest02 is a test for setting up an valid coverage2 value with
 *       "<" operator.
 */

static int DetectCoverage2ParseTest02 (void)
{
    DetectCoverage2Data *coverage2d = DetectCoverage2Parse("<10");

    FAIL_IF_NULL(coverage2d);
    FAIL_IF_NOT(coverage2d->arg1 == 10);
    FAIL_IF_NOT(coverage2d->mode == DETECT_COVERAGE2_LT);

    DetectCoverage2Free(coverage2d);

    PASS;
}

/**
 * \test DetectCoverage2ParseTest03 is a test for setting up an valid coverage2 values with
 *       "-" operator.
 */

static int DetectCoverage2ParseTest03 (void)
{
    DetectCoverage2Data *coverage2d = DetectCoverage2Parse("1-2");

    FAIL_IF_NULL(coverage2d);
    FAIL_IF_NOT(coverage2d->arg1 == 1);
    FAIL_IF_NOT(coverage2d->mode == DETECT_COVERAGE2_RA);

    DetectCoverage2Free(coverage2d);

    PASS;
}

/**
 * \test DetectCoverage2ParseTest04 is a test for setting up an valid coverage2 value with
 *       ">" operator and include spaces arround the given values.
 */

static int DetectCoverage2ParseTest04 (void)
{
    DetectCoverage2Data *coverage2d = DetectCoverage2Parse(" > 10 ");

    FAIL_IF_NULL(coverage2d);
    FAIL_IF_NOT(coverage2d->arg1 == 10);
    FAIL_IF_NOT(coverage2d->mode == DETECT_COVERAGE2_GT);

    DetectCoverage2Free(coverage2d);

    PASS;
}

/**
 * \test DetectCoverage2ParseTest05 is a test for setting up an valid coverage2 values with
 *       "-" operator and include spaces arround the given values.
 */

static int DetectCoverage2ParseTest05 (void)
{
    DetectCoverage2Data *coverage2d = DetectCoverage2Parse(" 1 - 2 ");

    FAIL_IF_NULL(coverage2d);
    FAIL_IF_NOT(coverage2d->arg1 == 1);
    FAIL_IF_NOT(coverage2d->arg2 == 2);
    FAIL_IF_NOT(coverage2d->mode == DETECT_COVERAGE2_RA);

    DetectCoverage2Free(coverage2d);

    PASS;
}

/**
 * \test DetectCoverage2ParseTest06 is a test for setting up an valid coverage2 values with
 *       invalid "=" operator and include spaces arround the given values.
 */

static int DetectCoverage2ParseTest06 (void)
{
    DetectCoverage2Data *coverage2d = DetectCoverage2Parse(" 1 = 2 ");
    FAIL_IF_NOT_NULL(coverage2d);
    PASS;
}

/**
 * \test DetectCoverage2ParseTest07 is a test for setting up an valid coverage2 values with
 *       invalid "<>" operator and include spaces arround the given values.
 */

static int DetectCoverage2ParseTest07 (void)
{
    DetectCoverage2Data *coverage2d = DetectCoverage2Parse(" 1<>2 ");
    FAIL_IF_NOT_NULL(coverage2d);
    PASS;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectCoverage2
 */
void DetectCoverage2RegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectCoverage2ParseTest01", DetectCoverage2ParseTest01);
    UtRegisterTest("DetectCoverage2ParseTest02", DetectCoverage2ParseTest02);
    UtRegisterTest("DetectCoverage2ParseTest03", DetectCoverage2ParseTest03);
    UtRegisterTest("DetectCoverage2ParseTest04", DetectCoverage2ParseTest04);
    UtRegisterTest("DetectCoverage2ParseTest05", DetectCoverage2ParseTest05);
    UtRegisterTest("DetectCoverage2ParseTest06", DetectCoverage2ParseTest06);
    UtRegisterTest("DetectCoverage2ParseTest07", DetectCoverage2ParseTest07);
#endif /* UNITTESTS */
}
