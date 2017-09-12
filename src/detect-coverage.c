/* Copyright (C) 2015-2016 Open Information Security Foundation
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
 * \author XXX Yourname <youremail@yourdomain>
 *
 * XXX Short description of the purpose of this keyword
 */

#include "suricata-common.h"
#include "util-unittest.h"

#include "detect-parse.h"
#include "detect-engine.h"

#include "detect-coverage.h"

/**
 * \brief Regex for parsing our keyword options
 */
#define PARSE_REGEX  "^\\s*([0-9]*)?\\s*([<>=-]+)?\\s*([0-9]+)?\\s*$"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

/* Prototypes of functions registered in DetectCoverageRegister below */
static int DetectCoverageMatch (ThreadVars *, DetectEngineThreadCtx *,
        Packet *, const Signature *, const SigMatchCtx *);
static int DetectCoverageSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectCoverageFree (void *);
static void DetectCoverageRegisterTests (void);

/**
 * \brief Registration function for coverage: keyword
 *
 * This function is called once in the 'lifetime' of the engine.
 */
void DetectCoverageRegister(void) {
    /* keyword name: this is how the keyword is used in a rule */
    sigmatch_table[DETECT_COVERAGE].name = "coverage";
    /* description: listed in "suricata --list-keywords=all" */
    sigmatch_table[DETECT_COVERAGE].desc = "match a checksum coverage in UDP-Lite pkts";
    /* link to further documentation of the keyword. Normally on the Suricata redmine/wiki */
    sigmatch_table[DETECT_COVERAGE].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Developers_Guide";
    /* match function is called when the signature is inspected on a packet */
    sigmatch_table[DETECT_COVERAGE].Match = DetectCoverageMatch;
    /* setup function is called during signature parsing, when the coverage
     * keyword is encountered in the rule */
    sigmatch_table[DETECT_COVERAGE].Setup = DetectCoverageSetup;
    /* free function is called when the detect engine is freed. Normally at
     * shutdown, but also during rule reloads. */
    sigmatch_table[DETECT_COVERAGE].Free = DetectCoverageFree;
    /* registers unittests into the system */
    sigmatch_table[DETECT_COVERAGE].RegisterTests = DetectCoverageRegisterTests;

    /* set up the PCRE for keyword parsing */
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);
}

static inline int CovMatch(const uint16_t pcov, const uint8_t mode,
                           const uint16_t cov1, const uint16_t cov2)
{
  SCLogDebug("cmp %d %d %d", pcov, cov1, cov2);
    if (mode == DETECT_COVERAGE_EQ && pcov == cov1)
        return 1;
    else if (mode == DETECT_COVERAGE_LT && pcov < cov1)
        return 1;
    else if (mode == DETECT_COVERAGE_GT && pcov > cov1)
        return 1;
    else if (mode == DETECT_COVERAGE_RA && (pcov >= cov1 && pcov <= cov2))
        return 1;

    return 0;
}

/**
 * \brief This function is used to match COVERAGE rule option on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch with context that we will cast into DetectCoverageData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectCoverageMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p,
                                const Signature *s, const SigMatchCtx *ctx)
{
    int ret = 0;
    const DetectCoverageData *coveraged = (const DetectCoverageData *) ctx;

    if (PKT_IS_PSEUDOPKT(p)) {
        return 0;
    }

    uint16_t pcov;
    if (PKT_IS_IPV4(p)) {
        if (!p->udplitehdr) {
          return 0;
        }
        pcov = ntohs(p->udplitehdr->checksum_coverage);
    } else {
        SCLogDebug("packet is of not IPv4 or IPv6");
        return ret;
    }

    return CovMatch(pcov, coveraged->mode, coveraged->csum1, coveraged->csum2);
}

/**
 * \brief This function is used to parse coverage options passed via coverage: keyword
 *
 * \param coveragestr Pointer to the user provided coverage options
 *
 * \retval coveraged pointer to DetectCoverageData on success
 * \retval NULL on failure
 */
static DetectCoverageData *DetectCoverageParse (const char *covstr)
{
    DetectCoverageData *covd = NULL;
    char *arg1 = NULL;
    char *arg2 = NULL;
    char *arg3 = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, covstr, strlen(covstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 2 || ret > 4) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        goto error;
    }
    const char *str_ptr;

    res = pcre_get_substring((char *) covstr, ov, MAX_SUBSTRINGS, 1, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }
    arg1 = (char *) str_ptr;
    SCLogDebug("Arg1 \"%s\"", arg1);

    if (ret >= 3) {
        res = pcre_get_substring((char *) covstr, ov, MAX_SUBSTRINGS, 2, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }
        arg2 = (char *) str_ptr;
        SCLogDebug("Arg2 \"%s\"", arg2);

        if (ret >= 4) {
            res = pcre_get_substring((char *) covstr, ov, MAX_SUBSTRINGS, 3, &str_ptr);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                goto error;
            }
            arg3 = (char *) str_ptr;
            SCLogDebug("Arg3 \"%s\"", arg3);
        }
    }

    covd = SCMalloc(sizeof (DetectCoverageData));
    if (unlikely(covd == NULL))
        goto error;
    covd->csum1 = 0;
    covd->csum2 = 0;

    if (arg2 != NULL) {
        /*set the values*/
        switch(arg2[0]) {
            case '<':
                if (arg3 == NULL)
                    goto error;

                covd->mode = DETECT_COVERAGE_LT;
                covd->csum1 = (uint8_t) atoi(arg3);

                SCLogDebug("coverage is %"PRIu8"",covd->csum1);
                if (strlen(arg1) > 0)
                    goto error;

                break;
            case '>':
                if (arg3 == NULL)
                    goto error;

                covd->mode = DETECT_COVERAGE_GT;
                covd->csum1 = (uint8_t) atoi(arg3);

                SCLogDebug("coverage is %"PRIu8"",covd->csum1);
                if (strlen(arg1) > 0)
                    goto error;

                break;
            case '-':
                if (arg1 == NULL || strlen(arg1)== 0)
                    goto error;
                if (arg3 == NULL || strlen(arg3)== 0)
                    goto error;

                covd->mode = DETECT_COVERAGE_RA;
                covd->csum1 = (uint8_t) atoi(arg1);

                covd->csum2 = (uint8_t) atoi(arg3);
                SCLogDebug("coverage is %"PRIu8" to %"PRIu8"",covd->csum1, covd->csum2);
                if (covd->csum1 >= covd->csum2) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid coverage range. ");
                    goto error;
                }
                break;
            default:
                covd->mode = DETECT_COVERAGE_EQ;

                if ((arg2 != NULL && strlen(arg2) > 0) ||
                    (arg3 != NULL && strlen(arg3) > 0) ||
                    (arg1 == NULL ||strlen(arg1) == 0))
                    goto error;

                covd->csum1 = (uint8_t) atoi(arg1);
                break;
        }
    } else {
        covd->mode = DETECT_COVERAGE_EQ;

        if ((arg3 != NULL && strlen(arg3) > 0) ||
            (arg1 == NULL ||strlen(arg1) == 0))
            goto error;

        covd->csum1 = (uint8_t) atoi(arg1);
    }

    SCFree(arg1);
    SCFree(arg2);
    SCFree(arg3);
    return covd;

error:
    if (covd)
        SCFree(covd);
    if (arg1)
        SCFree(arg1);
    if (arg2)
        SCFree(arg2);
    if (arg3)
        SCFree(arg3);
    return NULL;
}

/**
 * \brief parse the options from the 'coverage' keyword in the rule into
 *        the Signature data structure.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param coveragestr pointer to the user provided coverage options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectCoverageSetup (DetectEngineCtx *de_ctx, Signature *s, const char *coveragestr)
{
    DetectCoverageData *coveraged = NULL;
    SigMatch *sm = NULL;

    SCLogDebug("setup");

    coveraged = DetectCoverageParse(coveragestr);
    if (coveraged == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_COVERAGE;
    sm->ctx = (void *)coveraged;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (coveraged != NULL)
        DetectCoverageFree(coveraged);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectCoverageData
 *
 * \param ptr pointer to DetectCoverageData
 */
static void DetectCoverageFree(void *ptr) {
    DetectCoverageData *coveraged = (DetectCoverageData *)ptr;

    /* do more specific cleanup here, if needed */

    SCFree(coveraged);
}

/**
 * \test description of the test
 */

void DetectCoverageRegisterTests(void) {
}
