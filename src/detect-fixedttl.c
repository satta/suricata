/* Copyright (C) 2015-2017 Open Information Security Foundation
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

#include "host.h"
#include "host-storage.h"
#include "detect-parse.h"
#include "detect-engine.h"

#include "detect-fixedttl.h"

static int ttl_storage_id = -1; /**< host storage id for thresholds */

int TTLHostStorageId(void);
void TTLInit(void);

int TTLHostStorageId(void)
{
    return ttl_storage_id;
}

void TTLInit(void)
{
    ttl_storage_id = HostStorageRegister("fixed-ttl", sizeof(void *), NULL, free);
    if (ttl_storage_id == -1) {
        SCLogError(SC_ERR_HOST_INIT, "Can't initiate host storage for TTLs");
        exit(EXIT_FAILURE);
    }
}

/* Prototypes of functions registered in DetectFixedttlRegister below */
static int DetectFixedttlMatch (ThreadVars *, DetectEngineThreadCtx *,
        Packet *, const Signature *, const SigMatchCtx *);
static int DetectFixedttlSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectFixedttlFree (void *);

/**
 * \brief Registration function for fixedttl: keyword
 *
 * This function is called once in the 'lifetime' of the engine.
 */
void DetectFixedttlRegister(void) {
    /* keyword name: this is how the keyword is used in a rule */
    sigmatch_table[DETECT_FIXEDTTL].name = "fixed-ttl";
    /* description: listed in "suricata --list-keywords=all" */
    sigmatch_table[DETECT_FIXEDTTL].desc = "Raise an alert if TTL changes for an internal host.";
    /* link to further documentation of the keyword. Normally on the Suricata redmine/wiki */
    sigmatch_table[DETECT_FIXEDTTL].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Developers_Guide";
    /* match function is called when the signature is inspected on a packet */
    sigmatch_table[DETECT_FIXEDTTL].Match = DetectFixedttlMatch;
    /* setup function is called during signature parsing, when the fixedttl
     * keyword is encountered in the rule */
    sigmatch_table[DETECT_FIXEDTTL].Setup = DetectFixedttlSetup;
    /* free function is called when the detect engine is freed. Normally at
     * shutdown, but also during rule reloads. */
    sigmatch_table[DETECT_FIXEDTTL].Free = DetectFixedttlFree;
    /* registers unittests into the system */
    sigmatch_table[DETECT_FIXEDTTL].RegisterTests = NULL;
    sigmatch_table[DETECT_FIXEDTTL].flags = SIGMATCH_NOOPT;

    TTLInit();
}

/**
 * \brief This function is used to match FIXEDTTL rule option on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch with context that we will cast into DetectFixedttlData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectFixedttlMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p,
                                const Signature *s, const SigMatchCtx *ctx)
{
    int ret = 0;

    if (PKT_IS_PSEUDOPKT(p)) {
        return 0;
    }

    if (PKT_IS_IPV4(p)) {
        Host *h = HostGetHostFromHash(&p->src);
        uint8_t ttlval = IPV4_GET_RAW_IPTTL(p->ip4h);
        if (h) {
            uint8_t *ptr = (uint8_t *) HostGetStorageById(h, TTLHostStorageId());
            if (!ptr) {
              int err = 0;
              ptr = SCMalloc(sizeof(uint8_t));
              *ptr = ttlval;
              if ((err = HostSetStorageById(h, TTLHostStorageId(), ptr))) {
                SCLogError(err, "Can't set TTL value in storage");
                HostRelease(h);
                return 0;
              }
            } else {
              if (*ptr != ttlval) {
                *ptr = ttlval;
                HostRelease(h);
                return 1;
              }
            }
            HostRelease(h);
        }
    } else {
        SCLogDebug("packet is not IPv4");
        return ret;
    }

    return ret;
}

/**
 * \brief parse the options from the 'fixedttl' keyword in the rule into
 *        the Signature data structure.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param fixedttlstr pointer to the user provided fixedttl options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectFixedttlSetup (DetectEngineCtx *de_ctx, Signature *s, const char *fixedttlstr)
{
    DetectFixedttlData *fixedttld = NULL;
    SigMatch *sm = NULL;

    fixedttld = SCMalloc(sizeof (DetectFixedttlData));
    if (fixedttld == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FIXEDTTL;
    sm->ctx = (void *)fixedttld;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (fixedttld != NULL)
        DetectFixedttlFree(fixedttld);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectFixedttlData
 *
 * \param ptr pointer to DetectFixedttlData
 */
static void DetectFixedttlFree(void *ptr) {
    DetectFixedttlData *fixedttld = (DetectFixedttlData *)ptr;

    /* do more specific cleanup here, if needed */

    SCFree(fixedttld);
}
