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

/*
 * TODO: Update the \author in this file and detect-gopher-listing.h.
 * TODO: Update description in the \file section below.
 * TODO: Remove SCLogNotice statements or convert to debug.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Set up of the "gopher_listing" keyword to allow content
 * inspections on the decoded gopher application layer buffers.
 */

#include "suricata-common.h"
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-content-inspection.h"
#include "app-layer-gopher.h"
#include "detect-gopher-listing.h"

static int DetectGopherListingSetup(DetectEngineCtx *, Signature *, const char *);
static int DetectEngineInspectGopherListing(ThreadVars *tv,
    DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
    const Signature *s, const SigMatchData *smd,
    Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id);
static void DetectGopherListingRegisterTests(void);
static int g_gopher_listing_id = 0;

void DetectGopherListingRegister(void)
{
    sigmatch_table[DETECT_AL_GOPHER_LISTING].name = "gopher_listing";
    sigmatch_table[DETECT_AL_GOPHER_LISTING].desc =
        "Gopher content modififier to match on the gopher buffers only on listings";
    sigmatch_table[DETECT_AL_GOPHER_LISTING].Setup = DetectGopherListingSetup;
    sigmatch_table[DETECT_AL_GOPHER_LISTING].RegisterTests =
        DetectGopherListingRegisterTests;

    sigmatch_table[DETECT_AL_GOPHER_LISTING].flags |= SIGMATCH_NOOPT;

    /* register inspect engines */
    DetectAppLayerInspectEngineRegister("gopher_listing",
            ALPROTO_GOPHER, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectGopherListing);
    DetectAppLayerInspectEngineRegister("gopher_listing",
            ALPROTO_GOPHER, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectGopherListing);

    g_gopher_listing_id = DetectBufferTypeGetByName("gopher_listing");

    SCLogNotice("Gopher application layer detect registered.");
}

static int DetectGopherListingSetup(DetectEngineCtx *de_ctx, Signature *s,
    const char *str)
{
    s->init_data->list = g_gopher_listing_id;

    if (DetectSignatureSetAppProto(s, ALPROTO_GOPHER) != 0)
        return -1;

    return 0;
}

static int DetectEngineInspectGopherListing(ThreadVars *tv,
    DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
    const Signature *s, const SigMatchData *smd,
    Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    GopherTransaction *tx = (GopherTransaction *)txv;
    int ret = 0;
    bool is_listing = (strcmp(tx->request_item, "<directory listing>") == 0);

    if (is_listing && (flags & STREAM_TOCLIENT) && tx->response_buffer != NULL) {
        ret = DetectEngineContentInspection(de_ctx, det_ctx, s, smd,
            f, tx->response_buffer, tx->response_buffer_len, 0,
            DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE, NULL);
    }

    SCLogNotice("Returning %d.", ret);
    return ret;
}

#ifdef UNITTESTS

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "app-layer-parser.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "flow-util.h"
#include "stream-tcp.h"

static int DetectGopherListingTest(void)
{
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    Flow f;
    Packet *p;
    TcpSession tcp;
    ThreadVars tv;
    Signature *s;

    uint8_t request[] = "Hello World!";

    /* Setup flow. */
    memset(&f, 0, sizeof(Flow));
    memset(&tcp, 0, sizeof(TcpSession));
    memset(&tv, 0, sizeof(ThreadVars));
    p = UTHBuildPacket(request, sizeof(request), IPPROTO_TCP);
    FLOW_INITIALIZE(&f);
    f.alproto = ALPROTO_GOPHER;
    f.protoctx = (void *)&tcp;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;
    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    /* This rule should match. */
    s = DetectEngineAppendSig(de_ctx,
        "alert tcp any any -> any any ("
        "msg:\"GOPHER Test Rule\"; "
        "gopher_listing; content:\"World!\"; "
        "sid:1; rev:1;)");
    FAIL_IF_NULL(s);

    /* This rule should not match. */
    s = DetectEngineAppendSig(de_ctx,
        "alert tcp any any -> any any ("
        "msg:\"GOPHER Test Rule\"; "
        "gopher_listing; content:\"W0rld!\"; "
        "sid:2; rev:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_GOPHER,
                        STREAM_TOSERVER, request, sizeof(request));
    FLOWLOCK_UNLOCK(&f);

    /* Check that we have app-layer state. */
    FAIL_IF_NULL(f.alstate);

    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
    FAIL_IF(!PacketAlertCheck(p, 1));
    FAIL_IF(PacketAlertCheck(p, 2));

    /* Cleanup. */
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

#endif

static void DetectGopherListingRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectGopherListingTest", DetectGopherListingTest);
#endif /* UNITTESTS */
}
