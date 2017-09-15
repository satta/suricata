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
 * TODO: Update the \author in this file and detect-gopher-buffer.h.
 * TODO: Update description in the \file section below.
 * TODO: Remove SCLogNotice statements or convert to debug.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Set up of the "gopher_buffer" keyword to allow content
 * inspections on the decoded gopher application layer buffers.
 */

#include "suricata-common.h"
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-content-inspection.h"
#include "app-layer-gopher.h"
#include "detect-gopher-buffer.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-mpm.h"

static int DetectGopherBufferSetup(DetectEngineCtx *, Signature *, const char *);
static int DetectEngineInspectGopherBuffer(ThreadVars *tv,
    DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
    const Signature *s, const SigMatchData *smd,
    Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id);
static void DetectGopherBufferRegisterTests(void);
static int g_gopher_buffer_id = 0;

static void PrefilterTxGopherBuffer(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;
    const GopherTransaction *gopher_tx = txv;

    if (gopher_tx->response_buffer == NULL)
        return;

    const uint8_t *buffer = (const uint8_t *) gopher_tx->response_buffer;

    if (gopher_tx->response_buffer_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                &det_ctx->mtcu, &det_ctx->pmq, buffer,
                gopher_tx->response_buffer_len);
    }
}

static int PrefilterTxGopherBufferRegister(SigGroupHead *sgh, MpmCtx *mpm_ctx)
{
    SCEnter();

    int r = PrefilterAppendTxEngine(sgh, PrefilterTxGopherBuffer,
        ALPROTO_GOPHER, 0,
        mpm_ctx, NULL, "gopher_buffer (response)");
    return r;
}

void DetectGopherBufferRegister(void)
{
    sigmatch_table[DETECT_AL_GOPHER_BUFFER].name = "gopher_buffer";
    sigmatch_table[DETECT_AL_GOPHER_BUFFER].desc =
        "Gopher content modififier to match on the gopher buffers";
    sigmatch_table[DETECT_AL_GOPHER_BUFFER].Setup = DetectGopherBufferSetup;
    sigmatch_table[DETECT_AL_GOPHER_BUFFER].RegisterTests =
        DetectGopherBufferRegisterTests;

    sigmatch_table[DETECT_AL_GOPHER_BUFFER].flags |= SIGMATCH_NOOPT;

    DetectAppLayerMpmRegister("gopher_buffer", SIG_FLAG_TOCLIENT, 2,
            PrefilterTxGopherBufferRegister);

    /* register inspect engines */
    DetectAppLayerInspectEngineRegister("gopher_buffer",
            ALPROTO_GOPHER, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectGopherBuffer);
    DetectAppLayerInspectEngineRegister("gopher_buffer",
            ALPROTO_GOPHER, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectGopherBuffer);

    g_gopher_buffer_id = DetectBufferTypeGetByName("gopher_buffer");

    SCLogNotice("Gopher application layer detect registered.");
}

static int DetectGopherBufferSetup(DetectEngineCtx *de_ctx, Signature *s,
    const char *str)
{
    s->init_data->list = g_gopher_buffer_id;

    if (DetectSignatureSetAppProto(s, ALPROTO_GOPHER) != 0)
        return -1;

    return 0;
}

static int DetectEngineInspectGopherBuffer(ThreadVars *tv,
    DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
    const Signature *s, const SigMatchData *smd,
    Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    GopherTransaction *tx = (GopherTransaction *)txv;
    int ret = 0;

    if (flags & STREAM_TOSERVER && tx->request_item != NULL) {
        ret = DetectEngineContentInspection(de_ctx, det_ctx, s, smd,
            f, (uint8_t *) tx->request_item, strlen(tx->request_item), 0,
            DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE, NULL);
    }
    else if (flags & STREAM_TOCLIENT && tx->response_buffer != NULL) {
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

static int DetectGopherBufferTest(void)
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
        "gopher_buffer; content:\"World!\"; "
        "sid:1; rev:1;)");
    FAIL_IF_NULL(s);

    /* This rule should not match. */
    s = DetectEngineAppendSig(de_ctx,
        "alert tcp any any -> any any ("
        "msg:\"GOPHER Test Rule\"; "
        "gopher_buffer; content:\"W0rld!\"; "
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

static void DetectGopherBufferRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectGopherBufferTest", DetectGopherBufferTest);
#endif /* UNITTESTS */
}
