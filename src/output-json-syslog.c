/* Copyright (C) 2018-2021 Open Information Security Foundation
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
 * TODO: Update \author in this file and in output-json-syslog.h.
 * TODO: Remove SCLogNotice statements, or convert to debug.
 * TODO: Implement your app-layers logging.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Implement JSON/eve logging app-layer Syslog.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "util-buffer.h"
#include "util-debug.h"
#include "util-byte.h"

#include "output.h"
#include "output-json.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-syslog.h"
#include "output-json-syslog.h"
#include "rust.h"

typedef struct LogSyslogFileCtx_ {
    uint32_t    flags;
    OutputJsonCtx *eve_ctx;
} LogSyslogFileCtx;

typedef struct LogSyslogLogThread_ {
    LogSyslogFileCtx *sysloglog_ctx;
    OutputJsonThreadCtx *ctx;
} LogSyslogLogThread;

static int JsonSyslogLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    SCLogNotice("JsonSyslogLogger");
    LogSyslogLogThread *thread = thread_data;

    JsonBuilder *js = CreateEveHeader(
            p, LOG_DIR_PACKET, "syslog", NULL, thread->sysloglog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    jb_open_object(js, "syslog");
    if (!rs_syslog_logger_log(tx, js)) {
        goto error;
    }
    jb_close(js);

    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    return TM_ECODE_OK;

error:
    jb_free(js);
    return TM_ECODE_FAILED;
}

static void OutputSyslogLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogSyslogFileCtx *sysloglog_ctx = (LogSyslogFileCtx *)output_ctx->data;
    SCFree(sysloglog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputSyslogLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogSyslogFileCtx *sysloglog_ctx = SCCalloc(1, sizeof(*sysloglog_ctx));
    if (unlikely(sysloglog_ctx == NULL)) {
        return result;
    }
    sysloglog_ctx->eve_ctx = ajt;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(sysloglog_ctx);
        return result;
    }
    output_ctx->data = sysloglog_ctx;
    output_ctx->DeInit = OutputSyslogLogDeInitCtxSub;

    SCLogNotice("Syslog log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_SYSLOG);
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_SYSLOG);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonSyslogLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogSyslogLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogSyslog.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->sysloglog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->sysloglog_ctx->eve_ctx);
    if (!thread->ctx) {
        goto error_exit;
    }
    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonSyslogLogThreadDeinit(ThreadVars *t, void *data)
{
    LogSyslogLogThread *thread = (LogSyslogLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonSyslogLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_SYSLOG, "eve-log",
        "JsonSyslogLog", "eve-log.syslog",
        OutputSyslogLogInitSub, ALPROTO_SYSLOG, JsonSyslogLogger,
        JsonSyslogLogThreadInit, JsonSyslogLogThreadDeinit, NULL);

    SCLogNotice("Syslog JSON logger registered.");
}
