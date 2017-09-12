/* Copyright (C) 2017 Open Information Security Foundation
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
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "conf.h"

#include "threads.h"
#include "tm-threads.h"
#include "threadvars.h"
#include "util-debug.h"

#include "output.h"
#include "output-json.h"
#include "output-json-udplite.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-print.h"
#include "util-logopenfile.h"
#include "util-time.h"
#include "util-buffer.h"

#define MODULE_NAME "JsonUDPLitePacketLog"

#ifdef HAVE_LIBJANSSON

typedef struct JsonUDPLitePacketOutputCtx_ {
    LogFileCtx *file_ctx;
    uint8_t flags;
} JsonUDPLitePacketOutputCtx;

typedef struct JsonUDPLitePacketLogThread_ {
    JsonUDPLitePacketOutputCtx *UDPLite_ctx;
    MemBuffer *buffer;
} JsonUDPLitePacketLogThread;

#define OUTPUT_BUFFER_SIZE 65535

static TmEcode JsonUDPLitePacketLogThreadInit(ThreadVars *t,
        const void *initdata, void **data)
{
    JsonUDPLitePacketLogThread *aft = SCMalloc(sizeof(JsonUDPLitePacketLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(*aft));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for EveLogUDPLitePacket.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /** Use the Ouptut Context (file pointer and mutex) */
    aft->UDPLite_ctx = ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode JsonUDPLitePacketLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonUDPLitePacketLogThread *aft = (JsonUDPLitePacketLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);

    /* clear memory */
    memset(aft, 0, sizeof(*aft));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void JsonUDPLitePacketOutputCtxFree(JsonUDPLitePacketOutputCtx *UDPLite_ctx)
{
    if (UDPLite_ctx != NULL) {
        if (UDPLite_ctx->file_ctx != NULL)
            LogFileFreeCtx(UDPLite_ctx->file_ctx);
        SCFree(UDPLite_ctx);
    }
}

static void JsonUDPLitePacketLogDeInitCtx(OutputCtx *output_ctx)
{
    JsonUDPLitePacketOutputCtx *UDPLite_ctx = output_ctx->data;
    JsonUDPLitePacketOutputCtxFree(UDPLite_ctx);
    SCFree(output_ctx);
}

static void JsonUDPLitePacketLogDeInitCtxSub(OutputCtx *output_ctx)
{
    JsonUDPLitePacketOutputCtx *UDPLite_ctx = output_ctx->data;
    SCFree(UDPLite_ctx);
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    SCFree(output_ctx);
}

#define DEFAULT_LOG_FILENAME "UDPLite-packet.json"

static OutputCtx *JsonUDPLitePacketLogInitCtx(ConfNode *conf)
{
    JsonUDPLitePacketOutputCtx *UDPLite_ctx = SCCalloc(1, sizeof(*UDPLite_ctx));
    if (UDPLite_ctx == NULL)
        return NULL;

    UDPLite_ctx->file_ctx = LogFileNewCtx();
    if (UDPLite_ctx->file_ctx == NULL) {
        JsonUDPLitePacketOutputCtxFree(UDPLite_ctx);
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, UDPLite_ctx->file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        JsonUDPLitePacketOutputCtxFree(UDPLite_ctx);
        return NULL;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        JsonUDPLitePacketOutputCtxFree(UDPLite_ctx);
        return NULL;
    }

    output_ctx->data = UDPLite_ctx;
    output_ctx->DeInit = JsonUDPLitePacketLogDeInitCtx;
    return output_ctx;
}

static OutputCtx *JsonUDPLitePacketLogInitCtxSub(ConfNode *conf,
        OutputCtx *parent_ctx)
{
    AlertJsonThread *ajt = parent_ctx->data;

    JsonUDPLitePacketOutputCtx *UDPLite_ctx = SCCalloc(1, sizeof(*UDPLite_ctx));
    if (UDPLite_ctx == NULL)
        return NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        JsonUDPLitePacketOutputCtxFree(UDPLite_ctx);
        return NULL;
    }

    UDPLite_ctx->file_ctx = ajt->file_ctx;

    output_ctx->data = UDPLite_ctx;
    output_ctx->DeInit = JsonUDPLitePacketLogDeInitCtxSub;
    return output_ctx;
}

/**
 * \brief The log function that is called for each that passed the
 *     condition.
 *
 * \param tv    Pointer the current thread variables
 * \param data  Pointer to the droplog struct
 * \param p     Pointer the packet which is being logged
 *
 * \retval 0 on succes
 */
static int JsonUDPLitePacketLogger(ThreadVars *tv, void *thread_data,
        const Packet *p)
{
    JsonUDPLitePacketLogThread *td = thread_data;

    /* Creates a JSON root object with an event-type of
     * "UDPLite-packet". */
    json_t *js = CreateJSONHeader((Packet *)p, 0, "udplite");
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    json_t *tjs = json_object();
    if (unlikely(tjs == NULL)) {
        json_decref(js);
        return TM_ECODE_OK;
    }

    /* Reset the re-used buffer. */
    MemBufferReset(td->buffer);

    if (p->udplitehdr) {
        json_object_set_new(tjs, "coverage", json_integer(ntohs(p->udplitehdr->checksum_coverage)));
        json_object_set_new(tjs, "checksum", json_integer(ntohs(p->udplitehdr->checksum)));
        json_object_set_new(tjs, "src_port", json_integer(ntohs(p->udplitehdr->srcp)));
        json_object_set_new(tjs, "dst_port", json_integer(ntohs(p->udplitehdr->dstp)));
    }

    /* Add the tjs object to the root object. */
    json_object_set_new(js, "udplite", tjs);

    /* Output the buffer to the log destination. */
    OutputJSONBuffer(js, td->UDPLite_ctx->file_ctx, &td->buffer);

    /* Free the json object. */
    json_decref(js);

    return TM_ECODE_OK;
}


/**
 * \brief Check if this packet should be logged or not.
 *
 * \retval bool TRUE or FALSE
 */
static int JsonUDPLitePacketLogCondition(ThreadVars *tv, const Packet *p)
{
    return (p->proto == 136);
}

void JsonUDPLitePacketLogRegister(void)
{
    OutputRegisterPacketModule(LOGGER_JSON_DROP, MODULE_NAME,
        "json-udplite-log", JsonUDPLitePacketLogInitCtx,
        JsonUDPLitePacketLogger, JsonUDPLitePacketLogCondition,
        JsonUDPLitePacketLogThreadInit, JsonUDPLitePacketLogThreadDeinit,
        NULL);
    OutputRegisterPacketSubModule(LOGGER_JSON_DROP, "eve-log", MODULE_NAME,
        "eve-log.udplite", JsonUDPLitePacketLogInitCtxSub,
        JsonUDPLitePacketLogger, JsonUDPLitePacketLogCondition,
        JsonUDPLitePacketLogThreadInit, JsonUDPLitePacketLogThreadDeinit,
        NULL);
}

#else

void JsonUDPLitePacketLogRegister(void)
{
}

#endif
