/* Copyright (C) 2015 Open Information Security Foundation
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
 * TODO: Update \author in this file and app-layer-gopher.h.
 * TODO: Implement your app-layer logic with unit tests.
 * TODO: Remove SCLogNotice statements or convert to debug.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Gopher application layer detector and parser for learning and
 * gopher pruposes.
 *
 * This gopher implements a simple application layer for something
 * like the echo protocol running on port 7.
 */

#include "suricata-common.h"
#include "stream.h"
#include "conf.h"

#include "util-print.h"
#include "util-unittest.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "app-layer-gopher.h"
#include "util-streaming-buffer.h"

/* The default port to probe for echo traffic if not provided in the
 * configuration file. */
#define GOPHER_DEFAULT_PORT "70"

/* The minimum size for an echo message. For some protocols this might
 * be the size of a header. */
#define GOPHER_MIN_FRAME_LEN 2

StreamingBufferConfig sbcfg = STREAMING_BUFFER_CONFIG_INITIALIZER;

/* Enum of app-layer events for an echo protocol. Normally you might
 * have events for errors in parsing data, like unexpected data being
 * received. For echo we'll make something up, and log an app-layer
 * level alert if an empty message is received.
 *
 * Example rule:
 *
 * alert gopher any any -> any any (msg:"SURICATA Gopher empty message"; \
 *    app-layer-event:gopher.empty_message; sid:X; rev:Y;)
 */
enum {
    GOPHER_DECODER_EVENT_EMPTY_MESSAGE,
};

SCEnumCharMap gopher_decoder_event_table[] = {
    {"EMPTY_MESSAGE", GOPHER_DECODER_EVENT_EMPTY_MESSAGE},

    // event table must be NULL-terminated
    { NULL, -1 },
};

static GopherTransaction *GopherTxAlloc(GopherState *echo)
{
    GopherTransaction *tx = SCCalloc(1, sizeof(GopherTransaction));
    if (unlikely(tx == NULL)) {
        return NULL;
    }

    /* Increment the transaction ID on the state each time one is
     * allocated. */
    tx->tx_id = echo->transaction_max++;

    TAILQ_INSERT_TAIL(&echo->tx_list, tx, next);

    return tx;
}

static void GopherTxFree(void *tx)
{
    GopherTransaction *gophertx = tx;

    if (gophertx->request_buffer != NULL) {
        SCFree(gophertx->request_buffer);
    }
    gophertx->request_buffer_len = 0;

    if (gophertx->response_buffer != NULL) {
        SCFree(gophertx->response_buffer);
    }
    gophertx->response_buffer_len = 0;

    AppLayerDecoderEventsFreeEvents(&gophertx->decoder_events);

    free(gophertx->request_item);


    SCFree(tx);
}

static void *GopherStateAlloc(void)
{
    SCLogNotice("Allocating gopher state.");
    GopherState *state = SCCalloc(1, sizeof(GopherState));
    if (unlikely(state == NULL)) {
        return NULL;
    }
    TAILQ_INIT(&state->tx_list);
    state->first = true;
    return state;
}

static void GopherStateFree(void *state)
{
    GopherState *gopher_state = state;
    GopherTransaction *tx;
    SCLogNotice("Freeing gopher state.");
    while ((tx = TAILQ_FIRST(&gopher_state->tx_list)) != NULL) {
        TAILQ_REMOVE(&gopher_state->tx_list, tx, next);
        GopherTxFree(tx);
    }
    FileContainerFree(gopher_state->files_ts);
    SCFree(gopher_state);
}

static FileContainer *GopherStateGetFiles(void *state, uint8_t direction)
{
    if (state == NULL)
        return NULL;

    GopherState *gopher_state = (GopherState *)state;

    if (direction & STREAM_TOSERVER) {
        SCReturnPtr(NULL, "FileContainer");
    } else {
        SCReturnPtr(gopher_state->files_ts, "FileContainer");
    }
}

static void GopherStateTruncate(void *state, uint8_t direction)
{
    FileContainer *fc = GopherStateGetFiles(state, direction);
    if (fc != NULL) {
        SCLogDebug("truncating stream, closing files in %s direction (container %p)",
                direction & STREAM_TOCLIENT ? "STREAM_TOCLIENT" : "STREAM_TOSERVER", fc);
        FileTruncateAllOpenFiles(fc);
    }
}

/**
 * \brief Callback from the application layer to have a transaction freed.
 *
 * \param state a void pointer to the GopherState object.
 * \param tx_id the transaction ID to free.
 */
static void GopherStateTxFree(void *state, uint64_t tx_id)
{
    GopherState *echo = state;
    GopherTransaction *tx = NULL, *ttx;

    SCLogNotice("Freeing transaction %"PRIu64, tx_id);

    TAILQ_FOREACH_SAFE(tx, &echo->tx_list, next, ttx) {

        /* Continue if this is not the transaction we are looking
         * for. */
        if (tx->tx_id != tx_id) {
            continue;
        }

        /* Remove and free the transaction. */
        TAILQ_REMOVE(&echo->tx_list, tx, next);
        GopherTxFree(tx);
        return;
    }

    SCLogNotice("Transaction %"PRIu64" not found.", tx_id);
}

static int GopherStateGetEventInfo(const char *event_name, int *event_id,
    AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, gopher_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "gopher enum map table.",  event_name);
        /* This should be treated as fatal. */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static AppLayerDecoderEvents *GopherGetEvents(void *state, uint64_t tx_id)
{
    GopherState *gopher_state = state;
    GopherTransaction *tx;

    TAILQ_FOREACH(tx, &gopher_state->tx_list, next) {
        if (tx->tx_id == tx_id) {
            return tx->decoder_events;
        }
    }

    return NULL;
}

static int GopherHasEvents(void *state)
{
    GopherState *echo = state;
    return echo->events;
}

/**
 * \brief Probe the input to see if it looks like echo.
 *
 * \retval ALPROTO_GOPHER if it looks like echo, otherwise
 *     ALPROTO_UNKNOWN.
 */
static AppProto GopherProbingParser(uint8_t *input, uint32_t input_len,
    uint32_t *offset)
{
    /* Very simple test - if there is input, this is echo. */
    if (input_len < GOPHER_MIN_FRAME_LEN) {
        return ALPROTO_UNKNOWN;
    }

    if (input[0] == '/') {
      SCLogDebug("slash detected, is gopher");
      return ALPROTO_GOPHER;
    }

    if (input[0] == 0x0d && input[1] == 0x0a) {
      SCLogDebug("CRLF detected, is gopher");
      return ALPROTO_GOPHER;
    }

    SCLogNotice("Protocol not detected as ALPROTO_GOPHER.");
    return ALPROTO_UNKNOWN;
}

static int GopherParseRequest(Flow *f, void *state,
    AppLayerParserState *pstate, uint8_t *input, uint32_t input_len,
    void *local_data)
{
    GopherState *echo = state;

    SCLogNotice("Parsing gopher request: len=%"PRIu32, input_len);

    /* Likely connection closed, we can just return here. */
    if ((input == NULL || input_len == 0) &&
        AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        return 0;
    }

    /* Probably don't want to create a transaction in this case
     * either. */
    if (input == NULL || input_len == 0) {
        return 0;
    }

    GopherTransaction *tx = GopherTxAlloc(echo);
    if (unlikely(tx == NULL)) {
        SCLogNotice("Failed to allocate new Gopher tx.");
        goto end;
    }
    SCLogNotice("Allocated Gopher tx %"PRIu64".", tx->tx_id);

    /* Make a copy of the request. */
    tx->request_buffer = SCCalloc(1, input_len);
    if (unlikely(tx->request_buffer == NULL)) {
        goto end;
    }
    memcpy(tx->request_buffer, input, input_len);
    tx->request_buffer_len = input_len;

    if (tx->request_item) {
      free(tx->request_item);
    }
    tx->request_item = NULL;
    if (input_len == 2 && input[0] == 0x0d && input[1] == 0x0a) {
      SCLogDebug("Directory listing requested");
      tx->request_item = strdup("<directory listing>");
    }

    if (input_len > 3 && input[0] == '/' && input[input_len-1] == 0x0a) {
      SCLogDebug("Item requested");
      tx->request_item = calloc(input_len, sizeof(char));
      memcpy(tx->request_item, input, (input_len-2) * sizeof(uint8_t));
    }

    /* Here we check for an empty message and create an app-layer
     * event. */
    if ((input_len == 1 && tx->request_buffer[0] == '\n') ||
        (input_len == 2 && tx->request_buffer[0] == '\r')) {
        SCLogNotice("Creating event for empty message.");
        AppLayerDecoderEventsSetEventRaw(&tx->decoder_events,
            GOPHER_DECODER_EVENT_EMPTY_MESSAGE);
        echo->events++;
    }

end:
    return 0;
}

static int GopherParseResponse(Flow *f, void *state, AppLayerParserState *pstate,
    uint8_t *input, uint32_t input_len, void *local_data)
{
    GopherState *gopher_state = state;
    GopherTransaction *tx = NULL, *ttx;;

    SCLogNotice("Parsing Gopher response.");
    uint16_t flags = FileFlowToFlags(f, STREAM_TOCLIENT);

    TAILQ_FOREACH(ttx, &gopher_state->tx_list, next) {
        tx = ttx;
    }

    if (tx == NULL) {
        SCLogNotice("Failed to find transaction for response on echo state %p.",
            gopher_state);
        goto end;
    }

    SCLogNotice("Found transaction %"PRIu64" for response on echo state %p.",
        tx->tx_id, gopher_state);


    /* Likely connection closed, we can just return here. */
    if ((input == NULL || input_len == 0) &&
        AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        tx->response_done = 1;
        gopher_state->first = true;
        if (gopher_state->files_ts && gopher_state->files_ts->tail && gopher_state->files_ts->tail->state == FILE_STATE_OPENED) {
            int ret = FileCloseFile(gopher_state->files_ts, (uint8_t *) input, input_len, flags);
            if (ret != 0) {
                SCLogDebug("FileCloseFile() failed: %d", ret);
            }
                    SCLogDebug("file %s closed", tx->request_item+1);
        }
        return 0;
    }

    /* Probably don't want to create a transaction in this case
     * either. */
    if (input == NULL || input_len == 0) {
        return 0;
    }

    /* Make a copy of the response. */
    tx->response_buffer = SCRealloc(tx->response_buffer,
        (tx->response_buffer_len+input_len) * sizeof(uint8_t));
    if (unlikely(tx->response_buffer == NULL)) {
        goto end;
    }
    memcpy(tx->response_buffer+tx->response_buffer_len, input, input_len * sizeof(uint8_t));
    tx->response_buffer_len += input_len;

    if (strcmp(tx->request_item, "<directory listing>") != 0) {
      if (gopher_state->first) {
        if (gopher_state->files_ts == NULL) {
            gopher_state->files_ts = FileContainerAlloc();
            if (gopher_state->files_ts == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Could not create file container");
                exit(1);
            }
        }
        SCLogDebug("opening file %s", tx->request_item+1);

        if (FileOpenFile(gopher_state->files_ts, &sbcfg, (uint8_t *) tx->request_item+1, strlen(tx->request_item)-1,
                (uint8_t *) input, input_len, flags) == NULL) {
            SCLogDebug("FileOpenFile() failed");
            exit(1);
        }
        gopher_state->first = false;
      } else {
        int ret = FileAppendData(gopher_state->files_ts, (uint8_t *) input, input_len);
        if (ret == -2) {
            SCLogDebug("FileAppendData() - file no longer being extracted");
        } else if (ret < 0) {
            SCLogDebug("FileAppendData() failed: %d", ret);
        }
      }

    }

end:
    return 0;
}

static uint64_t GopherGetTxCnt(void *state)
{
    GopherState *echo = state;
    SCLogNotice("Current tx count is %"PRIu64".", echo->transaction_max);
    return echo->transaction_max;
}

static void *GopherGetTx(void *state, uint64_t tx_id)
{
    GopherState *echo = state;
    GopherTransaction *tx;

    SCLogNotice("Requested tx ID %"PRIu64".", tx_id);

    TAILQ_FOREACH(tx, &echo->tx_list, next) {
        if (tx->tx_id == tx_id) {
            SCLogNotice("Transaction %"PRIu64" found, returning tx object %p.",
                tx_id, tx);
            return tx;
        }
    }

    SCLogNotice("Transaction ID %"PRIu64" not found.", tx_id);
    return NULL;
}

static void GopherSetTxLogged(void *state, void *vtx, uint32_t logger)
{
    GopherTransaction *tx = (GopherTransaction *)vtx;
    tx->logged |= logger;
}

static int GopherGetTxLogged(void *state, void *vtx, uint32_t logger)
{
    GopherTransaction *tx = (GopherTransaction *)vtx;
    if (tx->logged & logger)
        return 1;

    return 0;
}

/**
 * \brief Called by the application layer.
 *
 * In most cases 1 can be returned here.
 */
static int GopherGetAlstateProgressCompletionStatus(uint8_t direction) {
    return 1;
}

/**
 * \brief Return the state of a transaction in a given direction.
 *
 * In the case of the echo protocol, the existence of a transaction
 * means that the request is done. However, some protocols that may
 * need multiple chunks of data to complete the request may need more
 * than just the existence of a transaction for the request to be
 * considered complete.
 *
 * For the response to be considered done, the response for a request
 * needs to be seen.  The response_done flag is set on response for
 * checking here.
 */
static int GopherGetStateProgress(void *tx, uint8_t direction)
{
    GopherTransaction *echotx = tx;

    SCLogNotice("Transaction progress requested for tx ID %"PRIu64
        ", direction=0x%02x", echotx->tx_id, direction);

    if (direction & STREAM_TOCLIENT && echotx->response_done) {
        return 1;
    }
    else if (direction & STREAM_TOSERVER) {
        /* For echo, just the existence of the transaction means the
         * request is done. */
        return 1;
    }

    return 0;
}

/**
 * \brief ???
 */
static DetectEngineState *GopherGetTxDetectState(void *vtx)
{
    GopherTransaction *tx = vtx;
    return tx->de_state;
}

/**
 * \brief ???
 */
static int GopherSetTxDetectState(void *state, void *vtx,
    DetectEngineState *s)
{
    GopherTransaction *tx = vtx;
    tx->de_state = s;
    return 0;
}

void RegisterGopherParsers(void)
{
    const char *proto_name = "gopher";
    sbcfg.buf_size = 256;

    /* Check if Gopher TCP detection is enabled. If it does not exist in
     * the configuration file then it will be enabled by default. */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {

        SCLogNotice("Gopher TCP protocol detection enabled.");

        AppLayerProtoDetectRegisterProtocol(ALPROTO_GOPHER, proto_name);

        if (RunmodeIsUnittests()) {

            SCLogNotice("Unittest mode, registeringd default configuration.");
            AppLayerProtoDetectPPRegister(IPPROTO_TCP, GOPHER_DEFAULT_PORT,
                ALPROTO_GOPHER, 0, GOPHER_MIN_FRAME_LEN, STREAM_TOSERVER,
                GopherProbingParser, NULL);

        }
        else {

            if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
                    proto_name, ALPROTO_GOPHER, 0, GOPHER_MIN_FRAME_LEN,
                    GopherProbingParser, NULL)) {
                SCLogNotice("No echo app-layer configuration, enabling echo"
                    " detection TCP detection on port %s.",
                    GOPHER_DEFAULT_PORT);
                AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                    GOPHER_DEFAULT_PORT, ALPROTO_GOPHER, 0,
                    GOPHER_MIN_FRAME_LEN, STREAM_TOSERVER,
                    GopherProbingParser, NULL);
            }

        }

    }

    else {
        SCLogNotice("Protocol detecter and parser disabled for Gopher.");
        return;
    }

    if (AppLayerParserConfParserEnabled("udp", proto_name)) {

        SCLogNotice("Registering Gopher protocol parser.");

        /* Register functions for state allocation and freeing. A
         * state is allocated for every new Gopher flow. */
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_GOPHER,
            GopherStateAlloc, GopherStateFree);

        /* Register request parser for parsing frame from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_GOPHER,
            STREAM_TOSERVER, GopherParseRequest);

        /* Register response parser for parsing frames from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_GOPHER,
            STREAM_TOCLIENT, GopherParseResponse);

        /* Register a function to be called by the application layer
         * when a transaction is to be freed. */
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_GOPHER,
            GopherStateTxFree);

        AppLayerParserRegisterLoggerFuncs(IPPROTO_TCP, ALPROTO_GOPHER,
            GopherGetTxLogged, GopherSetTxLogged);

        /* Register a function to return the current transaction count. */
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_GOPHER,
            GopherGetTxCnt);

        AppLayerParserRegisterGetFilesFunc(IPPROTO_TCP, ALPROTO_GOPHER, GopherStateGetFiles);
        AppLayerParserRegisterTruncateFunc(IPPROTO_TCP, ALPROTO_GOPHER, GopherStateTruncate);

        /* Transaction handling. */
        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_GOPHER,
            GopherGetAlstateProgressCompletionStatus);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP,
            ALPROTO_GOPHER, GopherGetStateProgress);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_GOPHER,
            GopherGetTx);

        /* Application layer event handling. */
        AppLayerParserRegisterHasEventsFunc(IPPROTO_TCP, ALPROTO_GOPHER,
            GopherHasEvents);

        /* What is this being registered for? */
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_GOPHER,
            NULL, GopherGetTxDetectState, GopherSetTxDetectState);

        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_GOPHER,
            GopherStateGetEventInfo);
        AppLayerParserRegisterGetEventsFunc(IPPROTO_TCP, ALPROTO_GOPHER,
            GopherGetEvents);
    }
    else {
        SCLogNotice("Gopher protocol parsing disabled.");
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_GOPHER,
        GopherParserRegisterTests);
#endif
}

#ifdef UNITTESTS
#endif

void GopherParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}
