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

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 */

#ifndef __APP_LAYER_GOPHER_H__
#define __APP_LAYER_GOPHER_H__

#include "detect-engine-state.h"

#include "queue.h"

void RegisterGopherParsers(void);
void GopherParserRegisterTests(void);

typedef struct GopherTransaction_ {

    uint64_t tx_id;             /*<< Internal transaction ID. */

    AppLayerDecoderEvents *decoder_events; /*<< Application layer
                                            * events that occurred
                                            * while parsing this
                                            * transaction. */

    uint8_t *request_buffer;
    uint32_t request_buffer_len;

    /* flags indicating which loggers that have logged */
    uint32_t logged;

    uint8_t *response_buffer;
    uint32_t response_buffer_len;

    uint8_t response_done; /*<< Flag to be set when the response is
                            * seen. */

    DetectEngineState *de_state;

    char *request_item;

    TAILQ_ENTRY(GopherTransaction_) next;

} GopherTransaction;

typedef struct GopherState_ {

    TAILQ_HEAD(, GopherTransaction_) tx_list; /**< List of Gopher transactions
                                       * associated with this
                                       * state. */

    uint64_t transaction_max; /**< A count of the number of
                               * transactions created.  The
                               * transaction ID for each transaction
                               * is allocted by incrementing this
                               * value. */

    uint16_t events; /**< Number of application layer events created
                      * for this state. */

} GopherState;

#endif /* __APP_LAYER_GOPHER_H__ */
