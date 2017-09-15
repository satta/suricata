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
 * \ingroup decode
 *
 * @{
 */


/**
 * \file
 *
 * \author Sascha Steinbiss <satta@debian.org>
 *
 * Decodes UDP-Lite.
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "decode-events.h"
#include "decode-udplite.h"
#include "rust-udplite-mod-gen.h"

#include "util-unittest.h"
#include "util-debug.h"

/**
 * \brief Function to decode UDP Lite packets
 * \param tv thread vars
 * \param dtv decoder thread vars
 * \param p packet
 * \param pkt raw packet data
 * \param len length in bytes of pkt array
 * \retval TM_ECODE_OK or TM_ECODE_FAILED on serious error
 */

int DecodeUDPLITE(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                   const uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    //StatsIncr(tv, dtv->counter_udplite);

    /* Validation: make sure that the input data is big enough to hold
     *             the header */
    if (len < sizeof(UdpliteHdr)) {
        /* in case of errors, we set events. Events are defined in
         * decode-events.h, and are then exposed to the detection
         * engine through detect-engine-events.h */
        //ENGINE_SET_EVENT(p,UDPLITE_HEADER_TOO_SMALL);
        return TM_ECODE_FAILED;
    }
    UdpliteHdr *myHdr = (UdpliteHdr *)pkt;

    int32_t sport = rs_udplite_decode_sport(pkt, len);
    if (sport < 0) {
    //  ENGINE_SET_INVALID_EVENT(p, UDPLITE_HEADER_TOO_SMALL);
      return TM_ECODE_FAILED;
    }
    int32_t dport = rs_udplite_decode_dport(pkt, len);
    if (dport < 0) {
    //  ENGINE_SET_INVALID_EVENT(p, UDPLITE_HEADER_TOO_SMALL);
      return TM_ECODE_FAILED;
    }
    int32_t checksum = rs_udplite_decode_checksum(pkt, len);
    if (checksum < 0) {
    //  ENGINE_SET_INVALID_EVENT(p, UDPLITE_HEADER_TOO_SMALL);
      return TM_ECODE_FAILED;
    }
    int32_t coverage = rs_udplite_decode_coverage(pkt, len);
    if (coverage < 0) {
    //  ENGINE_SET_INVALID_EVENT(p, UDPLITE_HEADER_TOO_SMALL);
      return TM_ECODE_FAILED;
    }

    p->sp = sport;
    p->dp = dport;

    SCLogDebug("#%"PRIu64": srcp %"PRIu16", dstp %"PRIu16", checksum_coverage %"PRIu16", checksum %"PRIu16, p->pcap_cnt,
                                                                      sport, dport, coverage, checksum);

    /* Check whether checksum coverage is valid according to RFC3828) */
    if (unlikely(ntohs(myHdr->checksum_coverage) > 0 && ntohs(myHdr->checksum_coverage) < 8)) {
        ENGINE_SET_INVALID_EVENT(p,UDP_LITE_INVALID_COVERAGE);
        return TM_ECODE_FAILED;
    }
    if (p->ip4h) {
        if (unlikely(ntohs(myHdr->checksum_coverage) > IPV4_GET_RAW_IPLEN(p->ip4h))) {
            ENGINE_SET_INVALID_EVENT(p,UDP_LITE_INVALID_COVERAGE);
            return TM_ECODE_FAILED;
        }
    }

    /* Now we can access the header */
    p->udplitehdr = myHdr;
    p->payload = pkt + sizeof(UdpliteHdr);
    p->payload_len = len - sizeof(UdpliteHdr);

/*
    SCLogDebug("#%"PRIu64": srcp %"PRIu16", dstp %"PRIu16", checksum_coverage %"PRIu16", checksum %"PRIu16, p->pcap_cnt,
                                                                      ntohs(p->udplitehdr->srcp),
                                                                      ntohs(p->udplitehdr->dstp),
                                                                      ntohs(p->udplitehdr->checksum_coverage),
                                                                      ntohs(p->udplitehdr->checksum));
*/
    return TM_ECODE_OK;
}
