/* Copyright (C) 2020-2022 Open Information Security Foundation
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
 * \author Sascha Steinbiss <sascha@steinbiss.name>
 */

#include "suricata-common.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "conf.h"
#include "decode.h"
#include "detect.h"
#include "detect-content.h"
#include "detect-parse.h"
#include "detect-pcre.h"
#include "detect-engine.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-mqtt-subscribe-topic.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "rust-bindings.h"

#include "threads.h"

#include "flow.h"
#include "flow-util.h"
#include "flow-var.h"

#include "util-debug.h"
#include "util-spm.h"
#include "util-print.h"
#include "util-profiling.h"

static int DetectMQTTSubscribeTopicSetup(DetectEngineCtx *, Signature *, const char *);

static int g_mqtt_subscribe_topic_buffer_id = 0;

static uint32_t subscribe_topic_match_limit = 100;

static InspectionBuffer *MQTTSubscribeTopicGetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flags, void *txv,
        int list_id, uint32_t local_id)
{
    SCEnter();

    if (subscribe_topic_match_limit > 0 && local_id >= subscribe_topic_match_limit)
        return NULL;

    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, local_id);
    if (buffer == NULL)
        return NULL;
    if (buffer->initialized)
        return buffer;

    const uint8_t *data;
    uint32_t data_len;
    if (rs_mqtt_tx_get_subscribe_topic(txv, local_id, &data, &data_len) == 0) {
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }

    InspectionBufferSetupMulti(buffer, transforms, data, data_len);
    buffer->flags = DETECT_CI_FLAGS_SINGLE;

    SCReturnPtr(buffer, "InspectionBuffer");
}

/**
 * \brief Registration function for keyword: mqtt.subscribe.topic
 */
void DetectMQTTSubscribeTopicRegister (void)
{
    sigmatch_table[DETECT_AL_MQTT_SUBSCRIBE_TOPIC].name = "mqtt.subscribe.topic";
    sigmatch_table[DETECT_AL_MQTT_SUBSCRIBE_TOPIC].desc = "sticky buffer to match MQTT SUBSCRIBE topic";
    sigmatch_table[DETECT_AL_MQTT_SUBSCRIBE_TOPIC].url = "/rules/mqtt-keywords.html#mqtt-subscribe-topic";
    sigmatch_table[DETECT_AL_MQTT_SUBSCRIBE_TOPIC].Setup = DetectMQTTSubscribeTopicSetup;
    sigmatch_table[DETECT_AL_MQTT_SUBSCRIBE_TOPIC].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_MQTT_SUBSCRIBE_TOPIC].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    intmax_t val = 0;
    if (ConfGetInt("app-layer.protocols.mqtt.subscribe-topic-match-limit", &val)) {
        subscribe_topic_match_limit = val;
    }
    if (subscribe_topic_match_limit <= 0) {
        SCLogDebug("Using unrestricted MQTT SUBSCRIBE topic matching");
    } else {
        SCLogDebug("Using MQTT SUBSCRIBE topic match-limit setting of: %u",
                subscribe_topic_match_limit);
    }

    DetectAppLayerMultiRegister("mqtt.subscribe.topic", ALPROTO_MQTT, SIG_FLAG_TOSERVER, 1,
            MQTTSubscribeTopicGetData, 1, 1);

    DetectBufferTypeSetDescriptionByName("mqtt.subscribe.topic",
            "subscribe topic query");

    g_mqtt_subscribe_topic_buffer_id = DetectBufferTypeGetByName("mqtt.subscribe.topic");

    DetectBufferTypeSupportsMultiInstance("mqtt.subscribe.topic");
}

/**
 * \brief setup the sticky buffer keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */

static int DetectMQTTSubscribeTopicSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(de_ctx, s, g_mqtt_subscribe_topic_buffer_id) < 0)
        return -1;
    if (DetectSignatureSetAppProto(s, ALPROTO_MQTT) < 0)
        return -1;
    return 0;
}
