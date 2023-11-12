// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "ParserJson.h"
#include "debug.h"
#include "yajl/yajl_parse.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

USE_DEBUG_FLAG(D_WAAP_PARSER_JSON);
USE_DEBUG_FLAG(D_OA_SCHEMA_UPDATER);

const std::string ParserJson::m_parserName = "jsonParser";

int
ParserJson::cb_null()
{
    dbgTrace(D_WAAP_PARSER_JSON) << "ParserJson::cb_null():";


    if (m_receiver2) {
        m_receiver2->onKvt(m_key.c_str(), m_key.size(), "null", 4, DataType::EMPTY);
    }

    if (m_receiver.onKv(m_key.c_str(), m_key.size(), "null", 4, BUFFERED_RECEIVER_F_BOTH, m_parser_depth)) {
        return 0;
    }

    if (!m_depthStack.empty() && m_depthStack.back() == js_map) {
        m_key.pop("json null");
    }

    return 1;
}

int
ParserJson::cb_boolean(int boolean)
{
    dbgTrace(D_WAAP_PARSER_JSON) << "ParserJson::cb_boolean(): " << boolean;


    if (m_receiver2) {
        m_receiver2->onKvt(m_key.c_str(), m_key.size(), NULL, boolean, DataType::BOOLEAN);
    }

    if (boolean) {
        if (m_receiver.onKv(m_key.c_str(), m_key.size(), "true", 4, BUFFERED_RECEIVER_F_BOTH, m_parser_depth)) {
            return 0;
        }
    } else {
        if (m_receiver.onKv(m_key.c_str(), m_key.size(), "false", 5, BUFFERED_RECEIVER_F_BOTH, m_parser_depth)) {
            return 0;
        }
    }

    if (!m_depthStack.empty() && m_depthStack.back() == js_map) {
        m_key.pop("json boolean");
    }
    return 1;
}

int
ParserJson::cb_number(const char *s, yajl_size_t slen)
{
    dbgTrace(D_WAAP_PARSER_JSON) << "ParserJson::cb_number(): '" << std::string(s, slen) << "'";

    if (m_receiver2) {
        m_receiver2->onKvt(m_key.c_str(), m_key.size(), s, slen, DataType::NUMBER);
    }

    if (m_receiver.onKv(m_key.c_str(), m_key.size(), s, slen, BUFFERED_RECEIVER_F_BOTH, m_parser_depth)) {
        return 0;
    }

    if (!m_depthStack.empty() && m_depthStack.back() == js_map) {
        m_key.pop("json number");
    }
    return 1;
}

int
ParserJson::cb_string(const unsigned char *s, yajl_size_t slen)
{
    dbgTrace(D_WAAP_PARSER_JSON) << "ParserJson::cb_string(): '" << std::string((const char *)s, slen) << "'";

    if (m_receiver2) {
        m_receiver2->onKvt(m_key.c_str(), m_key.size(), (const char*)s, slen, DataType::STRING);
    }


    if (m_receiver.onKv(
            m_key.c_str(), m_key.size(), (const char *)s, slen, BUFFERED_RECEIVER_F_BOTH, m_parser_depth
        )) {
        return 0;
    }

    if (!m_depthStack.empty() && m_depthStack.back() == js_map) {
        m_key.pop("json string");
    }
    return 1;
}

int
ParserJson::cb_map_key(const unsigned char *s, yajl_size_t slen)
{
    dbgTrace(D_WAAP_PARSER_JSON) << "ParserJson::cb_map_key(): '" << std::string((const char *)s, slen) << "'";

    m_key.push((char*)s, slen);

    if (m_receiver2) {
        m_receiver2->onMapKey(m_key.c_str(), m_key.size());
    }

    return 1;
}

int
ParserJson::cb_start_map()
{
    dbgTrace(D_WAAP_PARSER_JSON) << "ParserJson::cb_start_map():";

    if (m_receiver2) {
        m_receiver2->onStartMap();
    }

    m_depthStack.push_back(ParserJson::js_map);
    return 1;
}

int
ParserJson::cb_end_map()
{
    dbgTrace(D_WAAP_PARSER_JSON) << "ParserJson::cb_end_map():";

    if (m_receiver2) {
        m_receiver2->onEndMap();
    }

    if (!m_depthStack.empty()) {
        m_depthStack.pop_back();
    }

    if (!m_depthStack.empty() && m_depthStack.back() == js_map) {
        m_key.pop("json end map");
    }

    return 1;
}

int
ParserJson::cb_start_array()
{
    dbgTrace(D_WAAP_PARSER_JSON) << "ParserJson::cb_start_array():";

    if (m_receiver2) {
        m_receiver2->onStartArray();
    }

    m_depthStack.push_back(ParserJson::js_array);
    return 1;
}

int
ParserJson::cb_end_array()
{
    dbgTrace(D_WAAP_PARSER_JSON) << "ParserJson::cb_end_array():";

    if (m_receiver2) {
        m_receiver2->onEndArray();
    }

    if (!m_depthStack.empty()) {
        m_depthStack.pop_back();
    }


    if (!m_depthStack.empty() && m_depthStack.back() == js_map) {
        m_key.pop("json end array");
    }
    return 1;
}

// Static functions to be called from C and forward the calls to respective class cb_* methods
int
ParserJson::p_null(void *ctx)
{
    return ((ParserJson*)ctx)->cb_null();
}

int
ParserJson::p_boolean(void *ctx, int boolean)
{
    return ((ParserJson*)ctx)->cb_boolean(boolean);
}

int
ParserJson::p_number(void *ctx, const char *s, yajl_size_t slen)
{
    return ((ParserJson*)ctx)->cb_number(s, slen);
}

int
ParserJson::p_string(void *ctx, const unsigned char *s, yajl_size_t slen)
{
    return ((ParserJson*)ctx)->cb_string(s, slen);
}

int
ParserJson::p_map_key(void *ctx, const unsigned char *s, yajl_size_t slen)
{
    return ((ParserJson*)ctx)->cb_map_key(s, slen);
}

int
ParserJson::p_start_map(void *ctx)
{
    return ((ParserJson*)ctx)->cb_start_map();
}

int
ParserJson::p_end_map(void *ctx)
{
    return ((ParserJson*)ctx)->cb_end_map();
}

int
ParserJson::p_start_array(void *ctx)
{
    return ((ParserJson*)ctx)->cb_start_array();
}

int
ParserJson::p_end_array(void *ctx)
{
    return ((ParserJson*)ctx)->cb_end_array();
}

ParserJson::ParserJson(
    IParserReceiver &receiver,
    bool should_collect_oas,
    size_t parser_depth,
    IParserReceiver2 *receiver2)
        :
    m_receiver(receiver),
    m_receiver2(receiver2),
    m_state(s_start),
    m_bufLen(0),
    m_key("json_parser"),
    m_jsonHandler(NULL),
    is_map_empty(false),
    should_collect_for_oa_schema_updater(should_collect_oas),
    m_parser_depth(parser_depth)
{
    dbgTrace(D_WAAP_PARSER_JSON) << "parser_depth= " << parser_depth;

    // TODO:: do we really want to clear this?
    memset(m_buf, 0, sizeof(m_buf));

    static const yajl_callbacks callbacks = {
        p_null,
        p_boolean,
        NULL,
        NULL,
        p_number,
        p_string,
        p_start_map,
        p_map_key,
        p_end_map,
        p_start_array,
        p_end_array
    };

    m_jsonHandler = yajl_alloc(&callbacks, NULL, this);
    
    if (m_jsonHandler == NULL) {
        dbgTrace(D_WAAP_PARSER_JSON) << "ParserJson::ParserJson(): yajl_alloc() failed. Switching to s_error state.";
        m_state = s_error;
        return;
    }

    // Configure yajl parser
    yajl_config(m_jsonHandler, yajl_allow_comments, 1);
    yajl_config(m_jsonHandler, yajl_dont_validate_strings, 1); // disable utf8 checking
    yajl_config(m_jsonHandler, yajl_allow_multiple_values, 1);

    // Ugly: push first element into key (it will be ignored since we will never call the "first()"
    // method of this key within Json parser object.
    m_key.push("json", 4);
}

ParserJson::~ParserJson()
{
    // Cleanup JSON
    dbgTrace(D_WAAP_PARSER_JSON) << "ParserJson::~ParserJson():";

    if (m_jsonHandler) {
        yajl_free(m_jsonHandler);
    }
}

size_t
ParserJson::push(const char *buf, size_t len)
{
    size_t i = 0;
    char c;

    if (len == 0) {
        dbgTrace(D_WAAP_PARSER_JSON) << "ParserJson::push(): end of data signal! m_state=" << m_state;
        // TODO:: think - should I send existing data in buffer to yajl_parse() here?
        // Tell yajl that there's end of stream here
        if (yajl_complete_parse(m_jsonHandler) != yajl_status_ok) {
            m_state = s_error;
        }

        if (m_receiver2) {
            m_receiver2->onEndOfData();
        }

        return 0;
    }

    while (i < len) {
        c = buf[i];


        switch (m_state) {
        case s_start:
            dbgTrace(D_WAAP_PARSER_JSON) << "ParserJson::push(): s_start";
            m_state = s_accumulate_first_bytes;

            // fallthrough //
            CP_FALL_THROUGH;
        case s_accumulate_first_bytes:
                dbgTrace(D_WAAP_PARSER_JSON)
                    << "ParserJson::push(): s_accumulate_first_bytes. i="
                    << i
                    << " c='"
                    << buf[i]
                    << "'";
            m_buf[m_bufLen] = c;
            m_bufLen++;
            if (m_bufLen == FIRST_JSON_BUFFER_SIZE) {
                m_state = s_start_parsing;
            }
            break;

        case s_start_parsing:
                dbgTrace(D_WAAP_PARSER_JSON)
                    << "ParserJson::push(): s_start_parsing. sending len="
                    << (int)m_bufLen
                    << ": '"
                    << std::string(m_buf, m_bufLen)
                    << "'";
            m_state = s_parsing;

            // fallthrough //
            CP_FALL_THROUGH;
        case s_parsing:
                dbgTrace(D_WAAP_PARSER_JSON)
                    << "ParserJson::push(): s_parsing. sending len="
                    << (int)(len - i)
                    << ": '"
                    << std::string(buf + i, len - i)
                    << "'";
            if (m_bufLen > 0) {
                // Send accumulated bytes (if any)
                if (yajl_parse(m_jsonHandler, (unsigned char*)m_buf, m_bufLen) != yajl_status_ok) {
                    m_state = s_error;
                }
                // And reset buffer (so it's only get sent once)
                m_bufLen = 0;
            }
            if (yajl_parse(m_jsonHandler, (unsigned char*)(buf + i), len - i) != yajl_status_ok) {
                m_state = s_error;
            }
            // success (whole buffer consumed)
            i = len - 1; // take into account ++i at the end of the m_state machine loop
            break;
        case s_error: {
            dbgTrace(D_WAAP_PARSER_JSON) << "ParserJson::push(): s_error";
            return 0;
        }
        }

        ++i;
    }

    return len;
}

void
ParserJson::finish()
{
    push(NULL, 0);
}

const std::string &
ParserJson::name() const
{
    return m_parserName;
}

bool
ParserJson::error() const
{
    return m_state == s_error;
}
