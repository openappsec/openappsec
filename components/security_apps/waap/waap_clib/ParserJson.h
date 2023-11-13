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

#ifndef __PARSER_JSON_H__a94f1be2
#define __PARSER_JSON_H__a94f1be2

#include <string.h>
#include <vector>

#include "ParserBase.h"
#include "KeyStack.h"
#include "yajl/yajl_parse.h"

#define FIRST_JSON_BUFFER_SIZE 4 // must buffer at least 4 first bytes to allow unicode autodetection (BOM).

typedef size_t yajl_size_t;

class ParserJson : public ParserBase {
public:
    ParserJson(
        IParserReceiver &receiver,
        bool should_collect_for_oa_schema_updater=false,
        size_t parser_depth=0,
        IParserReceiver2 *receiver2=NULL);
    virtual ~ParserJson();
    size_t push(const char *data, size_t data_len);
    void finish();
    virtual const std::string &name() const;
    bool error() const;
    virtual size_t depth() { return (m_key.depth() > 0) ? m_key.depth()-1 : m_key.depth(); }
private:
    int cb_null();
    int cb_boolean(int boolean);
    int cb_number(const char *s, yajl_size_t slen);
    int cb_string(const unsigned char *s, yajl_size_t slen);
    int cb_map_key(const unsigned char *s, yajl_size_t slen);
    int cb_start_map();
    int cb_end_map();
    int cb_start_array();
    int cb_end_array();

    // Static callbacks to be called from C
    static int p_null(void *ctx);
    static int p_boolean(void *ctx, int boolean);
    static int p_number(void *ctx, const char *s, yajl_size_t slen);
    static int p_string(void *ctx, const unsigned char *s, yajl_size_t slen);
    static int p_map_key(void *ctx, const unsigned char *s, yajl_size_t slen);
    static int p_start_map(void *ctx);
    static int p_end_map(void *ctx);
    static int p_start_array(void *ctx);
    static int p_end_array(void *ctx);

    enum state {
        s_start,
        s_accumulate_first_bytes,
        s_start_parsing,
        s_parsing,
        s_error
    };
    
    enum js_state {
        js_array,
        js_map
    };

    IParserReceiver &m_receiver;
    IParserReceiver2 *m_receiver2;
    enum state m_state;
    // buffer first few bytes of stream
    // (required before calling JSON parser for the first time so it can recognize stuff like UTF-8 BOM)
    char m_buf[FIRST_JSON_BUFFER_SIZE];
    size_t m_bufLen;
    // Key and structure depth stacks
    KeyStack m_key;
    std::vector<enum js_state> m_depthStack;
    yajl_handle m_jsonHandler;
    bool is_map_empty;
    bool should_collect_for_oa_schema_updater;

    size_t m_parser_depth;
public:
    static const std::string m_parserName;
};

#endif // __PARSER_JSON_H__a94f1be2
