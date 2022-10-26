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

#ifndef __WAF2_REPORTING__001de2f8
#define __WAF2_REPORTING__001de2f8

// Generates data in JSON structure similar to what mod_security generates for its audit log
#include <stdio.h>
#include <string.h>
#include "yajl/yajl_gen.h"
#include "yajl/yajl_version.h"

#define yajl_string(s) yajl_gen_string(g, (const unsigned char *)(s), strlen(s))
#define yajl_string_len(s, l) yajl_gen_string(g, (const unsigned char *)(s), l)

#define yajl_kv_null(k) yajl_string(k); yajl_gen_null(g)
#define yajl_kv_int(k, v) yajl_string(k); yajl_gen_integer(g, v)
#define yajl_kv_bool(k, v) yajl_string(k); yajl_gen_bool(g, v)
#define yajl_kv_string(k, v) yajl_string(k); yajl_string(v)
#define yajl_kv_string_len(k, v, vlen) yajl_string(k); yajl_string_len(v, vlen)

typedef yajl_gen reporting_ctx_t;

inline reporting_ctx_t
reporting_ctx_create()
{
    return yajl_gen_alloc(NULL);
}

inline static void
reporting_ctx_free(reporting_ctx_t g)
{
    yajl_gen_free(g);
}

inline void
reporting_start_report(reporting_ctx_t g)
{
    yajl_gen_map_open(g);
}

inline void
reporting_emit_transaction_info(
    reporting_ctx_t g, const char *log_time,
    const char *transaction_id,
    const char *remote_addr,
    int remote_port,
    const char *local_addr,
    int local_port)
{
    yajl_string("transaction");
    yajl_gen_map_open(g);
    yajl_kv_string("time", log_time);
    yajl_kv_string("transaction_id", transaction_id);
    yajl_kv_string("remote_address", remote_addr);
    yajl_kv_int("remote_port", remote_port);
    yajl_kv_string("local_address", local_addr);
    yajl_kv_int("local_port", local_port);
    yajl_gen_map_close(g);
}

// Request
inline void
reporting_start_request(reporting_ctx_t g, const char *uri)
{
    yajl_string("request");
    yajl_gen_map_open(g);
    yajl_kv_string("uri", uri);
}

inline void
reporting_start_request_hdrs(reporting_ctx_t g)
{
    yajl_string("headers");
    yajl_gen_map_open(g);
}

inline void
reporting_add_request_hdr(reporting_ctx_t g, const char *name, int name_len, const char *value, int value_len)
{
    yajl_string_len(name, name_len);
    yajl_string_len(value, value_len);
}

inline void
reporting_end_request_hdrs(reporting_ctx_t g)
{
    yajl_gen_map_close(g);
}

inline void
reporting_start_request_body(reporting_ctx_t g)
{
    yajl_string("body");
    yajl_gen_array_open(g);
}

inline void
reporting_add_request_body_chunk(reporting_ctx_t g, const char *data, int data_len)
{
    yajl_string_len(data, data_len);
}

inline void
reporting_end_request_body(reporting_ctx_t g)
{
    yajl_gen_array_close(g);
}

inline void
reporting_end_request(reporting_ctx_t g)
{
    yajl_gen_map_close(g);
}

// Response
inline void
reporting_start_response(reporting_ctx_t g, int response_status, int http_version)
{
    yajl_string("response");
    yajl_gen_map_open(g);
    yajl_kv_string("protocol", (http_version==1) ? "HTTP/1.1" : "HTTP/1.0");
    // as an integer, response status is easier to parse than status_line
    yajl_kv_int("status", response_status);
}

inline void
reporting_start_response_hdrs(reporting_ctx_t g)
{
    yajl_string("headers");
    yajl_gen_map_open(g);
}

inline void
reporting_add_response_hdr(reporting_ctx_t g, const char *name, int name_len, const char *value, int value_len)
{
    yajl_string_len(name, name_len);
    yajl_string_len(value, value_len);
}

inline void
reporting_end_response_hdrs(reporting_ctx_t g)
{
    yajl_gen_map_close(g);
}

inline void
reporting_start_response_body(reporting_ctx_t g)
{
    yajl_string("body");
    yajl_gen_array_open(g);
}

inline void
reporting_add_response_body_chunk(reporting_ctx_t g, const char *data, int data_len)
{
    yajl_string_len(data, data_len);
}

inline void
reporting_end_response_body(reporting_ctx_t g)
{
    yajl_gen_array_close(g);
}

inline void
reporting_end_response(reporting_ctx_t g)
{
    yajl_gen_map_close(g);
}

inline void
reporting_end_report(reporting_ctx_t g)
{
    yajl_gen_map_close(g);
}

inline void
reporting_dump_report(reporting_ctx_t g, FILE *f)
{
    const unsigned char *final_buf;
    size_t len;
    yajl_gen_get_buf(g, &final_buf, &len);
    fwrite(final_buf, 1, len, f);
    yajl_gen_clear(g);
}

#endif // __WAF2_REPORTING__001de2f8
