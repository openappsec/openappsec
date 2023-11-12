// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __NGINX_ATTACHMENT_COMMON_H__
#define __NGINX_ATTACHMENT_COMMON_H__

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <assert.h>

#define MAX_NGINX_UID_LEN 32
#define NUM_OF_NGINX_IPC_ELEMENTS 200
#define DEFAULT_KEEP_ALIVE_INTERVAL_MSEC 300000
#define SHARED_MEM_PATH "/dev/shm/"
#define SHARED_REGISTRATION_SIGNAL_PATH SHARED_MEM_PATH "check-point/cp-nano-attachment-registration"
#define SHARED_KEEP_ALIVE_PATH SHARED_MEM_PATH "check-point/cp-nano-attachment-registration-expiration-socket"
#define SHARED_VERDICT_SIGNAL_PATH SHARED_MEM_PATH "check-point/cp-nano-http-transaction-handler"
#define SHARED_ATTACHMENT_CONF_PATH SHARED_MEM_PATH "cp_nano_http_attachment_conf"
#define DEFAULT_STATIC_RESOURCES_PATH SHARED_MEM_PATH "static_resources"
#define INJECT_POS_IRRELEVANT -1
#define CORRUPTED_SESSION_ID 0
#define METRIC_PERIODIC_TIMEOUT 600

extern char shared_verdict_signal_path[];
extern int workers_amount_to_send;

typedef int64_t ngx_http_cp_inject_pos_t;

#ifdef __cplusplus
typedef enum class ngx_http_modification_type
#else
typedef enum ngx_http_modification_type
#endif
{
    APPEND,
    INJECT,
    REPLACE
} ngx_http_modification_type_e;

#ifdef __cplusplus
typedef enum class ngx_http_chunk_type
#else
typedef enum ngx_http_chunk_type
#endif
{
    REQUEST_START,
    REQUEST_HEADER,
    REQUEST_BODY,
    REQUEST_END,
    RESPONSE_CODE,
    RESPONSE_HEADER,
    RESPONSE_BODY,
    RESPONSE_END,
    CONTENT_LENGTH,
    METRIC_DATA_FROM_PLUGIN,
    HOLD_DATA,

    COUNT
} ngx_http_chunk_type_e;

#ifdef __cplusplus
typedef enum class ngx_http_plugin_metric_type
#else
typedef enum ngx_http_plugin_metric_type
#endif
{
    TRANSPARENTS_COUNT,
    TOTAL_TRANSPARENTS_TIME,
    INSPECTION_OPEN_FAILURES_COUNT,
    INSPECTION_CLOSE_FAILURES_COUNT,
    INSPECTION_SUCCESSES_COUNT,
    INJECT_VERDICTS_COUNT,
    DROP_VERDICTS_COUNT,
    ACCEPT_VERDICTS_COUNT,
    IRRELEVANT_VERDICTS_COUNT,
    RECONF_VERDICTS_COUNT,
    INSPECT_VERDICTS_COUNT,
    HOLD_VERDICTS_COUNT,
    AVERAGE_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT,
    MAX_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT,
    MIN_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT,
    AVERAGE_REQ_PPROCESSING_TIME_UNTIL_VERDICT,
    MAX_REQ_PPROCESSING_TIME_UNTIL_VERDICT,
    MIN_REQ_PPROCESSING_TIME_UNTIL_VERDICT,
    AVERAGE_RES_PPROCESSING_TIME_UNTIL_VERDICT,
    MAX_RES_PPROCESSING_TIME_UNTIL_VERDICT,
    MIN_RES_PPROCESSING_TIME_UNTIL_VERDICT,
    THREAD_TIMEOUT,
    REG_THREAD_TIMEOUT,
    REQ_HEADER_THREAD_TIMEOUT,
    REQ_BODY_THREAD_TIMEOUT,
    AVERAGE_REQ_BODY_SIZE_UPON_TIMEOUT,
    MAX_REQ_BODY_SIZE_UPON_TIMEOUT,
    MIN_REQ_BODY_SIZE_UPON_TIMEOUT,
    RES_HEADER_THREAD_TIMEOUT,
    RES_BODY_THREAD_TIMEOUT,
    HOLD_THREAD_TIMEOUT,
    AVERAGE_RES_BODY_SIZE_UPON_TIMEOUT,
    MAX_RES_BODY_SIZE_UPON_TIMEOUT,
    MIN_RES_BODY_SIZE_UPON_TIMEOUT,
    THREAD_FAILURE,
    REQ_PROCCESSING_TIMEOUT,
    RES_PROCCESSING_TIMEOUT,
    REQ_FAILED_TO_REACH_UPSTREAM,
    REQ_FAILED_COMPRESSION_COUNT,
    RES_FAILED_COMPRESSION_COUNT,
    REQ_FAILED_DECOMPRESSION_COUNT,
    RES_FAILED_DECOMPRESSION_COUNT,
    REQ_SUCCESSFUL_COMPRESSION_COUNT,
    RES_SUCCESSFUL_COMPRESSION_COUNT,
    REQ_SUCCESSFUL_DECOMPRESSION_COUNT,
    RES_SUCCESSFUL_DECOMPRESSION_COUNT,
    CORRUPTED_ZIP_SKIPPED_SESSION_COUNT,
    CPU_USAGE,
    AVERAGE_VM_MEMORY_USAGE,
    AVERAGE_RSS_MEMORY_USAGE,
    MAX_VM_MEMORY_USAGE,
    MAX_RSS_MEMORY_USAGE,
    REQUEST_OVERALL_SIZE_COUNT,
    RESPONSE_OVERALL_SIZE_COUNT,

    METRIC_TYPES_COUNT
} ngx_http_plugin_metric_type_e;

#ifdef __cplusplus
typedef enum class ngx_http_cp_verdict
#else
typedef enum ngx_http_cp_verdict
#endif
{
    TRAFFIC_VERDICT_INSPECT,
    TRAFFIC_VERDICT_ACCEPT,
    TRAFFIC_VERDICT_DROP,
    TRAFFIC_VERDICT_INJECT,
    TRAFFIC_VERDICT_IRRELEVANT,
    TRAFFIC_VERDICT_RECONF,
    TRAFFIC_VERDICT_WAIT
} ngx_http_cp_verdict_e;

#ifdef __cplusplus
typedef enum class ngx_http_cp_debug_level
#else
typedef enum ngx_http_cp_debug_level
#endif
{
    DBG_LEVEL_TRACE,
    DBG_LEVEL_DEBUG,
    DBG_LEVEL_INFO,
    DBG_LEVEL_WARNING,
    DBG_LEVEL_ERROR,
#ifndef __cplusplus
    DBG_LEVEL_ASSERT,
#endif
    DBG_LEVEL_COUNT
} ngx_http_cp_debug_level_e;

#ifdef __cplusplus
typedef enum class ngx_http_meta_data
#else
typedef enum ngx_http_meta_data
#endif
{
    HTTP_PROTOCOL_SIZE,
    HTTP_PROTOCOL_DATA,
    HTTP_METHOD_SIZE,
    HTTP_METHOD_DATA,
    HOST_NAME_SIZE,
    HOST_NAME_DATA,
    LISTENING_ADDR_SIZE,
    LISTENING_ADDR_DATA,
    LISTENING_PORT,
    URI_SIZE,
    URI_DATA,
    CLIENT_ADDR_SIZE,
    CLIENT_ADDR_DATA,
    CLIENT_PORT,
    PARSED_HOST_SIZE,
    PARSED_HOST_DATA,
    PARSED_URI_SIZE,
    PARSED_URI_DATA,

    META_DATA_COUNT
} ngx_http_meta_data_e;

#ifdef __cplusplus
typedef enum class ngx_http_header_data
#else
typedef enum ngx_http_header_data
#endif
{
    HEADER_KEY_SIZE,
    HEADER_KEY_DATA,
    HEADER_VAL_SIZE,
    HEADER_VAL_DATA,

    HEADER_DATA_COUNT
} ngx_http_header_data_e;

typedef enum ngx_http_inspection_mode
{
    NON_BLOCKING_THREAD,
    BLOCKING_THREAD,
    NO_THREAD,

    INSPECTION_MODE_COUNT
} ngx_http_inspection_mode_e;

#ifdef __cplusplus
typedef enum class ngx_web_response_type
#else
typedef enum ngx_web_response_type
#endif
{
    CUSTOM_WEB_RESPONSE,
    REDIRECT_WEB_RESPONSE
} ngx_web_response_type_e;

typedef struct __attribute__((__packed__)) ngx_http_cp_inject_data {
    ngx_http_cp_inject_pos_t  injection_pos;
    ngx_http_modification_type_e mod_type;
    uint16_t injection_size;
    uint8_t is_header;
    uint8_t orig_buff_index;
    char data[0];
} ngx_http_cp_inject_data_t;

typedef struct __attribute__((__packed__)) ngx_http_cp_web_response_data {
    uint8_t web_repsonse_type;
    uint8_t uuid_size;

    union {
        struct __attribute__((__packed__)) ngx_http_cp_custom_web_response_data {
            uint16_t response_code;
            uint8_t title_size;
            uint8_t body_size;
            char data[0];
        } custom_response_data;

        struct __attribute__((__packed__)) ngx_http_cp_redirect_data {
            uint8_t unused_dummy;
            uint8_t add_event_id;
            uint16_t redirect_location_size;
            char redirect_location[0];
        } redirect_data;
    } response_data;
} ngx_http_cp_web_response_data_t;

static_assert(
    sizeof(((ngx_http_cp_web_response_data_t*)0)->response_data.custom_response_data) ==
    sizeof(((ngx_http_cp_web_response_data_t*)0)->response_data.redirect_data),
    "custom_response_data must be equal to redirect_data in size"
);

typedef union __attribute__((__packed__)) ngx_http_cp_modify_data {
    ngx_http_cp_inject_data_t inject_data[0];
    ngx_http_cp_web_response_data_t web_response_data[0];
} ngx_http_cp_modify_data_t;

typedef struct __attribute__((__packed__)) ngx_http_cp_reply_from_service {
    uint16_t verdict;
    uint32_t session_id;
    uint8_t modification_count;
    ngx_http_cp_modify_data_t modify_data[0];
} ngx_http_cp_reply_from_service_t;

typedef struct __attribute__((__packed__)) ngx_http_cp_request_data {
    uint16_t data_type;
    uint32_t session_id;
    unsigned char data[0];
} ngx_http_cp_request_data_t;

typedef struct __attribute__((__packed__)) ngx_http_cp_metric_data {
    uint16_t data_type;
#ifdef __cplusplus
    uint64_t data[static_cast<int>(ngx_http_plugin_metric_type::METRIC_TYPES_COUNT)];
#else
    uint64_t data[METRIC_TYPES_COUNT];
#endif
} ngx_http_cp_metric_data_t;

#endif // __NGINX_ATTACHMENT_COMMON_H__
