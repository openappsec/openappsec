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

#ifdef DEFINE_FLAG

DEFINE_FLAG(D_INFRA, D_ALL)
    DEFINE_FLAG(D_EXTERNAL_SDK, D_INFRA)
        DEFINE_FLAG(D_EXTERNAL_SDK_USER, D_INFRA)
        DEFINE_FLAG(D_EXTERNAL_SDK_SERVER, D_INFRA)
    DEFINE_FLAG(D_INFRA_API, D_INFRA)
    DEFINE_FLAG(D_INFRA_UTILS, D_INFRA)
    DEFINE_FLAG(D_COMPRESSION, D_INFRA)
    DEFINE_FLAG(D_SHMEM, D_INFRA)
    DEFINE_FLAG(D_CONFIG, D_INFRA)
    DEFINE_FLAG(D_ENVIRONMENT, D_INFRA)
    DEFINE_FLAG(D_INTELLIGENCE, D_INFRA)
    DEFINE_FLAG(D_RULEBASE_CONFIG, D_INFRA)
    DEFINE_FLAG(D_DEBUG_FOG, D_INFRA)
    DEFINE_FLAG(D_METRICS, D_INFRA)
        DEFINE_FLAG(D_METRICS_HTTP_MANAGER, D_METRICS)
        DEFINE_FLAG(D_METRICS_NGINX_ATTACHMENT, D_METRICS)
        DEFINE_FLAG(D_METRICS_ACCESS_CONTROL, D_METRICS)
    DEFINE_FLAG(D_MAINLOOP, D_INFRA)
    DEFINE_FLAG(D_SIGNAL_HANDLER, D_INFRA)
    DEFINE_FLAG(D_TENANT_MANAGER, D_INFRA)
    DEFINE_FLAG(D_MONITORING, D_INFRA)
    DEFINE_FLAG(D_SERVICE_HEALTH_STATUS, D_INFRA)
    DEFINE_FLAG(D_REPORT, D_INFRA)
        DEFINE_FLAG(D_REPORT_BULK, D_REPORT)
    DEFINE_FLAG(D_TRACE, D_INFRA)
    DEFINE_FLAG(D_COMP_IS, D_INFRA)
    DEFINE_FLAG(D_COMMUNICATION, D_INFRA)
        DEFINE_FLAG(D_API, D_COMMUNICATION)
        DEFINE_FLAG(D_SOCKET, D_COMMUNICATION)
        DEFINE_FLAG(D_SYNC, D_COMMUNICATION)
            DEFINE_FLAG(D_UPGRADE, D_SYNC)
        DEFINE_FLAG(D_MESSAGING, D_COMMUNICATION)
            DEFINE_FLAG(D_CONNECTION, D_MESSAGING)
            DEFINE_FLAG(D_MESSAGING_BUFFER, D_MESSAGING)
            DEFINE_FLAG(D_HTTP_REQUEST, D_MESSAGING)

DEFINE_FLAG(D_COMPONENT, D_ALL)
    DEFINE_FLAG(D_PRELOAD, D_COMPONENT)
    DEFINE_FLAG(D_PENDING, D_COMPONENT)

    DEFINE_FLAG(D_KERNEL_APP, D_COMPONENT)
        DEFINE_FLAG(D_KERNEL_MESSAGE_READER, D_KERNEL_APP)
        DEFINE_FLAG(D_MESSAGE_READER, D_KERNEL_APP)

    DEFINE_FLAG(D_TABLE, D_COMPONENT)
    DEFINE_FLAG(D_STREAMING, D_COMPONENT)
        DEFINE_FLAG(D_STREAMING_DATA, D_STREAMING)
        DEFINE_FLAG(D_CHECKSUM, D_STREAMING)

    DEFINE_FLAG(D_WAAP_GLOBAL, D_COMPONENT)
        DEFINE_FLAG(D_WAAP, D_WAAP_GLOBAL)
            DEFINE_FLAG(D_NGINX_EVENTS, D_WAAP)
            DEFINE_FLAG(D_OA_SCHEMA_UPDATER, D_WAAP)
            DEFINE_FLAG(D_WAAP_API, D_WAAP)
            DEFINE_FLAG(D_WAAP_AUTOMATION, D_WAAP)
            DEFINE_FLAG(D_WAAP_REGEX, D_WAAP)
            DEFINE_FLAG(D_WAAP_SAMPLE_SCAN, D_WAAP)
            DEFINE_FLAG(D_WAAP_ASSET_STATE, D_WAAP)
            DEFINE_FLAG(D_WAAP_CONFIDENCE_CALCULATOR, D_WAAP)
            DEFINE_FLAG(D_WAAP_REPUTATION, D_WAAP)
            DEFINE_FLAG(D_WAAP_SCORE_BUILDER, D_WAAP)
            DEFINE_FLAG(D_WAAP_ULIMITS, D_WAAP)
            DEFINE_FLAG(D_WAAP_SCANNER, D_WAAP)
            DEFINE_FLAG(D_WAAP_MODEL_LOGGER, D_WAAP)
            DEFINE_FLAG(D_WAAP_DEEP_PARSER, D_WAAP)
            DEFINE_FLAG(D_WAAP_BASE64, D_WAAP)
            DEFINE_FLAG(D_WAAP_JSON, D_WAAP)
            DEFINE_FLAG(D_WAAP_BOT_PROTECTION, D_WAAP)
            DEFINE_FLAG(D_WAAP_STREAMING_PARSING, D_WAAP)
            DEFINE_FLAG(D_WAAP_HEADERS, D_WAAP)
            DEFINE_FLAG(D_WAAP_OVERRIDE, D_WAAP)

        DEFINE_FLAG(D_WAAP_SAMPLE_HANDLING, D_WAAP_GLOBAL)
            DEFINE_FLAG(D_WAAP_SAMPLE_PREPROCESS, D_WAAP_SAMPLE_HANDLING)
            DEFINE_FLAG(D_WAAP_EVASIONS, D_WAAP_SAMPLE_HANDLING)

        DEFINE_FLAG(D_WAAP_PARSER, D_WAAP_GLOBAL)
            DEFINE_FLAG(D_WAAP_PARSER_XML, D_WAAP_PARSER)
            DEFINE_FLAG(D_WAAP_PARSER_HTML, D_WAAP_PARSER)
            DEFINE_FLAG(D_WAAP_PARSER_BINARY, D_WAAP_PARSER)
            DEFINE_FLAG(D_WAAP_PARSER_CONTENT_TYPE, D_WAAP_PARSER)
            DEFINE_FLAG(D_WAAP_PARSER_CONFLUENCE, D_WAAP_PARSER)
            DEFINE_FLAG(D_WAAP_PARSER_DELIMITER, D_WAAP_PARSER)
            DEFINE_FLAG(D_WAAP_PARSER_HDRVALUE, D_WAAP_PARSER)
            DEFINE_FLAG(D_WAAP_PARSER_JSON, D_WAAP_PARSER)
            DEFINE_FLAG(D_WAAP_PARSER_GQL, D_WAAP_PARSER)
            DEFINE_FLAG(D_WAAP_PARSER_MULTIPART_FORM, D_WAAP_PARSER)
            DEFINE_FLAG(D_WAAP_PARSER_RAW, D_WAAP_PARSER)
            DEFINE_FLAG(D_WAAP_PARSER_URLENCODE, D_WAAP_PARSER)
            DEFINE_FLAG(D_WAAP_PARSER_PHPSERIALIZE, D_WAAP_PARSER)
            DEFINE_FLAG(D_WAAP_PARSER_PERCENT, D_WAAP_PARSER)
            DEFINE_FLAG(D_WAAP_PARSER_PAIRS, D_WAAP_PARSER)
            DEFINE_FLAG(D_WAAP_PARSER_PDF, D_WAAP_PARSER)
            DEFINE_FLAG(D_WAAP_PARSER_BINARY_FILE, D_WAAP_PARSER)
            DEFINE_FLAG(D_WAAP_PARSER_KNOWN_SOURCE_SKIPPER, D_WAAP_PARSER)
            DEFINE_FLAG(D_WAAP_PARSER_SCREENED_JSON, D_WAAP_PARSER)

    DEFINE_FLAG(D_IPS, D_COMPONENT)
    DEFINE_FLAG(D_FILE_UPLOAD, D_COMPONENT)
    DEFINE_FLAG(D_RATE_LIMIT, D_COMPONENT)
    DEFINE_FLAG(D_ROLLBACK_TESTING, D_COMPONENT)
    DEFINE_FLAG(D_NGINX_MANAGER, D_COMPONENT)

    DEFINE_FLAG(D_PARSER, D_COMPONENT)
    DEFINE_FLAG(D_WS, D_COMPONENT)
    DEFINE_FLAG(D_CMI, D_COMPONENT)
        DEFINE_FLAG(D_KEYWORD, D_CMI)
        DEFINE_FLAG(D_PM, D_CMI)
            DEFINE_FLAG(D_PM_COMP, D_PM)
            DEFINE_FLAG(D_PM_EXEC, D_PM)

    DEFINE_FLAG(D_FW, D_COMPONENT)
        DEFINE_FLAG(D_STATELESS_CHECKS, D_FW)
        DEFINE_FLAG(D_FRAGMENTATION_HANDLER, D_FW)
        DEFINE_FLAG(D_POLICY, D_FW)
        DEFINE_FLAG(D_NSAAS, D_FW)
        DEFINE_FLAG(D_POLICY_MATCHER, D_FW)

    DEFINE_FLAG(D_PACKET, D_COMPONENT)
    DEFINE_FLAG(D_PKTCAP, D_COMPONENT)
    DEFINE_FLAG(D_THROUGHPUT, D_COMPONENT)
    DEFINE_FLAG(D_ASSET_RESOLVER, D_COMPONENT)
    DEFINE_FLAG(D_ASSET_REPORTER, D_COMPONENT)

    DEFINE_FLAG(D_HTTP_SECURITY_APP, D_COMPONENT)
    DEFINE_FLAG(D_HTTP_MANAGER, D_COMPONENT)

    DEFINE_FLAG(D_ORCHESTRATOR, D_COMPONENT)
        DEFINE_FLAG(D_HEALTH_CHECK_MANAGER, D_ORCHESTRATOR)
        DEFINE_FLAG(D_HEALTH_CHECK, D_ORCHESTRATOR)
        DEFINE_FLAG(D_AGENT_DETAILS, D_ORCHESTRATOR)
        DEFINE_FLAG(D_LOCAL_POLICY, D_ORCHESTRATOR)
        DEFINE_FLAG(D_NGINX_POLICY, D_ORCHESTRATOR)
        DEFINE_FLAG(D_SERVICE_CONTROLLER, D_ORCHESTRATOR)
        DEFINE_FLAG(D_UPDATES_PROCESS_REPORTER, D_ORCHESTRATOR)

    DEFINE_FLAG(D_GRADUAL_DEPLOYMENT, D_COMPONENT)
    DEFINE_FLAG(D_SDWAN, D_COMPONENT)
        DEFINE_FLAG(D_SDWAN_POLICY, D_SDWAN)
        DEFINE_FLAG(D_SDWAN_DATA, D_SDWAN)
        DEFINE_FLAG(D_SDWAN_FEATURE_FLAG, D_SDWAN)
        DEFINE_FLAG(D_LOGGER_SDWAN, D_SDWAN)
        DEFINE_FLAG(D_SDWAN_API, D_SDWAN)
    DEFINE_FLAG(D_REVERSE_PROXY, D_COMPONENT)
        DEFINE_FLAG(D_PLATFORM, D_REVERSE_PROXY)
        DEFINE_FLAG(D_NGINX_MESSAGE_READER, D_REVERSE_PROXY)
        DEFINE_FLAG(D_ERROR_REPORTER, D_REVERSE_PROXY)
        DEFINE_FLAG(D_UPSTREAM_KEEPALIVE, D_REVERSE_PROXY)
        DEFINE_FLAG(D_FORWARD_PROXY, D_REVERSE_PROXY)

    DEFINE_FLAG(D_IDA, D_COMPONENT)

    DEFINE_FLAG(D_IOT_NEXT, D_COMPONENT)
        DEFINE_FLAG(D_IOT_AUXILIARY, D_IOT_NEXT)
            DEFINE_FLAG(D_IOT_REPORT_STATUS, D_IOT_AUXILIARY)
            DEFINE_FLAG(D_IOT_COLLECT_METADATA, D_IOT_AUXILIARY)
            DEFINE_FLAG(D_IOT_QUERY_INTELLIGENCE, D_IOT_AUXILIARY)
            DEFINE_FLAG(D_IOT_SAVE_PERSISTENT, D_IOT_AUXILIARY)
            DEFINE_FLAG(D_IOT_DOCKER, D_IOT_AUXILIARY)
        DEFINE_FLAG(D_IOT_ENFORCE, D_IOT_NEXT)
            DEFINE_FLAG(D_IOT_ENFORCE_POLICY, D_IOT_ENFORCE)
            DEFINE_FLAG(D_IOT_ENFORCE_ASSETS, D_IOT_ENFORCE)
        DEFINE_FLAG(D_IOT_DOCTOR, D_IOT_NEXT)
        DEFINE_FLAG(D_IOT_RISK, D_IOT_NEXT)
            DEFINE_FLAG(D_IOT_QUERY_ASSETS, D_IOT_RISK)
            DEFINE_FLAG(D_IOT_INDICATOR_DATA, D_IOT_RISK)
            DEFINE_FLAG(D_IOT_INDICATORS, D_IOT_RISK)
            DEFINE_FLAG(D_IOT_DOCKER_WATCHDOG, D_IOT_RISK)
        DEFINE_FLAG(D_IOT_DISCOVERY, D_IOT_NEXT)
            DEFINE_FLAG(D_IOT_PROBE, D_IOT_DISCOVERY)
            DEFINE_FLAG(D_IOT_ASSETS_DATA, D_IOT_DISCOVERY)
            DEFINE_FLAG(D_IOT_INTEGRATIONS, D_IOT_DISCOVERY)
    DEFINE_FLAG(D_HTTP_EVENT_RECORD, D_COMPONENT)
    DEFINE_FLAG(D_GEO_DB, D_COMPONENT)
    DEFINE_FLAG(D_CPVIEW_METRIC_PROVIDER, D_COMPONENT)
    DEFINE_FLAG(D_GEO_FILTER, D_COMPONENT)
    DEFINE_FLAG(D_EGRESS_PROTECTION, D_COMPONENT)
        DEFINE_FLAG(D_URL_FILTERING, D_EGRESS_PROTECTION)
        DEFINE_FLAG(D_ANTIBOT, D_EGRESS_PROTECTION)
    DEFINE_FLAG(D_L7_ACCESS_CONTROL, D_COMPONENT)
    DEFINE_FLAG(D_IOT_ACCESS_CONTROL, D_COMPONENT)
    DEFINE_FLAG(D_HORIZON_TELEMETRY, D_COMPONENT)
    DEFINE_FLAG(D_PROMETHEUS, D_COMPONENT)

DEFINE_FLAG(D_FLOW, D_ALL)
    DEFINE_FLAG(D_DROP, D_FLOW)
    DEFINE_FLAG(D_ATTACHMENT, D_FLOW)
        DEFINE_FLAG(D_ATTACHMENT_REGISTRATION, D_ATTACHMENT)
        DEFINE_FLAG(D_NGINX_ATTACHMENT, D_ATTACHMENT)
            DEFINE_FLAG(D_NGINX_ATTACHMENT_PARSER, D_NGINX_ATTACHMENT)
        DEFINE_FLAG(D_SQUID_ATTACHMENT, D_ATTACHMENT)
        DEFINE_FLAG(D_WLP_ATTACHMENT, D_ATTACHMENT)

#endif // DEFINE_FLAG
