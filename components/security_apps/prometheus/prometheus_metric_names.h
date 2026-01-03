#ifndef __PROMETHEUS_METRIC_NAMES_H__
#define __PROMETHEUS_METRIC_NAMES_H__

#include <string>
#include <unordered_map>

#include "debug.h"

USE_DEBUG_FLAG(D_PROMETHEUS);

std::string
convertMetricName(const std::string &original_metric_name)
{
    static const std::unordered_map<std::string, std::string> original_to_representative_names = {
        // HybridModeMetric
        {"watchdogProcessStartupEventsSum", "nano_service_restarts_counter"},
        // nginxAttachmentMetric
        {"inspectVerdictSum", "traffic_inspection_verdict_inspect_counter"},
        {"acceptVeridctSum", "traffic_inspection_verdict_accept_counter"},
        {"dropVerdictSum", "traffic_inspection_verdict_drop_counter"},
        {"injectVerdictSum", "traffic_inspection_verdict_inject_counter"},
        {"irrelevantVerdictSum", "traffic_inspection_verdict_irrelevant_counter"},
        {"irrelevantVerdictSum", "traffic_inspection_verdict_irrelevant_counter"},
        {"reconfVerdictSum", "traffic_inspection_verdict_reconf_counter"},
        {"responseInspection", "response_body_inspection_counter"},
        // nginxIntakerMetric
        {"successfullInspectionTransactionsSum", "successful_Inspection_counter"},
        {"failopenTransactionsSum", "fail_open_Inspection_counter"},
        {"failcloseTransactionsSum", "fail_close_Inspection_counter"},
        {"transparentModeTransactionsSum", "transparent_mode_counter"},
        {"totalTimeInTransparentModeSum", "total_time_in_transparent_mode_counter"},
        {"reachInspectVerdictSum", "inspect_verdict_counter"},
        {"reachAcceptVerdictSum", "accept_verdict_counter"},
        {"reachDropVerdictSum", "drop_verdict_counter"},
        {"reachInjectVerdictSum", "inject_verdict_counter"},
        {"reachIrrelevantVerdictSum", "irrelevant_verdict_counter"},
        {"reachReconfVerdictSum", "reconf_verdict_counter"},
        {"requestCompressionFailureSum", "failed_requests_compression_counter"},
        {"responseCompressionFailureSum", "failed_response_compression_counter"},
        {"requestDecompressionFailureSum", "failed_requests_decompression_counter"},
        {"responseDecompressionFailureSum", "failed_response_decompression_counter"},
        {"requestCompressionSuccessSum", "successful_request_compression_counter"},
        {"responseCompressionSuccessSum", "successful_response_compression_counter"},
        {"requestDecompressionSuccessSum", "successful_request_decompression_counter"},
        {"responseDecompressionSuccessSum", "successful_response_decompression_counter"},
        {"skippedSessionsUponCorruptedZipSum", "corrupted_zip_skipped_session_counter"},
        {"attachmentThreadReachedTimeoutSum", "thread_exceeded_processing_time_counter"},
        {"registrationThreadReachedTimeoutSum", "failed_registration_thread_counter"},
        {"requestHeaderThreadReachedTimeoutSum", "request_headers_processing_thread_timeouts_counter"},
        {"requestBodyThreadReachedTimeoutSum", "request_body_processing_thread_timeouts_counter"},
        {"respondHeaderThreadReachedTimeoutSum", "response_headers_processing_thread_timeouts_counter"},
        {"respondBodyThreadReachedTimeoutSum", "response_body_processing_thread_timeouts_counter"},
        {"attachmentThreadFailureSum", "thread_failures_counter"},
        {"httpRequestProcessingReachedTimeoutSum", "request_processing_timeouts_counter"},
        {"httpRequestsSizeSum", "requests_total_size_counter"},
        {"httpResponsesSizeSum", "response_total_size_counter"},
        {"httpRequestFailedToReachWebServerUpstreamSum", "requests_failed_reach_upstram_counter"},
        {"overallSessionProcessTimeToVerdictAvgSample", "overall_processing_time_until_verdict_average"},
        {"overallSessionProcessTimeToVerdictMaxSample", "overall_processing_time_until_verdict_max"},
        {"overallSessionProcessTimeToVerdictMinSample", "overall_processing_time_until_verdict_min"},
        {"requestProcessTimeToVerdictAvgSample", "requests_processing_time_until_verdict_average"},
        {"requestProcessTimeToVerdictMaxSample", "requests_processing_time_until_verdict_max"},
        {"requestProcessTimeToVerdictMinSample", "requests_processing_time_until_verdict_min"},
        {"responseProcessTimeToVerdictAvgSample", "response_processing_time_until_verdict_average"},
        {"responseProcessTimeToVerdictMaxSample", "response_processing_time_until_verdict_max"},
        {"responseProcessTimeToVerdictMinSample", "response_processing_time_until_verdict_min"},
        {"requestBodySizeUponTimeoutAvgSample", "request_body_size_average"},
        {"requestBodySizeUponTimeoutMaxSample", "request_body_size_max"},
        {"requestBodySizeUponTimeoutMinSample", "request_body_size_min"},
        {"responseBodySizeUponTimeoutAvgSample", "response_body_size_average"},
        {"responseBodySizeUponTimeoutMaxSample", "response_body_size_max"},
        {"responseBodySizeUponTimeoutMinSample", "response_body_size_min"},
        // WaapTelemetrics
        {"reservedNgenA_WAAP telemetry", "total_requests_counter"},
        {"reservedNgenB_WAAP telemetry", "unique_sources_counter"},
        {"reservedNgenC_WAAP telemetry", "requests_blocked_by_force_and_exception_counter"},
        {"reservedNgenD_WAAP telemetry", "requests_blocked_by_waf_counter"},
        {"reservedNgenE_WAAP telemetry", "requests_blocked_by_open_api_counter"},
        {"reservedNgenF_WAAP telemetry", "requests_blocked_by_bot_protection_counter"},
        {"reservedNgenG_WAAP telemetry", "requests_threat_level_info_and_no_threat_counter"},
        {"reservedNgenH_WAAP telemetry", "requests_threat_level_low_counter"},
        {"reservedNgenI_WAAP telemetry", "requests_threat_level_medium_counter"},
        {"reservedNgenJ_WAAP telemetry", "requests_threat_level_high_counter"},
        // WaapTrafficTelemetrics
        {"reservedNgenA_WAAP traffic telemetry", "post_requests_counter"},
        {"reservedNgenB_WAAP traffic telemetry", "get_requests_counter"},
        {"reservedNgenC_WAAP traffic telemetry", "put_requests_counter"},
        {"reservedNgenD_WAAP traffic telemetry", "patch_requests_counter"},
        {"reservedNgenE_WAAP traffic telemetry", "delete_requests_counter"},
        {"reservedNgenF_WAAP traffic telemetry", "other_requests_counter"},
        {"reservedNgenG_WAAP traffic telemetry", "status_code_2xx_responses_counter"},
        {"reservedNgenH_WAAP traffic telemetry", "status_code_4xx_responses_counter"},
        {"reservedNgenI_WAAP traffic telemetry", "status_code_5xx_responses_counter"},
        {"reservedNgenJ_WAAP traffic telemetry", "requests_time_latency_average"},
        // WaapAttackTypesMetrics
        {"reservedNgenA_WAAP attack type telemetry", "sql_injection_attacks_type_counter"},
        {"reservedNgenB_WAAP attack type telemetry", "vulnerability_scanning_attacks_type_counter"},
        {"reservedNgenC_WAAP attack type telemetry", "path_traversal_attacks_type_counter"},
        {"reservedNgenD_WAAP attack type telemetry", "ldap_injection_attacks_type_counter"},
        {"reservedNgenE_WAAP attack type telemetry", "evasion_techniques_attacks_type_counter"},
        {"reservedNgenF_WAAP attack type telemetry", "remote_code_execution_attacks_type_counter"},
        {"reservedNgenG_WAAP attack type telemetry", "xml_extern_entity_attacks_type_counter"},
        {"reservedNgenH_WAAP attack type telemetry", "cross_site_scripting_attacks_type_counter"},
        {"reservedNgenI_WAAP attack type telemetry", "general_attacks_type_counter"},
        // AssetsMetric
        {"numberOfProtectedApiAssetsSample", "api_assets_counter"},
        {"numberOfProtectedWebAppAssetsSample", "web_api_assets_counter"},
        {"numberOfProtectedAssetsSample", "all_assets_counter"},
        // IPSMetric
        {"preventEngineMatchesSample", "prevent_action_matches_counter"},
        {"detectEngineMatchesSample", "detect_action_matches_counter"},
        {"ignoreEngineMatchesSample", "ignore_action_matches_counter"},
        // CPUMetric
        {"cpuMaxSample", "cpu_usage_percentage_max"},
        {"cpuAvgSample", "cpu_usage_percentage_average"},
        {"cpuSample", "cpu_usage_percentage_last_value"},
        // LogMetric
        {"logQueueMaxSizeSample", "logs_queue_size_max"},
        {"logQueueAvgSizeSample", "logs_queue_size_average"},
        {"logQueueCurrentSizeSample", "logs_queue_size_last_value"},
        {"sentLogsSum", "logs_sent_counter"},
        {"sentLogsBulksSum", "bulk_logs_sent_counter"},
        // MemoryMetric
        {"serviceVirtualMemorySizeMaxSample", "service_virtual_memory_size_kb_max"},
        {"serviceVirtualMemorySizeMinSample", "service_virtual_memory_size_kb_min"},
        {"serviceVirtualMemorySizeAvgSample", "service_virtual_memory_size_kb_average"},
        {"serviceRssMemorySizeMaxSample", "service_physical_memory_size_kb_max"},
        {"serviceRssMemorySizeMinSample", "service_physical_memory_size_kb_min"},
        {"serviceRssMemorySizeAvgSample", "service_physical_memory_size_kb_average"},
        {"generalTotalMemorySizeMaxSample", "general_total_used_memory_max"},
        {"generalTotalMemorySizeMinSample", "general_total_used_memory_min"},
        {"generalTotalMemorySizeAvgSample", "general_total_used_memory_average"},
    };

    auto metric_names = original_to_representative_names.find(original_metric_name);
    if (metric_names != original_to_representative_names.end()) return metric_names->second;
    dbgDebug(D_PROMETHEUS)
        << "Metric don't have a representative name, originl name: "
        << original_metric_name;
    return "";
}

#endif // __PROMETHEUS_METRIC_NAMES_H__
