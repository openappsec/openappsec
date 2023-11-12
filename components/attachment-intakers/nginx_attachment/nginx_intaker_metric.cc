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

#include "nginx_intaker_metric.h"

USE_DEBUG_FLAG(D_METRICS_NGINX_ATTACHMENT);

void
nginxIntakerEvent::resetAllCounters()
{
    successfull_inspection_counter = 0;
    open_failure_inspection_counter = 0;
    close_failure_inspection_counter = 0;
    transparent_mode_counter = 0;
    total_transparent_time = 0;
    accept_verdict_counter = 0;
    inspect_verdict_counter = 0;
    drop_verdict_counter = 0;
    inject_verdict_counter = 0;
    irrelevant_verdict_counter = 0;
    reconf_verdict_counter = 0;
    wait_verdict_counter = 0;
    req_failed_compression_counter = 0;
    res_failed_compression_counter = 0;
    req_failed_decompression_counter = 0;
    res_failed_decompression_counter = 0;
    req_successful_compression_counter = 0;
    res_successful_compression_counter = 0;
    req_successful_decompression_counter = 0;
    res_successful_decompression_counter = 0;
    corrupted_zip_skipped_session_counter = 0;
    thread_timeout = 0;
    reg_thread_timeout = 0;
    req_header_thread_timeout = 0;
    req_body_thread_timeout = 0;
    res_header_thread_timeout = 0;
    res_body_thread_timeout = 0;
    thread_failure = 0;
    req_proccessing_timeout = 0;
    res_proccessing_timeout = 0;
    req_failed_to_reach_upstream = 0;
    req_overall_size = 0;
    res_overall_size = 0;
    cpu_event.setCPU(0);
}

ngx_http_plugin_metric_type_e
nginxIntakerEvent::EnumOfIndex(int i)
{
    return static_cast<ngx_http_plugin_metric_type_e>(i);
}

void
nginxIntakerEvent::addPluginMetricCounter(const ngx_http_cp_metric_data_t *recieved_metric_data)
{
    for (int i = 0; i < static_cast<int>(ngx_http_plugin_metric_type_e::METRIC_TYPES_COUNT); i++) {
        ngx_http_plugin_metric_type_e metric_type = EnumOfIndex(i);
        uint64_t amount = recieved_metric_data->data[i];
        switch (metric_type) {
            case ngx_http_plugin_metric_type_e::INSPECTION_SUCCESSES_COUNT: {
                successfull_inspection_counter += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::INSPECTION_OPEN_FAILURES_COUNT: {
                open_failure_inspection_counter += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::INSPECTION_CLOSE_FAILURES_COUNT: {
                close_failure_inspection_counter += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::TRANSPARENTS_COUNT: {
                transparent_mode_counter += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::TOTAL_TRANSPARENTS_TIME: {
                total_transparent_time += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::INSPECT_VERDICTS_COUNT: {
                inspect_verdict_counter += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::ACCEPT_VERDICTS_COUNT: {
                accept_verdict_counter += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::DROP_VERDICTS_COUNT: {
                drop_verdict_counter += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::INJECT_VERDICTS_COUNT: {
                inject_verdict_counter += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::IRRELEVANT_VERDICTS_COUNT: {
                irrelevant_verdict_counter += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::RECONF_VERDICTS_COUNT: {
                reconf_verdict_counter += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::AVERAGE_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT: {
                if (amount > 0) average_overall_processing_time_until_verdict = amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::MAX_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT: {
                if (amount > 0) max_overall_processing_time_until_verdict = amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::MIN_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT: {
                if (amount > 0) min_overall_processing_time_until_verdict = amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::AVERAGE_REQ_PPROCESSING_TIME_UNTIL_VERDICT: {
                if (amount > 0) average_req_processing_time_until_verdict = amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::MAX_REQ_PPROCESSING_TIME_UNTIL_VERDICT: {
                if (amount > 0) max_req_processing_time_until_verdict = amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::MIN_REQ_PPROCESSING_TIME_UNTIL_VERDICT: {
                if (amount > 0) min_req_processing_time_until_verdict = amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::AVERAGE_RES_PPROCESSING_TIME_UNTIL_VERDICT: {
                if (amount > 0) average_res_processing_time_until_verdict = amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::MAX_RES_PPROCESSING_TIME_UNTIL_VERDICT: {
                if (amount > 0) max_res_processing_time_until_verdict = amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::MIN_RES_PPROCESSING_TIME_UNTIL_VERDICT: {
                if (amount > 0) min_res_processing_time_until_verdict = amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::REQ_FAILED_COMPRESSION_COUNT: {
                req_failed_compression_counter += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::RES_FAILED_COMPRESSION_COUNT: {
                res_failed_compression_counter += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::REQ_FAILED_DECOMPRESSION_COUNT: {
                req_failed_decompression_counter += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::RES_FAILED_DECOMPRESSION_COUNT: {
                res_failed_decompression_counter += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::REQ_SUCCESSFUL_COMPRESSION_COUNT: {
                req_successful_compression_counter += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::RES_SUCCESSFUL_COMPRESSION_COUNT: {
                res_successful_compression_counter += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::REQ_SUCCESSFUL_DECOMPRESSION_COUNT: {
                req_successful_decompression_counter += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::RES_SUCCESSFUL_DECOMPRESSION_COUNT: {
                res_successful_decompression_counter += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::CORRUPTED_ZIP_SKIPPED_SESSION_COUNT: {
                corrupted_zip_skipped_session_counter += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::THREAD_TIMEOUT: {
                thread_timeout += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::REG_THREAD_TIMEOUT: {
                reg_thread_timeout += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::REQ_HEADER_THREAD_TIMEOUT: {
                req_header_thread_timeout += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::REQ_BODY_THREAD_TIMEOUT: {
                req_body_thread_timeout += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::AVERAGE_REQ_BODY_SIZE_UPON_TIMEOUT: {
                if (amount > 0) average_req_body_size_upon_timeout = amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::MAX_REQ_BODY_SIZE_UPON_TIMEOUT: {
                if (amount > 0) max_req_body_size_upon_timeout = amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::MIN_REQ_BODY_SIZE_UPON_TIMEOUT: {
                if (amount > 0) min_req_body_size_upon_timeout = amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::RES_HEADER_THREAD_TIMEOUT: {
                res_header_thread_timeout += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::RES_BODY_THREAD_TIMEOUT: {
                res_body_thread_timeout += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::AVERAGE_RES_BODY_SIZE_UPON_TIMEOUT: {
                if (amount > 0) average_res_body_size_upon_timeout = amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::MAX_RES_BODY_SIZE_UPON_TIMEOUT: {
                if (amount > 0) max_res_body_size_upon_timeout = amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::MIN_RES_BODY_SIZE_UPON_TIMEOUT: {
                if (amount > 0) min_res_body_size_upon_timeout = amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::THREAD_FAILURE: {
                thread_failure += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::REQ_PROCCESSING_TIMEOUT: {
                req_proccessing_timeout += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::RES_PROCCESSING_TIMEOUT: {
                res_proccessing_timeout += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::REQ_FAILED_TO_REACH_UPSTREAM: {
                req_failed_to_reach_upstream += amount;
                break;
            }
            case ngx_http_plugin_metric_type_e::CPU_USAGE: {
                cpu_event.setCPU(amount);
                break;
            }
            case ngx_http_plugin_metric_type_e::REQUEST_OVERALL_SIZE_COUNT: {
                req_overall_size += amount;
                static const uint64_t max_expected_res_size = 100ULL * 1024 * 1024 * 1024;
                if (amount > max_expected_res_size) {
                    dbgWarning(D_METRICS_NGINX_ATTACHMENT) << "Requests sizes higher than expected: " << amount;
                }
                break;
            }
            case ngx_http_plugin_metric_type_e::RESPONSE_OVERALL_SIZE_COUNT: {
                res_overall_size += amount;
                break;
            }
            default:
                dbgWarning(D_METRICS_NGINX_ATTACHMENT)
                    << "Unsupported metric type. Type: " << static_cast<int>(metric_type);
                break;
        }
    }
}

uint64_t
nginxIntakerEvent::getPluginMetricCounter(ngx_http_plugin_metric_type_e metric_type) const
{
    switch (metric_type) {
        case ngx_http_plugin_metric_type_e::INSPECTION_SUCCESSES_COUNT:
            return successfull_inspection_counter;
        case ngx_http_plugin_metric_type_e::INSPECTION_OPEN_FAILURES_COUNT:
            return open_failure_inspection_counter;
        case ngx_http_plugin_metric_type_e::INSPECTION_CLOSE_FAILURES_COUNT:
            return close_failure_inspection_counter;
        case ngx_http_plugin_metric_type_e::TRANSPARENTS_COUNT:
            return transparent_mode_counter;
        case ngx_http_plugin_metric_type_e::TOTAL_TRANSPARENTS_TIME:
            return total_transparent_time;
        case ngx_http_plugin_metric_type_e::INSPECT_VERDICTS_COUNT:
            return inspect_verdict_counter;
        case ngx_http_plugin_metric_type_e::ACCEPT_VERDICTS_COUNT:
            return accept_verdict_counter;
        case ngx_http_plugin_metric_type_e::DROP_VERDICTS_COUNT:
            return drop_verdict_counter;
        case ngx_http_plugin_metric_type_e::INJECT_VERDICTS_COUNT:
            return inject_verdict_counter;
        case ngx_http_plugin_metric_type_e::IRRELEVANT_VERDICTS_COUNT:
            return irrelevant_verdict_counter;
        case ngx_http_plugin_metric_type_e::RECONF_VERDICTS_COUNT:
            return reconf_verdict_counter;
        case ngx_http_plugin_metric_type_e::AVERAGE_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT:
            return average_overall_processing_time_until_verdict;
        case ngx_http_plugin_metric_type_e::MAX_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT:
            return max_overall_processing_time_until_verdict;
        case ngx_http_plugin_metric_type_e::MIN_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT:
            return min_overall_processing_time_until_verdict;
        case ngx_http_plugin_metric_type_e::AVERAGE_REQ_PPROCESSING_TIME_UNTIL_VERDICT:
            return average_req_processing_time_until_verdict;
        case ngx_http_plugin_metric_type_e::MAX_REQ_PPROCESSING_TIME_UNTIL_VERDICT:
            return max_req_processing_time_until_verdict;
        case ngx_http_plugin_metric_type_e::MIN_REQ_PPROCESSING_TIME_UNTIL_VERDICT:
            return min_req_processing_time_until_verdict;
        case ngx_http_plugin_metric_type_e::AVERAGE_RES_PPROCESSING_TIME_UNTIL_VERDICT:
            return average_res_processing_time_until_verdict;
        case ngx_http_plugin_metric_type_e::MAX_RES_PPROCESSING_TIME_UNTIL_VERDICT:
            return max_res_processing_time_until_verdict;
        case ngx_http_plugin_metric_type_e::MIN_RES_PPROCESSING_TIME_UNTIL_VERDICT:
            return min_res_processing_time_until_verdict;
        case ngx_http_plugin_metric_type_e::REQ_FAILED_COMPRESSION_COUNT:
            return req_failed_compression_counter;
        case ngx_http_plugin_metric_type_e::RES_FAILED_COMPRESSION_COUNT:
            return res_failed_compression_counter;
        case ngx_http_plugin_metric_type_e::REQ_FAILED_DECOMPRESSION_COUNT:
            return req_failed_decompression_counter;
        case ngx_http_plugin_metric_type_e::RES_FAILED_DECOMPRESSION_COUNT:
            return res_failed_decompression_counter;
        case ngx_http_plugin_metric_type_e::REQ_SUCCESSFUL_COMPRESSION_COUNT:
            return req_successful_compression_counter;
        case ngx_http_plugin_metric_type_e::RES_SUCCESSFUL_COMPRESSION_COUNT:
            return res_successful_compression_counter;
        case ngx_http_plugin_metric_type_e::REQ_SUCCESSFUL_DECOMPRESSION_COUNT:
            return req_successful_decompression_counter;
        case ngx_http_plugin_metric_type_e::RES_SUCCESSFUL_DECOMPRESSION_COUNT:
            return res_successful_decompression_counter;
        case ngx_http_plugin_metric_type_e::CORRUPTED_ZIP_SKIPPED_SESSION_COUNT:
            return corrupted_zip_skipped_session_counter;
        case ngx_http_plugin_metric_type_e::THREAD_TIMEOUT:
            return thread_timeout;
        case ngx_http_plugin_metric_type_e::REG_THREAD_TIMEOUT:
            return reg_thread_timeout;
        case ngx_http_plugin_metric_type_e::REQ_HEADER_THREAD_TIMEOUT:
            return req_header_thread_timeout;
        case ngx_http_plugin_metric_type_e::REQ_BODY_THREAD_TIMEOUT:
            return req_body_thread_timeout;
        case ngx_http_plugin_metric_type_e::AVERAGE_REQ_BODY_SIZE_UPON_TIMEOUT:
            return average_req_body_size_upon_timeout;
        case ngx_http_plugin_metric_type_e::MAX_REQ_BODY_SIZE_UPON_TIMEOUT:
            return max_req_body_size_upon_timeout;
        case ngx_http_plugin_metric_type_e::MIN_REQ_BODY_SIZE_UPON_TIMEOUT:
            return min_req_body_size_upon_timeout;
        case ngx_http_plugin_metric_type_e::RES_HEADER_THREAD_TIMEOUT:
            return res_header_thread_timeout;
        case ngx_http_plugin_metric_type_e::RES_BODY_THREAD_TIMEOUT:
            return res_body_thread_timeout;
        case ngx_http_plugin_metric_type_e::AVERAGE_RES_BODY_SIZE_UPON_TIMEOUT:
            return average_res_body_size_upon_timeout;
        case ngx_http_plugin_metric_type_e::MAX_RES_BODY_SIZE_UPON_TIMEOUT:
            return max_res_body_size_upon_timeout;
        case ngx_http_plugin_metric_type_e::MIN_RES_BODY_SIZE_UPON_TIMEOUT:
            return min_res_body_size_upon_timeout;
        case ngx_http_plugin_metric_type_e::THREAD_FAILURE:
            return thread_failure;
        case ngx_http_plugin_metric_type_e::REQ_PROCCESSING_TIMEOUT:
            return req_proccessing_timeout;
        case ngx_http_plugin_metric_type_e::RES_PROCCESSING_TIMEOUT:
            return res_proccessing_timeout;
        case ngx_http_plugin_metric_type_e::REQ_FAILED_TO_REACH_UPSTREAM:
            return req_failed_to_reach_upstream;
        case ngx_http_plugin_metric_type_e::CPU_USAGE:
            return static_cast<uint64_t>(cpu_event.getCPU());
        case ngx_http_plugin_metric_type_e::REQUEST_OVERALL_SIZE_COUNT:
            return req_overall_size;
        case ngx_http_plugin_metric_type_e::RESPONSE_OVERALL_SIZE_COUNT:
            return res_overall_size;
        default:
            dbgWarning(D_METRICS_NGINX_ATTACHMENT)
                    << "Unsupported metric type. Type: " << static_cast<int>(metric_type);
            return 0;
    }
}

void
nginxIntakerMetric::upon(const nginxIntakerEvent &event)
{
    successfull_inspection_counter.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::INSPECTION_SUCCESSES_COUNT)
    );
    transparent_mode_counter.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::TRANSPARENTS_COUNT)
    );
    total_transparent_time.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::TOTAL_TRANSPARENTS_TIME)
    );
    open_failure_inspection_counter.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::INSPECTION_OPEN_FAILURES_COUNT)
    );
    close_failure_inspection_counter.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::INSPECTION_CLOSE_FAILURES_COUNT)
    );
    inject_verdict_counter.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::INJECT_VERDICTS_COUNT)
    );
    inspect_verdict_counter.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::INSPECT_VERDICTS_COUNT)
    );
    accept_verdict_counter.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::ACCEPT_VERDICTS_COUNT)
    );
    drop_verdict_counter.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::DROP_VERDICTS_COUNT)
    );
    irrelevant_verdict_counter.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::IRRELEVANT_VERDICTS_COUNT)
    );
    reconf_verdict_counter.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::RECONF_VERDICTS_COUNT)
    );
    average_overall_processing_time_until_verdict.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::AVERAGE_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT)
    );
    max_overall_processing_time_until_verdict.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::MAX_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT)
    );
    min_overall_processing_time_until_verdict.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::MIN_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT)
    );
    average_req_processing_time_until_verdict.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::AVERAGE_REQ_PPROCESSING_TIME_UNTIL_VERDICT)
    );
    max_req_processing_time_until_verdict.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::MAX_REQ_PPROCESSING_TIME_UNTIL_VERDICT)
    );
    min_req_processing_time_until_verdict.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::MIN_REQ_PPROCESSING_TIME_UNTIL_VERDICT)
    );
    average_res_processing_time_until_verdict.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::AVERAGE_RES_PPROCESSING_TIME_UNTIL_VERDICT)
    );
    max_res_processing_time_until_verdict.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::MAX_RES_PPROCESSING_TIME_UNTIL_VERDICT)
    );
    min_res_processing_time_until_verdict.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::MIN_RES_PPROCESSING_TIME_UNTIL_VERDICT)
    );
    req_failed_compression_counter.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::REQ_FAILED_COMPRESSION_COUNT)
    );
    res_failed_compression_counter.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::RES_FAILED_COMPRESSION_COUNT)
    );
    req_failed_decompression_counter.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::REQ_FAILED_DECOMPRESSION_COUNT)
    );
    res_failed_decompression_counter.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::RES_FAILED_DECOMPRESSION_COUNT)
    );
    req_successful_compression_counter.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::REQ_SUCCESSFUL_COMPRESSION_COUNT)
    );
    res_successful_compression_counter.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::RES_SUCCESSFUL_COMPRESSION_COUNT)
    );
    req_successful_decompression_counter.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::REQ_SUCCESSFUL_DECOMPRESSION_COUNT)
    );
    res_successful_decompression_counter.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::RES_SUCCESSFUL_DECOMPRESSION_COUNT)
    );
    corrupted_zip_skipped_session_counter.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::CORRUPTED_ZIP_SKIPPED_SESSION_COUNT)
    );
    thread_timeout.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::THREAD_TIMEOUT)
    );
    reg_thread_timeout.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::REG_THREAD_TIMEOUT)
    );
    req_header_thread_timeout.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::REQ_HEADER_THREAD_TIMEOUT)
    );
    req_body_thread_timeout.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::REQ_BODY_THREAD_TIMEOUT)
    );
    average_req_body_size_upon_timeout.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::AVERAGE_REQ_BODY_SIZE_UPON_TIMEOUT)
    );
    max_req_body_size_upon_timeout.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::MAX_REQ_BODY_SIZE_UPON_TIMEOUT)
    );
    min_req_body_size_upon_timeout.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::MIN_REQ_BODY_SIZE_UPON_TIMEOUT)
    );
    res_header_thread_timeout.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::RES_HEADER_THREAD_TIMEOUT)
    );
    res_body_thread_timeout.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::RES_BODY_THREAD_TIMEOUT)
    );
    average_res_body_size_upon_timeout.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::AVERAGE_RES_BODY_SIZE_UPON_TIMEOUT)
    );
    max_res_body_size_upon_timeout.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::MAX_RES_BODY_SIZE_UPON_TIMEOUT)
    );
    min_res_body_size_upon_timeout.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::MIN_RES_BODY_SIZE_UPON_TIMEOUT)
    );
    thread_failure.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::THREAD_FAILURE)
    );
    req_proccessing_timeout.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::REQ_PROCCESSING_TIMEOUT)
    );
    res_proccessing_timeout.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::RES_PROCCESSING_TIMEOUT)
    );
    req_failed_to_reach_upstream.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::REQ_FAILED_TO_REACH_UPSTREAM)
    );
    req_overall_size.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::REQUEST_OVERALL_SIZE_COUNT)
    );
    res_overall_size.report(
        event.getPluginMetricCounter(ngx_http_plugin_metric_type_e::RESPONSE_OVERALL_SIZE_COUNT)
    );
    event.notifyCPU();
}
