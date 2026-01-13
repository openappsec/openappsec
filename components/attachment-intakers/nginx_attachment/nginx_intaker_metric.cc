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

AttachmentMetricType
nginxIntakerEvent::EnumOfIndex(int i)
{
    return static_cast<AttachmentMetricType>(i);
}

void
nginxIntakerEvent::addPluginMetricCounter(const NanoHttpMetricData *recieved_metric_data)
{
    for (int i = 0; i < static_cast<int>(AttachmentMetricType::METRIC_TYPES_COUNT); i++) {
        AttachmentMetricType metric_type = EnumOfIndex(i);
        uint64_t amount = recieved_metric_data->data[i];
        switch (metric_type) {
            case AttachmentMetricType::INSPECTION_SUCCESSES_COUNT: {
                successfull_inspection_counter += amount;
                break;
            }
            case AttachmentMetricType::INSPECTION_OPEN_FAILURES_COUNT: {
                open_failure_inspection_counter += amount;
                break;
            }
            case AttachmentMetricType::INSPECTION_CLOSE_FAILURES_COUNT: {
                close_failure_inspection_counter += amount;
                break;
            }
            case AttachmentMetricType::TRANSPARENTS_COUNT: {
                transparent_mode_counter += amount;
                break;
            }
            case AttachmentMetricType::TOTAL_TRANSPARENTS_TIME: {
                total_transparent_time += amount;
                break;
            }
            case AttachmentMetricType::INSPECT_VERDICTS_COUNT: {
                inspect_verdict_counter += amount;
                break;
            }
            case AttachmentMetricType::ACCEPT_VERDICTS_COUNT: {
                accept_verdict_counter += amount;
                break;
            }
            case AttachmentMetricType::DROP_VERDICTS_COUNT: {
                drop_verdict_counter += amount;
                break;
            }
            case AttachmentMetricType::INJECT_VERDICTS_COUNT: {
                inject_verdict_counter += amount;
                break;
            }
            case AttachmentMetricType::IRRELEVANT_VERDICTS_COUNT: {
                irrelevant_verdict_counter += amount;
                break;
            }
            case AttachmentMetricType::RECONF_VERDICTS_COUNT: {
                reconf_verdict_counter += amount;
                break;
            }
            case AttachmentMetricType::AVERAGE_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT: {
                if (amount > 0) average_overall_processing_time_until_verdict = amount;
                break;
            }
            case AttachmentMetricType::MAX_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT: {
                if (amount > 0) max_overall_processing_time_until_verdict = amount;
                break;
            }
            case AttachmentMetricType::MIN_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT: {
                if (amount > 0) min_overall_processing_time_until_verdict = amount;
                break;
            }
            case AttachmentMetricType::AVERAGE_REQ_PPROCESSING_TIME_UNTIL_VERDICT: {
                if (amount > 0) average_req_processing_time_until_verdict = amount;
                break;
            }
            case AttachmentMetricType::MAX_REQ_PPROCESSING_TIME_UNTIL_VERDICT: {
                if (amount > 0) max_req_processing_time_until_verdict = amount;
                break;
            }
            case AttachmentMetricType::MIN_REQ_PPROCESSING_TIME_UNTIL_VERDICT: {
                if (amount > 0) min_req_processing_time_until_verdict = amount;
                break;
            }
            case AttachmentMetricType::AVERAGE_RES_PPROCESSING_TIME_UNTIL_VERDICT: {
                if (amount > 0) average_res_processing_time_until_verdict = amount;
                break;
            }
            case AttachmentMetricType::MAX_RES_PPROCESSING_TIME_UNTIL_VERDICT: {
                if (amount > 0) max_res_processing_time_until_verdict = amount;
                break;
            }
            case AttachmentMetricType::MIN_RES_PPROCESSING_TIME_UNTIL_VERDICT: {
                if (amount > 0) min_res_processing_time_until_verdict = amount;
                break;
            }
            case AttachmentMetricType::REQ_FAILED_COMPRESSION_COUNT: {
                req_failed_compression_counter += amount;
                break;
            }
            case AttachmentMetricType::RES_FAILED_COMPRESSION_COUNT: {
                res_failed_compression_counter += amount;
                break;
            }
            case AttachmentMetricType::REQ_FAILED_DECOMPRESSION_COUNT: {
                req_failed_decompression_counter += amount;
                break;
            }
            case AttachmentMetricType::RES_FAILED_DECOMPRESSION_COUNT: {
                res_failed_decompression_counter += amount;
                break;
            }
            case AttachmentMetricType::REQ_SUCCESSFUL_COMPRESSION_COUNT: {
                req_successful_compression_counter += amount;
                break;
            }
            case AttachmentMetricType::RES_SUCCESSFUL_COMPRESSION_COUNT: {
                res_successful_compression_counter += amount;
                break;
            }
            case AttachmentMetricType::REQ_SUCCESSFUL_DECOMPRESSION_COUNT: {
                req_successful_decompression_counter += amount;
                break;
            }
            case AttachmentMetricType::RES_SUCCESSFUL_DECOMPRESSION_COUNT: {
                res_successful_decompression_counter += amount;
                break;
            }
            case AttachmentMetricType::CORRUPTED_ZIP_SKIPPED_SESSION_COUNT: {
                corrupted_zip_skipped_session_counter += amount;
                break;
            }
            case AttachmentMetricType::THREAD_TIMEOUT: {
                thread_timeout += amount;
                break;
            }
            case AttachmentMetricType::REG_THREAD_TIMEOUT: {
                reg_thread_timeout += amount;
                break;
            }
            case AttachmentMetricType::REQ_HEADER_THREAD_TIMEOUT: {
                req_header_thread_timeout += amount;
                break;
            }
            case AttachmentMetricType::REQ_BODY_THREAD_TIMEOUT: {
                req_body_thread_timeout += amount;
                break;
            }
            case AttachmentMetricType::AVERAGE_REQ_BODY_SIZE_UPON_TIMEOUT: {
                if (amount > 0) average_req_body_size_upon_timeout = amount;
                break;
            }
            case AttachmentMetricType::MAX_REQ_BODY_SIZE_UPON_TIMEOUT: {
                if (amount > 0) max_req_body_size_upon_timeout = amount;
                break;
            }
            case AttachmentMetricType::MIN_REQ_BODY_SIZE_UPON_TIMEOUT: {
                if (amount > 0) min_req_body_size_upon_timeout = amount;
                break;
            }
            case AttachmentMetricType::RES_HEADER_THREAD_TIMEOUT: {
                res_header_thread_timeout += amount;
                break;
            }
            case AttachmentMetricType::RES_BODY_THREAD_TIMEOUT: {
                res_body_thread_timeout += amount;
                break;
            }
            case AttachmentMetricType::AVERAGE_RES_BODY_SIZE_UPON_TIMEOUT: {
                if (amount > 0) average_res_body_size_upon_timeout = amount;
                break;
            }
            case AttachmentMetricType::MAX_RES_BODY_SIZE_UPON_TIMEOUT: {
                if (amount > 0) max_res_body_size_upon_timeout = amount;
                break;
            }
            case AttachmentMetricType::MIN_RES_BODY_SIZE_UPON_TIMEOUT: {
                if (amount > 0) min_res_body_size_upon_timeout = amount;
                break;
            }
            case AttachmentMetricType::THREAD_FAILURE: {
                thread_failure += amount;
                break;
            }
            case AttachmentMetricType::REQ_PROCCESSING_TIMEOUT: {
                req_proccessing_timeout += amount;
                break;
            }
            case AttachmentMetricType::RES_PROCCESSING_TIMEOUT: {
                res_proccessing_timeout += amount;
                break;
            }
            case AttachmentMetricType::REQ_FAILED_TO_REACH_UPSTREAM: {
                req_failed_to_reach_upstream += amount;
                break;
            }
            case AttachmentMetricType::CPU_USAGE: {
                cpu_event.setCPU(amount);
                break;
            }
            case AttachmentMetricType::REQUEST_OVERALL_SIZE_COUNT: {
                req_overall_size += amount;
                static const uint64_t max_expected_res_size = 100ULL * 1024 * 1024 * 1024;
                if (amount > max_expected_res_size) {
                    dbgWarning(D_METRICS_NGINX_ATTACHMENT) << "Requests sizes higher than expected: " << amount;
                }
                break;
            }
            case AttachmentMetricType::RESPONSE_OVERALL_SIZE_COUNT: {
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
nginxIntakerEvent::getPluginMetricCounter(AttachmentMetricType metric_type) const
{
    switch (metric_type) {
        case AttachmentMetricType::INSPECTION_SUCCESSES_COUNT:
            return successfull_inspection_counter;
        case AttachmentMetricType::INSPECTION_OPEN_FAILURES_COUNT:
            return open_failure_inspection_counter;
        case AttachmentMetricType::INSPECTION_CLOSE_FAILURES_COUNT:
            return close_failure_inspection_counter;
        case AttachmentMetricType::TRANSPARENTS_COUNT:
            return transparent_mode_counter;
        case AttachmentMetricType::TOTAL_TRANSPARENTS_TIME:
            return total_transparent_time;
        case AttachmentMetricType::INSPECT_VERDICTS_COUNT:
            return inspect_verdict_counter;
        case AttachmentMetricType::ACCEPT_VERDICTS_COUNT:
            return accept_verdict_counter;
        case AttachmentMetricType::DROP_VERDICTS_COUNT:
            return drop_verdict_counter;
        case AttachmentMetricType::INJECT_VERDICTS_COUNT:
            return inject_verdict_counter;
        case AttachmentMetricType::IRRELEVANT_VERDICTS_COUNT:
            return irrelevant_verdict_counter;
        case AttachmentMetricType::RECONF_VERDICTS_COUNT:
            return reconf_verdict_counter;
        case AttachmentMetricType::AVERAGE_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT:
            return average_overall_processing_time_until_verdict;
        case AttachmentMetricType::MAX_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT:
            return max_overall_processing_time_until_verdict;
        case AttachmentMetricType::MIN_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT:
            return min_overall_processing_time_until_verdict;
        case AttachmentMetricType::AVERAGE_REQ_PPROCESSING_TIME_UNTIL_VERDICT:
            return average_req_processing_time_until_verdict;
        case AttachmentMetricType::MAX_REQ_PPROCESSING_TIME_UNTIL_VERDICT:
            return max_req_processing_time_until_verdict;
        case AttachmentMetricType::MIN_REQ_PPROCESSING_TIME_UNTIL_VERDICT:
            return min_req_processing_time_until_verdict;
        case AttachmentMetricType::AVERAGE_RES_PPROCESSING_TIME_UNTIL_VERDICT:
            return average_res_processing_time_until_verdict;
        case AttachmentMetricType::MAX_RES_PPROCESSING_TIME_UNTIL_VERDICT:
            return max_res_processing_time_until_verdict;
        case AttachmentMetricType::MIN_RES_PPROCESSING_TIME_UNTIL_VERDICT:
            return min_res_processing_time_until_verdict;
        case AttachmentMetricType::REQ_FAILED_COMPRESSION_COUNT:
            return req_failed_compression_counter;
        case AttachmentMetricType::RES_FAILED_COMPRESSION_COUNT:
            return res_failed_compression_counter;
        case AttachmentMetricType::REQ_FAILED_DECOMPRESSION_COUNT:
            return req_failed_decompression_counter;
        case AttachmentMetricType::RES_FAILED_DECOMPRESSION_COUNT:
            return res_failed_decompression_counter;
        case AttachmentMetricType::REQ_SUCCESSFUL_COMPRESSION_COUNT:
            return req_successful_compression_counter;
        case AttachmentMetricType::RES_SUCCESSFUL_COMPRESSION_COUNT:
            return res_successful_compression_counter;
        case AttachmentMetricType::REQ_SUCCESSFUL_DECOMPRESSION_COUNT:
            return req_successful_decompression_counter;
        case AttachmentMetricType::RES_SUCCESSFUL_DECOMPRESSION_COUNT:
            return res_successful_decompression_counter;
        case AttachmentMetricType::CORRUPTED_ZIP_SKIPPED_SESSION_COUNT:
            return corrupted_zip_skipped_session_counter;
        case AttachmentMetricType::THREAD_TIMEOUT:
            return thread_timeout;
        case AttachmentMetricType::REG_THREAD_TIMEOUT:
            return reg_thread_timeout;
        case AttachmentMetricType::REQ_HEADER_THREAD_TIMEOUT:
            return req_header_thread_timeout;
        case AttachmentMetricType::REQ_BODY_THREAD_TIMEOUT:
            return req_body_thread_timeout;
        case AttachmentMetricType::AVERAGE_REQ_BODY_SIZE_UPON_TIMEOUT:
            return average_req_body_size_upon_timeout;
        case AttachmentMetricType::MAX_REQ_BODY_SIZE_UPON_TIMEOUT:
            return max_req_body_size_upon_timeout;
        case AttachmentMetricType::MIN_REQ_BODY_SIZE_UPON_TIMEOUT:
            return min_req_body_size_upon_timeout;
        case AttachmentMetricType::RES_HEADER_THREAD_TIMEOUT:
            return res_header_thread_timeout;
        case AttachmentMetricType::RES_BODY_THREAD_TIMEOUT:
            return res_body_thread_timeout;
        case AttachmentMetricType::AVERAGE_RES_BODY_SIZE_UPON_TIMEOUT:
            return average_res_body_size_upon_timeout;
        case AttachmentMetricType::MAX_RES_BODY_SIZE_UPON_TIMEOUT:
            return max_res_body_size_upon_timeout;
        case AttachmentMetricType::MIN_RES_BODY_SIZE_UPON_TIMEOUT:
            return min_res_body_size_upon_timeout;
        case AttachmentMetricType::THREAD_FAILURE:
            return thread_failure;
        case AttachmentMetricType::REQ_PROCCESSING_TIMEOUT:
            return req_proccessing_timeout;
        case AttachmentMetricType::RES_PROCCESSING_TIMEOUT:
            return res_proccessing_timeout;
        case AttachmentMetricType::REQ_FAILED_TO_REACH_UPSTREAM:
            return req_failed_to_reach_upstream;
        case AttachmentMetricType::CPU_USAGE:
            return static_cast<uint64_t>(cpu_event.getCPU());
        case AttachmentMetricType::REQUEST_OVERALL_SIZE_COUNT:
            return req_overall_size;
        case AttachmentMetricType::RESPONSE_OVERALL_SIZE_COUNT:
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
        event.getPluginMetricCounter(AttachmentMetricType::INSPECTION_SUCCESSES_COUNT)
    );
    transparent_mode_counter.report(
        event.getPluginMetricCounter(AttachmentMetricType::TRANSPARENTS_COUNT)
    );
    total_transparent_time.report(
        event.getPluginMetricCounter(AttachmentMetricType::TOTAL_TRANSPARENTS_TIME)
    );
    open_failure_inspection_counter.report(
        event.getPluginMetricCounter(AttachmentMetricType::INSPECTION_OPEN_FAILURES_COUNT)
    );
    close_failure_inspection_counter.report(
        event.getPluginMetricCounter(AttachmentMetricType::INSPECTION_CLOSE_FAILURES_COUNT)
    );
    inject_verdict_counter.report(
        event.getPluginMetricCounter(AttachmentMetricType::INJECT_VERDICTS_COUNT)
    );
    inspect_verdict_counter.report(
        event.getPluginMetricCounter(AttachmentMetricType::INSPECT_VERDICTS_COUNT)
    );
    accept_verdict_counter.report(
        event.getPluginMetricCounter(AttachmentMetricType::ACCEPT_VERDICTS_COUNT)
    );
    drop_verdict_counter.report(
        event.getPluginMetricCounter(AttachmentMetricType::DROP_VERDICTS_COUNT)
    );
    irrelevant_verdict_counter.report(
        event.getPluginMetricCounter(AttachmentMetricType::IRRELEVANT_VERDICTS_COUNT)
    );
    reconf_verdict_counter.report(
        event.getPluginMetricCounter(AttachmentMetricType::RECONF_VERDICTS_COUNT)
    );
    average_overall_processing_time_until_verdict.report(
        event.getPluginMetricCounter(AttachmentMetricType::AVERAGE_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT)
    );
    max_overall_processing_time_until_verdict.report(
        event.getPluginMetricCounter(AttachmentMetricType::MAX_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT)
    );
    min_overall_processing_time_until_verdict.report(
        event.getPluginMetricCounter(AttachmentMetricType::MIN_OVERALL_PPROCESSING_TIME_UNTIL_VERDICT)
    );
    average_req_processing_time_until_verdict.report(
        event.getPluginMetricCounter(AttachmentMetricType::AVERAGE_REQ_PPROCESSING_TIME_UNTIL_VERDICT)
    );
    max_req_processing_time_until_verdict.report(
        event.getPluginMetricCounter(AttachmentMetricType::MAX_REQ_PPROCESSING_TIME_UNTIL_VERDICT)
    );
    min_req_processing_time_until_verdict.report(
        event.getPluginMetricCounter(AttachmentMetricType::MIN_REQ_PPROCESSING_TIME_UNTIL_VERDICT)
    );
    average_res_processing_time_until_verdict.report(
        event.getPluginMetricCounter(AttachmentMetricType::AVERAGE_RES_PPROCESSING_TIME_UNTIL_VERDICT)
    );
    max_res_processing_time_until_verdict.report(
        event.getPluginMetricCounter(AttachmentMetricType::MAX_RES_PPROCESSING_TIME_UNTIL_VERDICT)
    );
    min_res_processing_time_until_verdict.report(
        event.getPluginMetricCounter(AttachmentMetricType::MIN_RES_PPROCESSING_TIME_UNTIL_VERDICT)
    );
    req_failed_compression_counter.report(
        event.getPluginMetricCounter(AttachmentMetricType::REQ_FAILED_COMPRESSION_COUNT)
    );
    res_failed_compression_counter.report(
        event.getPluginMetricCounter(AttachmentMetricType::RES_FAILED_COMPRESSION_COUNT)
    );
    req_failed_decompression_counter.report(
        event.getPluginMetricCounter(AttachmentMetricType::REQ_FAILED_DECOMPRESSION_COUNT)
    );
    res_failed_decompression_counter.report(
        event.getPluginMetricCounter(AttachmentMetricType::RES_FAILED_DECOMPRESSION_COUNT)
    );
    req_successful_compression_counter.report(
        event.getPluginMetricCounter(AttachmentMetricType::REQ_SUCCESSFUL_COMPRESSION_COUNT)
    );
    res_successful_compression_counter.report(
        event.getPluginMetricCounter(AttachmentMetricType::RES_SUCCESSFUL_COMPRESSION_COUNT)
    );
    req_successful_decompression_counter.report(
        event.getPluginMetricCounter(AttachmentMetricType::REQ_SUCCESSFUL_DECOMPRESSION_COUNT)
    );
    res_successful_decompression_counter.report(
        event.getPluginMetricCounter(AttachmentMetricType::RES_SUCCESSFUL_DECOMPRESSION_COUNT)
    );
    corrupted_zip_skipped_session_counter.report(
        event.getPluginMetricCounter(AttachmentMetricType::CORRUPTED_ZIP_SKIPPED_SESSION_COUNT)
    );
    thread_timeout.report(
        event.getPluginMetricCounter(AttachmentMetricType::THREAD_TIMEOUT)
    );
    reg_thread_timeout.report(
        event.getPluginMetricCounter(AttachmentMetricType::REG_THREAD_TIMEOUT)
    );
    req_header_thread_timeout.report(
        event.getPluginMetricCounter(AttachmentMetricType::REQ_HEADER_THREAD_TIMEOUT)
    );
    req_body_thread_timeout.report(
        event.getPluginMetricCounter(AttachmentMetricType::REQ_BODY_THREAD_TIMEOUT)
    );
    average_req_body_size_upon_timeout.report(
        event.getPluginMetricCounter(AttachmentMetricType::AVERAGE_REQ_BODY_SIZE_UPON_TIMEOUT)
    );
    max_req_body_size_upon_timeout.report(
        event.getPluginMetricCounter(AttachmentMetricType::MAX_REQ_BODY_SIZE_UPON_TIMEOUT)
    );
    min_req_body_size_upon_timeout.report(
        event.getPluginMetricCounter(AttachmentMetricType::MIN_REQ_BODY_SIZE_UPON_TIMEOUT)
    );
    res_header_thread_timeout.report(
        event.getPluginMetricCounter(AttachmentMetricType::RES_HEADER_THREAD_TIMEOUT)
    );
    res_body_thread_timeout.report(
        event.getPluginMetricCounter(AttachmentMetricType::RES_BODY_THREAD_TIMEOUT)
    );
    average_res_body_size_upon_timeout.report(
        event.getPluginMetricCounter(AttachmentMetricType::AVERAGE_RES_BODY_SIZE_UPON_TIMEOUT)
    );
    max_res_body_size_upon_timeout.report(
        event.getPluginMetricCounter(AttachmentMetricType::MAX_RES_BODY_SIZE_UPON_TIMEOUT)
    );
    min_res_body_size_upon_timeout.report(
        event.getPluginMetricCounter(AttachmentMetricType::MIN_RES_BODY_SIZE_UPON_TIMEOUT)
    );
    thread_failure.report(
        event.getPluginMetricCounter(AttachmentMetricType::THREAD_FAILURE)
    );
    req_proccessing_timeout.report(
        event.getPluginMetricCounter(AttachmentMetricType::REQ_PROCCESSING_TIMEOUT)
    );
    res_proccessing_timeout.report(
        event.getPluginMetricCounter(AttachmentMetricType::RES_PROCCESSING_TIMEOUT)
    );
    req_failed_to_reach_upstream.report(
        event.getPluginMetricCounter(AttachmentMetricType::REQ_FAILED_TO_REACH_UPSTREAM)
    );
    req_overall_size.report(
        event.getPluginMetricCounter(AttachmentMetricType::REQUEST_OVERALL_SIZE_COUNT)
    );
    res_overall_size.report(
        event.getPluginMetricCounter(AttachmentMetricType::RESPONSE_OVERALL_SIZE_COUNT)
    );
    event.notifyCPU();
}
