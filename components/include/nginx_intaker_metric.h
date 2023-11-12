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

#ifndef __NGINX_INTAKER_METRIC_H__
#define __NGINX_INTAKER_METRIC_H__

#include "nginx_attachment_common.h"
#include "generic_metric.h"
#include "cpu/cpu_metric.h"


class nginxIntakerEvent : public Event<nginxIntakerEvent>
{
public:
    nginxIntakerEvent() :  cpu_event(0, true) {}

    void resetAllCounters();

    ngx_http_plugin_metric_type_e EnumOfIndex(int i);

    void addPluginMetricCounter(const ngx_http_cp_metric_data_t *recieved_metric_data);

    uint64_t getPluginMetricCounter(ngx_http_plugin_metric_type_e _verdict) const;

    void notifyCPU() const { cpu_event.notify(); }

private:
    uint64_t successfull_inspection_counter = 0;
    uint64_t open_failure_inspection_counter = 0;
    uint64_t close_failure_inspection_counter = 0;
    uint64_t transparent_mode_counter = 0;
    uint64_t total_transparent_time = 0;
    uint64_t accept_verdict_counter = 0;
    uint64_t inspect_verdict_counter = 0;
    uint64_t drop_verdict_counter = 0;
    uint64_t inject_verdict_counter = 0;
    uint64_t irrelevant_verdict_counter = 0;
    uint64_t reconf_verdict_counter = 0;
    uint64_t wait_verdict_counter = 0;
    uint64_t average_overall_processing_time_until_verdict = 0;
    uint64_t max_overall_processing_time_until_verdict = 0;
    uint64_t min_overall_processing_time_until_verdict = 0;
    uint64_t average_req_processing_time_until_verdict = 0;
    uint64_t max_req_processing_time_until_verdict = 0;
    uint64_t min_req_processing_time_until_verdict = 0;
    uint64_t average_res_processing_time_until_verdict = 0;
    uint64_t max_res_processing_time_until_verdict = 0;
    uint64_t min_res_processing_time_until_verdict = 0;
    uint64_t req_failed_compression_counter = 0;
    uint64_t res_failed_compression_counter = 0;
    uint64_t req_failed_decompression_counter = 0;
    uint64_t res_failed_decompression_counter = 0;
    uint64_t req_successful_compression_counter = 0;
    uint64_t res_successful_compression_counter = 0;
    uint64_t req_successful_decompression_counter = 0;
    uint64_t res_successful_decompression_counter = 0;
    uint64_t corrupted_zip_skipped_session_counter = 0;
    uint64_t thread_timeout = 0;
    uint64_t reg_thread_timeout = 0;
    uint64_t req_header_thread_timeout = 0;
    uint64_t req_body_thread_timeout = 0;
    uint64_t average_req_body_size_upon_timeout = 0;
    uint64_t max_req_body_size_upon_timeout = 0;
    uint64_t min_req_body_size_upon_timeout = 0;
    uint64_t res_header_thread_timeout = 0;
    uint64_t res_body_thread_timeout = 0;
    uint64_t average_res_body_size_upon_timeout = 0;
    uint64_t max_res_body_size_upon_timeout = 0;
    uint64_t min_res_body_size_upon_timeout = 0;
    uint64_t thread_failure = 0;
    uint64_t req_proccessing_timeout = 0;
    uint64_t res_proccessing_timeout = 0;
    uint64_t req_failed_to_reach_upstream = 0;
    uint64_t req_overall_size = 0;
    uint64_t res_overall_size = 0;
    CPUEvent cpu_event;
};

class nginxIntakerMetric
        :
    public GenericMetric,
    public Listener<nginxIntakerEvent>
{
public:
    void upon(const nginxIntakerEvent &event) override;

private:
    using Counter = MetricCalculations::Counter;
    using LastValue = MetricCalculations::LastReportedValue<uint64_t>;

    Counter successfull_inspection_counter{this, "successfullInspectionTransactionsSum"};
    Counter open_failure_inspection_counter{this, "failopenTransactionsSum"};
    Counter close_failure_inspection_counter{this, "failcloseTransactionsSum"};
    Counter transparent_mode_counter{this, "transparentModeTransactionsSum"};
    Counter total_transparent_time{this, "totalTimeInTransparentModeSum"};
    Counter inspect_verdict_counter{this, "reachInspectVerdictSum"};
    Counter accept_verdict_counter{this, "reachAcceptVerdictSum"};
    Counter drop_verdict_counter{this, "reachDropVerdictSum"};
    Counter inject_verdict_counter{this, "reachInjectVerdictSum"};
    Counter irrelevant_verdict_counter{this, "reachIrrelevantVerdictSum"};
    Counter reconf_verdict_counter{this, "reachReconfVerdictSum"};
    LastValue average_overall_processing_time_until_verdict{this, "overallSessionProcessTimeToVerdictAvgSample"};
    LastValue max_overall_processing_time_until_verdict{this, "overallSessionProcessTimeToVerdictMaxSample"};
    LastValue min_overall_processing_time_until_verdict{this, "overallSessionProcessTimeToVerdictMinSample"};
    LastValue average_req_processing_time_until_verdict{this, "requestProcessTimeToVerdictAvgSample"};
    LastValue max_req_processing_time_until_verdict{this, "requestProcessTimeToVerdictMaxSample"};
    LastValue min_req_processing_time_until_verdict{this, "requestProcessTimeToVerdictMinSample"};
    LastValue average_res_processing_time_until_verdict{this, "responseProcessTimeToVerdictAvgSample"};
    LastValue max_res_processing_time_until_verdict{this, "responseProcessTimeToVerdictMaxSample"};
    LastValue min_res_processing_time_until_verdict{this, "responseProcessTimeToVerdictMinSample"};
    Counter req_failed_compression_counter{this, "requestCompressionFailureSum"};
    Counter res_failed_compression_counter{this, "responseCompressionFailureSum"};
    Counter req_failed_decompression_counter{this, "requestDecompressionFailureSum"};
    Counter res_failed_decompression_counter{this, "responseDecompressionFailureSum"};
    Counter req_successful_compression_counter{this, "requestCompressionSuccessSum"};
    Counter res_successful_compression_counter{this, "responseCompressionSuccessSum"};
    Counter req_successful_decompression_counter{this, "requestDecompressionSuccessSum"};
    Counter res_successful_decompression_counter{this, "responseDecompressionSuccessSum"};
    Counter corrupted_zip_skipped_session_counter{this, "skippedSessionsUponCorruptedZipSum"};
    Counter thread_timeout{this, "attachmentThreadReachedTimeoutSum"};
    Counter reg_thread_timeout{this, "registrationThreadReachedTimeoutSum"};
    Counter req_header_thread_timeout{this, "requestHeaderThreadReachedTimeoutSum"};
    Counter req_body_thread_timeout{this, "requestBodyThreadReachedTimeoutSum"};
    LastValue average_req_body_size_upon_timeout{this, "requestBodySizeUponTimeoutAvgSample"};
    LastValue max_req_body_size_upon_timeout{this, "requestBodySizeUponTimeoutMaxSample"};
    LastValue min_req_body_size_upon_timeout{this, "requestBodySizeUponTimeoutMinSample"};
    Counter res_header_thread_timeout{this, "respondHeaderThreadReachedTimeoutSum"};
    Counter res_body_thread_timeout{this, "respondBodyThreadReachedTimeoutSum"};
    LastValue average_res_body_size_upon_timeout{this, "responseBodySizeUponTimeoutAvgSample"};
    LastValue max_res_body_size_upon_timeout{this, "responseBodySizeUponTimeoutMaxSample"};
    LastValue min_res_body_size_upon_timeout{this, "responseBodySizeUponTimeoutMinSample"};
    Counter thread_failure{this, "attachmentThreadFailureSum"};
    Counter req_proccessing_timeout{this, "httpRequestProcessingReachedTimeoutSum"};
    Counter res_proccessing_timeout{this, "httpResponseProcessingReachedTimeoutSum"};
    Counter req_overall_size{this, "httpRequestsSizeSum"};
    Counter res_overall_size{this, "httpResponsesSizeSum"};
    Counter req_failed_to_reach_upstream{this, "httpRequestFailedToReachWebServerUpstreamSum"};
};

#endif // __NGINX_INTAKER_METRIC_H__
