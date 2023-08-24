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

#include "http_manager_opaque.h"

#include "config.h"

using namespace std;

USE_DEBUG_FLAG(D_HTTP_MANAGER);

HttpManagerOpaque::HttpManagerOpaque()
        :
    TableOpaqueSerialize<HttpManagerOpaque>(this),
    prev_data_cache()
{
}

void
HttpManagerOpaque::setApplicationVerdict(const string &app_name, ngx_http_cp_verdict_e verdict)
{
    applications_verdicts[app_name] = verdict;
}

ngx_http_cp_verdict_e
HttpManagerOpaque::getApplicationsVerdict(const string &app_name) const
{
    auto verdict = applications_verdicts.find(app_name);
    return verdict == applications_verdicts.end() ? ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INSPECT : verdict->second;
}

ngx_http_cp_verdict_e
HttpManagerOpaque::getCurrVerdict() const
{
    if (manager_verdict == ngx_http_cp_verdict_e::TRAFFIC_VERDICT_DROP) {
        return manager_verdict;
    }

    uint accepted_apps = 0;
    ngx_http_cp_verdict_e verdict = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INSPECT;
    for (const auto &app_verdic_pair : applications_verdicts) {
        switch (app_verdic_pair.second) {
            case ngx_http_cp_verdict_e::TRAFFIC_VERDICT_DROP:
                return app_verdic_pair.second;
            case ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INJECT:
                verdict = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INJECT;
                break;
            case ngx_http_cp_verdict_e::TRAFFIC_VERDICT_ACCEPT:
                accepted_apps++;
                break;
            case ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INSPECT:
                break;
            case ngx_http_cp_verdict_e::TRAFFIC_VERDICT_IRRELEVANT:
                dbgTrace(D_HTTP_MANAGER) << "Verdict 'Irrelevant' is not yet supported. Returning Accept";
                accepted_apps++;
                break;
            case ngx_http_cp_verdict_e::TRAFFIC_VERDICT_WAIT:
                verdict = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_WAIT;
                break;
            default:
                dbgAssert(false)
                    << "Received unknown verdict "
                    << static_cast<int>(app_verdic_pair.second);
        }
    }

    return accepted_apps == applications_verdicts.size() ? ngx_http_cp_verdict_e::TRAFFIC_VERDICT_ACCEPT : verdict;
}

void
HttpManagerOpaque::saveCurrentDataToCache(const Buffer &full_data)
{
    uint data_cache_size = getConfigurationWithDefault<uint>(0, "HTTP manager", "Previous Buffer Cache size");
    if (data_cache_size == 0) {
        prev_data_cache.clear();
        return;
    }
    prev_data_cache = full_data.getSubBuffer(
        full_data.size() <= data_cache_size ? 0 : full_data.size() - data_cache_size,
        full_data.size()
    );
}

void
HttpManagerOpaque::updatePayloadSize(const uint curr_payload_size)
{
    aggregated_payload_size += curr_payload_size;
}
