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

void
HttpManagerOpaque::setApplicationWebResponse(const string &app_name, string web_user_response_id)
{
    dbgTrace(D_HTTP_MANAGER) << "Security app: " << app_name << ", has web user response: " << web_user_response_id;
    applications_web_user_response[app_name] = web_user_response_id;
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
                dbgTrace(D_HTTP_MANAGER) << "Verdict DROP for app: " << app_verdic_pair.first;
                current_web_user_response = applications_web_user_response.at(app_verdic_pair.first);
                dbgTrace(D_HTTP_MANAGER) << "current_web_user_response=" << current_web_user_response;
                return app_verdic_pair.second;
            case ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INJECT:
                // Sent in ResponseHeaders and ResponseBody.
                verdict = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INJECT;
                break;
            case ngx_http_cp_verdict_e::TRAFFIC_VERDICT_ACCEPT:
                accepted_apps++;
                break;
            case ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INSPECT:
                break;
            case ngx_http_cp_verdict_e::LIMIT_RESPONSE_HEADERS:
                // Sent in End Request.
                verdict = ngx_http_cp_verdict_e::LIMIT_RESPONSE_HEADERS;
                break;
            case ngx_http_cp_verdict_e::TRAFFIC_VERDICT_IRRELEVANT:
                dbgTrace(D_HTTP_MANAGER) << "Verdict 'Irrelevant' is not yet supported. Returning Accept";
                accepted_apps++;
                break;
            case ngx_http_cp_verdict_e::TRAFFIC_VERDICT_WAIT:
                // Sent in Request Headers and Request Body.
                verdict = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_WAIT;
                break;
            default:
                dbgAssert(false)
                    << AlertInfo(AlertTeam::CORE, "http manager")
                    << "Received unknown verdict "
                    << static_cast<int>(app_verdic_pair.second);
        }
    }

    return accepted_apps == applications_verdicts.size() ? ngx_http_cp_verdict_e::TRAFFIC_VERDICT_ACCEPT : verdict;
}

std::set<std::string>
HttpManagerOpaque::getCurrentDropVerdictCausers() const
{
    std::set<std::string> causers;
    if (manager_verdict == ngx_http_cp_verdict_e::TRAFFIC_VERDICT_DROP) {
        causers.insert(HTTP_MANAGER_NAME);
    }
    for (const auto &app_verdic_pair : applications_verdicts) {
        bool was_dropped = app_verdic_pair.second == ngx_http_cp_verdict_e::TRAFFIC_VERDICT_DROP;
        dbgTrace(D_HTTP_MANAGER)
            << "The verdict from: " << app_verdic_pair.first
            << (was_dropped ? " is \"drop\"" : " is not \"drop\" ");
        if (was_dropped) {
            causers.insert(app_verdic_pair.first);
        }
    }
    return causers;
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
