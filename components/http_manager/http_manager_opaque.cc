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
HttpManagerOpaque::setApplicationVerdict(const string &app_name, ServiceVerdict verdict)
{
    applications_verdicts[app_name] = verdict;
}

void
HttpManagerOpaque::setApplicationWebResponse(const string &app_name, string web_user_response_id)
{
    dbgTrace(D_HTTP_MANAGER) << "Security app: " << app_name << ", has web user response: " << web_user_response_id;
    applications_web_user_response[app_name] = web_user_response_id;
}

void
HttpManagerOpaque::setCustomResponse(const std::string &app_name, const CustomResponse &custom_response)
{
    dbgTrace(D_HTTP_MANAGER) << "Security app: " << app_name
        << ", has custom response: " << custom_response.getBody()
        << ", with code: " << custom_response.getStatusCode();
    current_custom_response = custom_response;
}

ServiceVerdict
HttpManagerOpaque::getApplicationsVerdict(const string &app_name) const
{
    auto verdict = applications_verdicts.find(app_name);
    return verdict == applications_verdicts.end() ? ServiceVerdict::TRAFFIC_VERDICT_INSPECT : verdict->second;
}

ServiceVerdict
HttpManagerOpaque::getCurrVerdict() const
{
    if (manager_verdict == ServiceVerdict::TRAFFIC_VERDICT_DROP) {
        return manager_verdict;
    }

    ServiceVerdict verdict = ServiceVerdict::TRAFFIC_VERDICT_IRRELEVANT;

    for (const auto &app_verdict_pair : applications_verdicts) {
        int priority = getVerdictPriority(app_verdict_pair.second);
        if (priority < 0) {
            dbgAssertOpt(false)
                << AlertInfo(AlertTeam::CORE, "http manager")
                << "Received unknown verdict "
                << static_cast<int>(app_verdict_pair.second);
            bool is_fail_open = getProfileAgentSettingWithDefault(true, "agent.failOpenState.nginxModule");
            if (!is_fail_open) {
                return ServiceVerdict::TRAFFIC_VERDICT_DROP;
            }
            continue;
        }

        if (getVerdictPriority(app_verdict_pair.second) > getVerdictPriority(verdict)) {
            dbgTrace(D_HTTP_MANAGER)
                << "Updating aggregated verdict to "
                << static_cast<int>(app_verdict_pair.second)
                << " based on app: " << app_verdict_pair.first;
            verdict = app_verdict_pair.second;

            if (verdict == ServiceVerdict::TRAFFIC_VERDICT_DROP) {
                dbgTrace(D_HTTP_MANAGER) << "Verdict DROP for app: " << app_verdict_pair.first;
                auto it = applications_web_user_response.find(app_verdict_pair.first);
                if (it != applications_web_user_response.end() && !it->second.empty()) {
                    current_web_user_response = it->second;
                    dbgTrace(D_HTTP_MANAGER) << "current_web_user_response=" << current_web_user_response;
                    return verdict;
                }
            }
        }
    }

    if (verdict == ServiceVerdict::TRAFFIC_VERDICT_DROP) {
        current_web_user_response = "";
        dbgTrace(D_HTTP_MANAGER) << "current_web_user_response=" << current_web_user_response;
    }

    return verdict;
}

std::set<std::string>
HttpManagerOpaque::getCurrentDropVerdictCausers() const
{
    std::set<std::string> causers;
    if (manager_verdict == ServiceVerdict::TRAFFIC_VERDICT_DROP) {
        causers.insert(HTTP_MANAGER_NAME);
    }
    for (const auto &app_verdict_pair : applications_verdicts) {
        bool was_dropped = app_verdict_pair.second == ServiceVerdict::TRAFFIC_VERDICT_DROP;
        dbgTrace(D_HTTP_MANAGER)
            << "The verdict from: " << app_verdict_pair.first
            << (was_dropped ? " is \"drop\"" : " is not \"drop\" ");
        if (was_dropped) {
            causers.insert(app_verdict_pair.first);
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
