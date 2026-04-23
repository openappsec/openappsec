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

#include "http_manager.h"

#include <string>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <boost/algorithm/string.hpp>
#include <fstream>
#include <algorithm>

#include "common.h"
#include "config.h"
#include "http_manager_opaque.h"
#include "log_generator.h"
#include "http_inspection_events.h"
#include "agent_core_utilities.h"

USE_DEBUG_FLAG(D_HTTP_MANAGER);

using namespace std;

static ostream &
operator<<(ostream &os, const EventVerdict &event)
{
    switch (event.getVerdict()) {
        case ServiceVerdict::TRAFFIC_VERDICT_INSPECT: return os << "Inspect";
        case ServiceVerdict::LIMIT_RESPONSE_HEADERS: return os << "Limit Response Headers";
        case ServiceVerdict::TRAFFIC_VERDICT_ACCEPT: return os << "Accept";
        case ServiceVerdict::TRAFFIC_VERDICT_DROP: return os << "Drop";
        case ServiceVerdict::TRAFFIC_VERDICT_INJECT: return os << "Inject";
        case ServiceVerdict::TRAFFIC_VERDICT_IRRELEVANT: return os << "Irrelevant";
        case ServiceVerdict::TRAFFIC_VERDICT_RECONF: return os << "Reconf";
        case ServiceVerdict::TRAFFIC_VERDICT_DELAYED: return os << "Wait";
        case ServiceVerdict::TRAFFIC_VERDICT_CUSTOM_RESPONSE: return os << "Force 200";
    }

    dbgAssert(false)
        << AlertInfo(AlertTeam::CORE, "http manager")
        << "Illegal Event Verdict value: "
        << static_cast<uint>(event.getVerdict());
    return os;
}

class HttpManager::Impl
        :
    Singleton::Provide<I_HttpManager>::From<HttpManager>
{
public:
    void
    init()
    {
        dbgFlow(D_HTTP_MANAGER);

        i_transaction_table = Singleton::Consume<I_Table>::by<HttpManager>();

        Singleton::Consume<I_Logging>::by<HttpManager>()->addGeneralModifier(compressAppSecLogs);
        custom_header = getProfileAgentSettingWithDefault<string>("", "agent.customHeaderValueLogging");

        registerConfigLoadCb(
            [this]() {
                custom_header = getProfileAgentSettingWithDefault<string>("", "agent.customHeaderValueLogging");
            }
    );
    }

    FilterVerdict
    inspect(const HttpTransactionData &event) override
    {
        if (!i_transaction_table->createState<HttpManagerOpaque>()) {
            dbgWarning(D_HTTP_MANAGER) << "Failed to create new transaction table state - Returning default verdict.";
            return FilterVerdict(default_verdict);
        }

        ScopedContext ctx;
        ctx.registerValue(app_sec_marker_key, i_transaction_table->keyToString(), EnvKeyAttr::LogSection::MARKER);

        return handleEvent(NewHttpTransactionEvent(event).performNamedQuery());
    }

    FilterVerdict
    inspect(const HttpHeader &event, bool is_request) override
    {
        if (!i_transaction_table->hasState<HttpManagerOpaque>()) {
            dbgWarning(D_HTTP_MANAGER) << "Transaction state was not found - Returning default verdict.";
            return FilterVerdict(default_verdict);
        }

        ScopedContext ctx;
        ctx.registerValue(app_sec_marker_key, i_transaction_table->keyToString(), EnvKeyAttr::LogSection::MARKER);

        HttpManagerOpaque &state = i_transaction_table->getState<HttpManagerOpaque>();

        if (event.getKey().isEqualLowerCase(custom_header)) {
            string event_value = static_cast<string>(event.getValue());
            dbgTrace(D_HTTP_MANAGER)
                << "Found header key and value - ("
                << custom_header
                << ": "
                << event_value
                << ") that matched agent settings";
            state.setUserDefinedValue(event_value);
        }

        if (state.getUserDefinedValue().ok()) {
            ctx.registerValue("UserDefined", state.getUserDefinedValue().unpack(), EnvKeyAttr::LogSection::DATA);
        }

        auto event_responds =
            is_request ?
            HttpRequestHeaderEvent(event).performNamedQuery() :
            HttpResponseHeaderEvent(event).performNamedQuery();
        FilterVerdict verdict = handleEvent(event_responds);
        if (verdict.getVerdict() == ServiceVerdict::TRAFFIC_VERDICT_INJECT) {
            applyInjectionModifications(verdict, event_responds, event.getHeaderIndex());
        }
        return verdict;
    }

    FilterVerdict
    inspect(const HttpBody &event, bool is_request) override
    {
        if (!i_transaction_table->hasState<HttpManagerOpaque>()) {
            dbgWarning(D_HTTP_MANAGER) << "Transaction state was not found - Returning default verdict.";
            return FilterVerdict(default_verdict);
        }

        ServiceVerdict body_size_limit_verdict = handleBodySizeLimit(is_request, event);
        if (body_size_limit_verdict != ServiceVerdict::TRAFFIC_VERDICT_INSPECT) {
            return FilterVerdict(body_size_limit_verdict);
        }

        HttpManagerOpaque &state = i_transaction_table->getState<HttpManagerOpaque>();

        ScopedContext ctx;
        ctx.registerValue(app_sec_marker_key, i_transaction_table->keyToString(), EnvKeyAttr::LogSection::MARKER);
        if (state.getUserDefinedValue().ok()) {
            ctx.registerValue("UserDefined", state.getUserDefinedValue().unpack(), EnvKeyAttr::LogSection::DATA);
        }

        FilterVerdict verdict(ServiceVerdict::TRAFFIC_VERDICT_INSPECT);
        if (!is_request && event.getData().size() == 0 && !event.isLastChunk()) {
            dbgDebug(D_HTTP_MANAGER) << "Skipping inspection of first empty chunk for respond body";
            return verdict;
        }

        auto event_responds =
            is_request ?
            HttpRequestBodyEvent(event, state.getPreviousDataCache()).performNamedQuery() :
            HttpResponseBodyEvent(event, state.getPreviousDataCache()).performNamedQuery();
        verdict = handleEvent(event_responds);
        state.saveCurrentDataToCache(event.getData());
        if (verdict.getVerdict() == ServiceVerdict::TRAFFIC_VERDICT_INJECT) {
            applyInjectionModifications(verdict, event_responds, event.getBodyChunkIndex());
        }
        return verdict;
    }

    FilterVerdict
    inspect(const ResponseCode &event) override
    {
        if (!i_transaction_table->hasState<HttpManagerOpaque>()) {
            dbgWarning(D_HTTP_MANAGER) << "Transaction state was not found - Returning default verdict.";
            return FilterVerdict(default_verdict);
        }

        ScopedContext ctx;
        ctx.registerValue(app_sec_marker_key, i_transaction_table->keyToString(), EnvKeyAttr::LogSection::MARKER);

        HttpManagerOpaque &state = i_transaction_table->getState<HttpManagerOpaque>();
        if (state.getUserDefinedValue().ok()) {
            ctx.registerValue("UserDefined", state.getUserDefinedValue().unpack(), EnvKeyAttr::LogSection::DATA);
        }

        return handleEvent(ResponseCodeEvent(event).performNamedQuery());
    }

    FilterVerdict
    inspectEndRequest() override
    {
        if (!i_transaction_table->hasState<HttpManagerOpaque>()) {
            dbgWarning(D_HTTP_MANAGER) << "Transaction state was not found - Returning default verdict.";
            return FilterVerdict(default_verdict);
        }

        HttpManagerOpaque &state = i_transaction_table->getState<HttpManagerOpaque>();
        state.resetPayloadSize();

        ScopedContext ctx;
        ctx.registerValue(app_sec_marker_key, i_transaction_table->keyToString(), EnvKeyAttr::LogSection::MARKER);
        if (state.getUserDefinedValue().ok()) {
            ctx.registerValue("UserDefined", state.getUserDefinedValue().unpack(), EnvKeyAttr::LogSection::DATA);
        }
        return handleEvent(EndRequestEvent().performNamedQuery());
    }

    FilterVerdict
    inspectEndTransaction() override
    {
        if (!i_transaction_table->hasState<HttpManagerOpaque>()) {
            dbgWarning(D_HTTP_MANAGER) << "Transaction state was not found - Returning default verdict.";
            return FilterVerdict(default_verdict);
        }

        HttpManagerOpaque &state = i_transaction_table->getState<HttpManagerOpaque>();
        state.resetPayloadSize();

        ScopedContext ctx;
        ctx.registerValue(app_sec_marker_key, i_transaction_table->keyToString(), EnvKeyAttr::LogSection::MARKER);
        if (state.getUserDefinedValue().ok()) {
            ctx.registerValue("UserDefined", state.getUserDefinedValue().unpack(), EnvKeyAttr::LogSection::DATA);
        }

        return handleEvent(EndTransactionEvent().performNamedQuery());
    }

    FilterVerdict
    inspectDelayedVerdict() override
    {
        if (!i_transaction_table->hasState<HttpManagerOpaque>()) {
            dbgWarning(D_HTTP_MANAGER) << "Transaction state was not found - Returning default verdict.";
            return FilterVerdict(default_verdict);
        }

        ScopedContext ctx;
        ctx.registerValue(app_sec_marker_key, i_transaction_table->keyToString(), EnvKeyAttr::LogSection::MARKER);

        HttpManagerOpaque &state = i_transaction_table->getState<HttpManagerOpaque>();
        if (state.getUserDefinedValue().ok()) {
            ctx.registerValue("UserDefined", state.getUserDefinedValue().unpack(), EnvKeyAttr::LogSection::DATA);
        }

        return handleEvent(WaitTransactionEvent().performNamedQuery());
    }

    void
    sendPolicyLog()
    {
        LogGen(
            "Web AppSec Policy Loaded Successfully",
            ReportIS::Audience::SECURITY,
            ReportIS::Severity::INFO,
            ReportIS::Priority::LOW,
            ReportIS::Tags::THREAT_PREVENTION
        );
    }

private:
    ServiceVerdict
    handleBodySizeLimit(bool is_request_body_type, const HttpBody &event)
    {
        HttpManagerOpaque &state = i_transaction_table->getState<HttpManagerOpaque>();
        state.updatePayloadSize(event.getData().size());

        auto size_limit = getConfigurationWithCache<uint>(
            "HTTP manager",
            is_request_body_type ? "Max Request Body Size" : "Max Response Body Size"
        );

        string size_limit_verdict = getConfigurationWithDefault<string>(
            "Accept",
            "HTTP manager",
            is_request_body_type ? "Request Size Limit Verdict" : "Response Size Limit Verdict"
        );

        if (!size_limit.ok() || state.getAggeregatedPayloadSize() < size_limit.unpack()) {
            return ServiceVerdict::TRAFFIC_VERDICT_INSPECT;
        }

        ServiceVerdict verdict = size_limit_verdict == "Drop" ?
            ServiceVerdict::TRAFFIC_VERDICT_DROP :
            ServiceVerdict::TRAFFIC_VERDICT_ACCEPT;

        dbgDebug(D_HTTP_MANAGER)
            << "Transaction body size is over the limit. Max body size: "
            << size_limit.unpack()
            << ", Returned verdict: "
            << size_limit_verdict
            << ".";

        state.setManagerVerdict(verdict);
        return verdict;
    }

    static void
    applyInjectionModifications(
        FilterVerdict &verdict,
        const vector<pair<string, EventVerdict>> &event_responds,
        ModifiedChunkIndex event_idx)
    {
        for (const pair<string, EventVerdict> &respond : event_responds) {
            if (respond.second.getVerdict() == ServiceVerdict::TRAFFIC_VERDICT_INJECT) {
                dbgTrace(D_HTTP_MANAGER)
                    << "Applying inject verdict modifications for security App: "
                    << respond.first;
                verdict.addModifications(respond.second.getModifications(), event_idx);
            }
        }
    }

    FilterVerdict
    handleEvent(const vector<pair<string, EventVerdict>> &event_responds)
    {
        HttpManagerOpaque &state = i_transaction_table->getState<HttpManagerOpaque>();

        for (const pair<string, EventVerdict> &respond : event_responds) {
            if (state.getApplicationsVerdict(respond.first) == ServiceVerdict::TRAFFIC_VERDICT_ACCEPT) {
                dbgTrace(D_HTTP_MANAGER)
                    << "Skipping event verdict for app that already accepted traffic. App: "
                    << respond.first;
                continue;
            }

            dbgTrace(D_HTTP_MANAGER)
                << "Security app "
                << respond.first
                << " returned verdict "
                << respond.second.getVerdict();

            state.setApplicationVerdict(respond.first, respond.second.getVerdict());
            state.setApplicationWebResponse(respond.first, respond.second.getWebUserResponseByPractice());
            if (respond.second.getVerdict() == ServiceVerdict::TRAFFIC_VERDICT_CUSTOM_RESPONSE) {
                if (!respond.second.getCustomResponse().ok()) {
                    dbgWarning(D_HTTP_MANAGER)
                        << "Security app: "
                        << respond.first
                        << ", returned verdict CUSTOM_RESPONSE, but no custom response was found.";
                    continue;
                }
                state.setCustomResponse(respond.first, respond.second.getCustomResponse().unpack());
            }
        }
        auto ver = state.getCurrVerdict();
        dbgTrace(D_HTTP_MANAGER) << "Aggregated verdict is: " << ver;
        if (ver == ServiceVerdict::TRAFFIC_VERDICT_CUSTOM_RESPONSE) {
            if (!state.getCurrentCustomResponse().ok()) {
                dbgWarning(D_HTTP_MANAGER) << "No custom response found for verdict CUSTOM_RESPONSE";
                return FilterVerdict(ServiceVerdict::TRAFFIC_VERDICT_ACCEPT);
            }
            return FilterVerdict(ver, state.getCurrentCustomResponse().unpack());
        } else {
            FilterVerdict aggregated_verdict(ver, state.getCurrWebUserResponse());
            if (aggregated_verdict.getVerdict() == ServiceVerdict::TRAFFIC_VERDICT_DROP) {
                SecurityAppsDropEvent(state.getCurrentDropVerdictCausers()).notify();
            }
            return aggregated_verdict;
        }
    }

    static void
    compressAppSecLogs(LogBulkRest &bulk)
    {
        dbgTrace(D_HTTP_MANAGER) << "Starting to reduce logs";

        map<string, uint> app_sec_logs_by_key;

        for (const auto &log : bulk) {
            auto &markers = log.getMarkers();
            auto appsec_marker = markers.find(app_sec_marker_key);
            if (appsec_marker != markers.end()) app_sec_logs_by_key[appsec_marker->second]++;
        }

        for (const auto &specific_set_of_logs : app_sec_logs_by_key) {
            if (specific_set_of_logs.second > 1) reduceLogs(bulk, specific_set_of_logs.first);
        }

        dbgTrace(D_HTTP_MANAGER) << "Finished logs reduction";
    }

    static void
    reduceLogs(LogBulkRest &bulk, const string &current_id)
    {
        dbgTrace(D_HTTP_MANAGER) << "Reducing logs for marker " << current_id;

        vector<vector<Report>::iterator> relevent_logs;
        vector<Report>::iterator keep_log = bulk.end();
        for (auto curr_log = bulk.begin(); curr_log != bulk.end(); ++curr_log) {
            if (isRelevantLog(curr_log, current_id)) {
                relevent_logs.push_back(curr_log);
                if (keep_log == bulk.end() || (isPreventLog(curr_log) && !isPreventLog(keep_log))) keep_log = curr_log;
            }
        }

        dbgTrace(D_HTTP_MANAGER) << "Found " << relevent_logs.size() << " logs that match marker " << current_id;

        // Reverse iteration to avoid iterator invalidation
        for (auto iter = relevent_logs.rbegin(); iter != relevent_logs.rend(); ++iter) {
            if (*iter != keep_log) bulk.erase(*iter);
        }

        dbgTrace(D_HTTP_MANAGER) << "Finished going over maker " << current_id;
    }

    static bool
    isRelevantLog(const vector<Report>::iterator &log, const string &current_id)
    {
        const auto &markers = log->getMarkers();
        auto app_sec_marker = markers.find(app_sec_marker_key);
        if (app_sec_marker == markers.end()) return false;
        return app_sec_marker->second == current_id;
    }

    static bool
    isPreventLog(const vector<Report>::iterator &log)
    {
        auto res = log->getStringData("securityAction");
        return res.ok() && *res == "Prevent";
    }

    I_Table *i_transaction_table;
    string custom_header = "";
    static const ServiceVerdict default_verdict;
    static const string app_sec_marker_key;
};

const ServiceVerdict HttpManager::Impl::default_verdict(ServiceVerdict::TRAFFIC_VERDICT_DROP);
const string HttpManager::Impl::app_sec_marker_key = "app_sec_marker";

HttpManager::HttpManager() : Component("HttpManager"), pimpl(make_unique<Impl>()) {}
HttpManager::~HttpManager() {}

void HttpManager::init() { pimpl->init(); }

void
HttpManager::preload()
{
    registerExpectedConfigurationWithCache<uint>("assetId", "HTTP manager", "Previous Buffer Cache size");
    registerExpectedConfigurationWithCache<uint>("assetId", "HTTP manager", "Max Request Body Size");
    registerExpectedConfigurationWithCache<uint>("assetId", "HTTP manager", "Max Response Body Size");
    registerExpectedConfigurationWithCache<string>("assetId", "HTTP manager", "Request Size Limit Verdict");
    registerExpectedConfigurationWithCache<string>("assetId", "HTTP manager", "Response Size Limit Verdict");
    registerConfigLoadCb([this] () { pimpl->sendPolicyLog(); });
}
