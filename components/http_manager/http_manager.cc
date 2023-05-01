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
#include <sys/stat.h>
#include <climits>
#include <unordered_map>
#include <boost/range/iterator_range.hpp>
#include <fstream>
#include <algorithm>

#include "common.h"
#include "config.h"
#include "table_opaque.h"
#include "http_manager_opaque.h"
#include "log_generator.h"
#include "http_inspection_events.h"

USE_DEBUG_FLAG(D_HTTP_MANAGER);

using namespace std;

static ostream &
operator<<(ostream &os, const EventVerdict &event)
{
    switch (event.getVerdict()) {
        case ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INSPECT: return os << "Inspect";
        case ngx_http_cp_verdict_e::TRAFFIC_VERDICT_ACCEPT: return os << "Accept";
        case ngx_http_cp_verdict_e::TRAFFIC_VERDICT_DROP: return os << "Drop";
        case ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INJECT: return os << "Inject";
        case ngx_http_cp_verdict_e::TRAFFIC_VERDICT_IRRELEVANT: return os << "Irrelevant";
        case ngx_http_cp_verdict_e::TRAFFIC_VERDICT_RECONF: return os << "Reconf";
        case ngx_http_cp_verdict_e::TRAFFIC_VERDICT_WAIT: return os << "Wait";
    }

    dbgAssert(false) << "Illegal Event Verdict value: " << static_cast<uint>(event.getVerdict());
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
        string event_key = static_cast<string>(event.getKey());
        if (event_key == getProfileAgentSettingWithDefault<string>("", "agent.customHeaderValueLogging")) {
            string event_value = static_cast<string>(event.getValue());
            dbgTrace(D_HTTP_MANAGER)
                << "Found header key and value - ("
                << event_key
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
        if (verdict.getVerdict() == ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INJECT) {
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

        ngx_http_cp_verdict_e body_size_limit_verdict = handleBodySizeLimit(is_request, event);
        if (body_size_limit_verdict != ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INSPECT) {
            return FilterVerdict(body_size_limit_verdict);
        }

        HttpManagerOpaque &state = i_transaction_table->getState<HttpManagerOpaque>();

        ScopedContext ctx;
        ctx.registerValue(app_sec_marker_key, i_transaction_table->keyToString(), EnvKeyAttr::LogSection::MARKER);
        if (state.getUserDefinedValue().ok()) {
            ctx.registerValue("UserDefined", state.getUserDefinedValue().unpack(), EnvKeyAttr::LogSection::DATA);
        }

        FilterVerdict verdict(ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INSPECT);
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
        if (verdict.getVerdict() == ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INJECT) {
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
    ngx_http_cp_verdict_e
    handleBodySizeLimit(bool is_request_body_type, const HttpBody &event)
    {
        HttpManagerOpaque &state = i_transaction_table->getState<HttpManagerOpaque>();
        state.updatePayloadSize(event.getData().size());

        auto size_limit = getConfiguration<uint>(
            "HTTP manager",
            is_request_body_type ? "Max Request Body Size" : "Max Response Body Size"
        );

        string size_limit_verdict = getConfigurationWithDefault<string>(
            "Accept",
            "HTTP manager",
            is_request_body_type ? "Request Size Limit Verdict" : "Response Size Limit Verdict"
        );

        if (!size_limit.ok() || state.getAggeregatedPayloadSize() < size_limit.unpack()) {
            return ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INSPECT;
        }

        ngx_http_cp_verdict_e verdict = size_limit_verdict == "Drop" ?
            ngx_http_cp_verdict_e::TRAFFIC_VERDICT_DROP :
            ngx_http_cp_verdict_e::TRAFFIC_VERDICT_ACCEPT;

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
            if (respond.second.getVerdict() == ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INJECT) {
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
            if (state.getApplicationsVerdict(respond.first) == ngx_http_cp_verdict_e::TRAFFIC_VERDICT_ACCEPT) {
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
        }

        return state.getCurrVerdict();
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
    static const ngx_http_cp_verdict_e default_verdict;
    static const string app_sec_marker_key;
};

const ngx_http_cp_verdict_e HttpManager::Impl::default_verdict(ngx_http_cp_verdict_e::TRAFFIC_VERDICT_DROP);
const string HttpManager::Impl::app_sec_marker_key = "app_sec_marker";

HttpManager::HttpManager() : Component("HttpManager"), pimpl(make_unique<Impl>()) {}
HttpManager::~HttpManager() {}

void HttpManager::init() { pimpl->init(); }

void
HttpManager::preload()
{
    registerExpectedConfiguration<uint>("HTTP manager", "Previous Buffer Cache size");
    registerExpectedConfiguration<uint>("HTTP manager", "Max Request Body Size");
    registerExpectedConfiguration<uint>("HTTP manager", "Max Response Body Size");
    registerExpectedConfiguration<string>("HTTP manager", "Request Size Limit Verdict");
    registerExpectedConfiguration<string>("HTTP manager", "Response Size Limit Verdict");
    registerConfigLoadCb([this] () { pimpl->sendPolicyLog(); });
}
