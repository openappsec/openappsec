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

#define WAF2_LOGGING_ENABLE

#include <unordered_set>
#include <fstream>
#include <arpa/inet.h>
#include <boost/tokenizer.hpp>
#include <boost/noncopyable.hpp>
#include <sys/stat.h>
#include <stdlib.h>
#include <iostream>
#include <libxml/parser.h>

#include "debug.h"
#include "waap_clib/WaapAssetStatesManager.h"
#include "waap_clib/Waf2Engine.h"
#include "waap_clib/WaapConfigApi.h"
#include "waap_clib/WaapConfigApplication.h"
#include "waap_clib/WaapDecision.h"
#include "telemetry.h"
#include "waap_clib/DeepAnalyzer.h"
#include "waap_component_impl.h"
#include "i_waapConfig.h"
#include "generic_rulebase/rulebase_config.h"
#include "report_messaging.h"
#include "first_request_object.h"

using namespace std;

USE_DEBUG_FLAG(D_WAAP);
USE_DEBUG_FLAG(D_WAAP_ULIMITS);
USE_DEBUG_FLAG(D_OA_SCHEMA_UPDATER);

WaapComponent::Impl::Impl() :
    pending_response(ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INSPECT),
    accept_response(ngx_http_cp_verdict_e::TRAFFIC_VERDICT_ACCEPT),
    drop_response(ngx_http_cp_verdict_e::TRAFFIC_VERDICT_DROP),
    waapStateTable(NULL),
    transactionsCount(0),
    deepAnalyzer()
{
}

WaapComponent::Impl::~Impl()
{
}

// Called when component is initialized
void
WaapComponent::Impl::init()
{
    std::string waapDataFileName = getConfigurationWithDefault<string>(
        "/etc/cp/conf/waap/waap.data",
        "WAAP",
        "Sigs file path"
    );

    assets_metric.init(
        "Assets Count",
        ReportIS::AudienceTeam::AGENT_CORE,
        ReportIS::IssuingEngine::AGENT_CORE,
        std::chrono::minutes(10),
        true,
        ReportIS::Audience::INTERNAL
    );
    assets_metric.registerListener();
    registerListener();
    waap_metric.registerListener();

    init(waapDataFileName);
}

void
WaapComponent::Impl::init(const std::string &waapDataFileName)
{
    //waf2_set_log_target(WAF2_LOGTARGET_STDERR);
    dbgTrace(D_WAAP) << "WaapComponent::Impl::init() ...";

    reputationAggregator.init();

    waapStateTable = Singleton::Consume<I_Table>::by<WaapComponent>();
    
    bool success = waf2_proc_start(waapDataFileName);
    if (!success) {
        dbgWarning(D_WAAP) << "WAF2 engine FAILED to initialize (probably failed to load signatures). Aborting!";
        waf2_proc_exit();
        return;
    }

    dbgTrace(D_WAAP) << "WaapComponent::Impl::init() signatures loaded succesfully.";

    I_StaticResourcesHandler *static_resources = Singleton::Consume<I_StaticResourcesHandler>::by<WaapComponent>();
    static_resources->registerStaticResource("cp-ab.js", "/etc/cp/conf/waap/cp-ab.js");
    static_resources->registerStaticResource("cp-csrf.js", "/etc/cp/conf/waap/cp-csrf.js");
}

// Called when component is shut down
void
WaapComponent::Impl::fini()
{
    dbgTrace(D_WAAP) << "WaapComponent::impl::fini(). Shutting down waap engine before exiting...";
    unregisterListener();
    waf2_proc_exit();
}

std::string
WaapComponent::Impl::getListenerName() const
{
    return "waap application";
}

// Start request (called before headers arrive). However, the method and URL path is known at this stage.
// Should return pending_response to hold the data (not send to upstream)
EventVerdict
WaapComponent::Impl::respond(const NewHttpTransactionEvent &event)
{
    dbgTrace(D_WAAP) << " * \e[32mNGEN_EVENT: NewTransactionEvent\e[0m";

    if (waapStateTable->hasState<Waf2Transaction>()) {
        dbgWarning(D_WAAP) << " * \e[31 -- NewTransactionEvent called twice on same entry \e[0m";
        return drop_response;
    }

    I_WaapAssetStatesManager* pWaapAssetStatesManager =
        Singleton::Consume<I_WaapAssetStatesManager>::by<WaapComponent>();
    std::shared_ptr<WaapAssetState> pCurrentWaapAssetState = pWaapAssetStatesManager->getWaapAssetStateGlobal();

    if (!pCurrentWaapAssetState || pCurrentWaapAssetState->getSignatures()->fail())
    {
        dbgTrace(D_WAAP) << "WaapComponent::Impl::UponEvent(NewTransactionEvent): couldn't get WaapAssetState ...";
        return drop_response;
    }

    dbgTrace(D_WAAP) << "WaapComponent::Impl::UponEvent(NewTransactionEvent): creating state...";
    if(!waapStateTable->createState<Waf2Transaction>(pCurrentWaapAssetState)) {
        dbgWarning(D_WAAP) << " * \e[31 -- NewTransactionEvent failed to create new state in table\e[0m";
        return drop_response;
    }

    if (!waapStateTable->hasState<Waf2Transaction>()) {
        dbgWarning(D_WAAP) << " * \e[31 -- NewTransactionEvent state was created but still missing \e[0m";
        return drop_response;
    }

    IWaf2Transaction& waf2Transaction = waapStateTable->getState<Waf2Transaction>();

    // Assign unique numeric index to this transaction
    waf2Transaction.setIndex(transactionsCount++);

    std::string uri = event.getURI();
    std::string httpMethodStr = event.getHttpMethod();

    dbgTrace(D_WAAP) << "start Transaction: " << httpMethodStr << " " << uri << " (REQUEST)";
    // See below..
    Waf2TransactionFlags &waf2TransactionFlags = waf2Transaction.getTransactionFlags();
    waf2TransactionFlags.requestDataPushStarted = false;
    waf2TransactionFlags.endResponseHeadersCalled = false;
    waf2TransactionFlags.responseDataPushStarted = false;

    waf2Transaction.start();

    char sourceIpStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(event.getSourceIP()), sourceIpStr, INET_ADDRSTRLEN);

    char listeningIpStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(event.getListeningIP()), listeningIpStr, INET_ADDRSTRLEN);

    // Set envelope data
    waf2Transaction.set_transaction_remote(sourceIpStr, event.getSourcePort());
    waf2Transaction.set_transaction_local(listeningIpStr, event.getListeningPort());

    waf2Transaction.set_method(httpMethodStr.c_str());
    waf2Transaction.set_uri(uri.c_str());

    // Tell waf2 API that request headers started
    waf2Transaction.start_request_hdrs();


    return pending_response;
}


// Request headers coming
// Should return pending_response to hold the data (not send to upstream)
EventVerdict
WaapComponent::Impl::respond(const HttpRequestHeaderEvent &event)
{
    auto &header_name = event.getKey();
    auto &header_value = event.getValue();

    dbgTrace(D_WAAP)
        << " * \e[32mNGEN_EVENT: HttpHeaderRequest event: "
        << string(header_name)
        << ": "
        << string(header_value)
        << "\e[0m";

    if (!waapStateTable->hasState<Waf2Transaction>()) {
        dbgWarning(D_WAAP)
            << " * \e[31mNGEN_EVENT: http_header - "
            << "failed to get waf2 transaction, state not exist\e[0m";

        return drop_response;
    }
    IWaf2Transaction& waf2Transaction = waapStateTable->getState<Waf2Transaction>();

    // Tell waf2 API that another request header arrived
    waf2Transaction.add_request_hdr(
        reinterpret_cast<const char *>(header_name.data()),  //const char * name //
        header_name.size(),  //int name_len //
        reinterpret_cast<const char *>(header_value.data()), //const char * value //
        header_value.size()  //int value_len //
    );

    EventVerdict verdict = pending_response;

    // Last header handled
    if (event.isLastHeader()) {
        waf2Transaction.end_request_hdrs();

        verdict = waf2Transaction.getUserLimitVerdict();

        if (verdict.getVerdict() == pending_response.getVerdict()) {
            // waapDecision returns one of these verdicts: accept, drop, pending
            // PENDING verdict (also called INSPECT by ngen core) will be returned if the waap engine wants to also
            // inspect response.
            verdict = waapDecisionAfterHeaders(waf2Transaction);
        }

    }

    // Delete state before returning any verdict which is not pending
    if ((verdict.getVerdict() != pending_response.getVerdict()) &&  waapStateTable->hasState<Waf2Transaction>()) {
        finishTransaction(waf2Transaction);
    } else {
    }

    return verdict;
}

// Request body pieces coming.
// Should return pending_response to hold the data (not send to upstream)
EventVerdict
WaapComponent::Impl::respond(const HttpRequestBodyEvent &event)
{
    dbgTrace(D_WAAP) << " * \e[32mNGEN_EVENT: HttpBodyRequest data buffer event\e[0m";

    if (!waapStateTable->hasState<Waf2Transaction>()) {
        dbgWarning(D_WAAP) <<
            " * \e[31mNGEN_EVENT: data buffer - failed to get waf2 transaction, state not exist\e[0m";
        return drop_response;
    }

    IWaf2Transaction& waf2Transaction = waapStateTable->getState<Waf2Transaction>();
    Waf2TransactionFlags &waf2TransactionFlags = waf2Transaction.getTransactionFlags();

    // Do this only once (on first request body data packet)
    if (!waf2TransactionFlags.requestDataPushStarted) {
        dbgTrace(D_WAAP) << "first request body packet";
        waf2Transaction.start_request_body();
        waf2TransactionFlags.requestDataPushStarted = true;
    }

    // Push the request data chunk to the waf2 engine
    const char *dataBuf = (const char*)event.getData().data();
    size_t dataBufLen = event.getData().size();

    waf2Transaction.add_request_body_chunk(dataBuf, dataBufLen);

    ngx_http_cp_verdict_e verdict = waf2Transaction.getUserLimitVerdict();
    if (verdict != ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INSPECT) {
        finishTransaction(waf2Transaction);
    }

    return EventVerdict(verdict);
}


// Called when request ends and response starts.
// For WAAP its time to decide and return either "accept_response" or "drop_response"
EventVerdict
WaapComponent::Impl::respond(const EndRequestEvent &)
{
    dbgTrace(D_WAAP) << " * \e[32mNGEN_EVENT: endRequest event\e[0m";

    if (!waapStateTable->hasState<Waf2Transaction>()) {
        dbgWarning(D_WAAP)
                << "* \e[31mNGEN_EVENT: endRequest - failed to get waf2 transaction, state does not exist\e[0m";
        return drop_response;
    }

    IWaf2Transaction& waf2Transaction = waapStateTable->getState<Waf2Transaction>();
    Waf2TransactionFlags &waf2TransactionFlags = waf2Transaction.getTransactionFlags();

    // Do not forget to tell waf2 engine that data ended (if we started request_body above...)
    if (waf2TransactionFlags.requestDataPushStarted) {
        waf2Transaction.end_request_body();
        waf2TransactionFlags.requestDataPushStarted = false;
    }

    // Tell waf2 engine that request stage is finished
    waf2Transaction.end_request();

    // waapDecision returns one of these verdicts: accept, drop, pending
    // PENDING verdict (also called INSPECT by ngen core) will be returned if the waap engine wants to also inspect
    // response.
    EventVerdict verdict = waapDecision(waf2Transaction);

    // Delete state before returning any verdict which is not pending
    if (verdict.getVerdict() != ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INSPECT &&
        waapStateTable->hasState<Waf2Transaction>()
    ) {
        finishTransaction(waf2Transaction);
    }

    return verdict;
}

EventVerdict
WaapComponent::Impl::respond(const ResponseCodeEvent &event)
{
    dbgTrace(D_WAAP)
        << " * \e[32mNGEN_EVENT: ResponseCodeTransactionEvent event code = "
        << event.getResponseCode()
        << "\e[0m";

    if (!waapStateTable->hasState<Waf2Transaction>()) {
        dbgWarning(D_WAAP)
                << " * \e[31mNGEN_EVENT: ResponseCodeTransactionEvent - failed to get waf2 transaction, "
                << "state does not exist\e[0m";
        return drop_response;
    }

    IWaf2Transaction& waf2Transaction = waapStateTable->getState<Waf2Transaction>();
    // TODO:: extract HTTP version from attachment?
    static const int http_version = 0x11;

    // Tell waf2 API that response starts
    waf2Transaction.start_response(event.getResponseCode(), http_version);

    EventVerdict verdict = pending_response;

    // Set drop verdict if waap engine decides to drop response.
    if (!waf2Transaction.decideResponse()) {
        dbgTrace(D_WAAP) << " * \e[32m ResponseCodeTransactionEvent: decideResponse: DROP\e[0m";
        verdict = drop_response;
    } else if (!waf2Transaction.shouldInspectResponse()) {
        // Set accept verdict if waap engine no more interested in response
        dbgTrace(D_WAAP) << " * \e[32m ResponseCodeTransactionEvent: shouldInspectResponse==false: ACCEPT\e[0m";
        verdict = accept_response;
    } else {
        // Tell waf2 API that response headers start
        waf2Transaction.start_response_hdrs();
    }

    // Delete state before returning any verdict which is not pending
    if (verdict.getVerdict() != ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INSPECT &&
        verdict.getVerdict() != ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INJECT &&
        waapStateTable->hasState<Waf2Transaction>()
    ) {
        finishTransaction(waf2Transaction);
    }

    return verdict;
}

EventVerdict
WaapComponent::Impl::respond(const HttpResponseHeaderEvent &event)
{
    auto &header_name = event.getKey();
    auto &header_value = event.getValue();

    dbgTrace(D_WAAP)
        << " * \e[32mNGEN_EVENT: HttpHeaderResponse event: "
        << string(header_name)
        << ": "
        << string(header_value)
        << "\e[0m";

    if (!waapStateTable->hasState<Waf2Transaction>()) {
        dbgWarning(D_WAAP)
            << " * \e[31mNGEN_EVENT: HttpHeaderResponse - "
            << "failed to get waf2 transaction, state does not exist\e[0m";
        return drop_response;
    }

    IWaf2Transaction& waf2Transaction = waapStateTable->getState<Waf2Transaction>();

    // Send response header to the engine
    waf2Transaction.add_response_hdr(
        reinterpret_cast<const char *>(header_name.data()),
        header_name.size(),
        reinterpret_cast<const char *>(header_value.data()),
        header_value.size()
    );

    ngx_http_cp_verdict_e verdict = pending_response.getVerdict();
    HttpHeaderModification modifications;
    bool isSecurityHeadersInjected = false;

    if (waf2Transaction.shouldInjectSecurityHeaders()) {
        dbgTrace(D_WAAP) << " * \e[32m HttpHeaderResponse: Trying to inject Security Headers\e[0m";
        if (event.isLastHeader()) {
            dbgTrace(D_WAAP) << " * \e[32m HttpHeaderResponse: Injecting Security Headers\e[0m";
            std::vector<std::pair<std::string, std::string>> injectHeaderStr;
            waf2Transaction.handleSecurityHeadersInjection(injectHeaderStr);
            for (auto header : injectHeaderStr) {
                dbgTrace(D_WAAP) << " * \e[32m HttpHeaderResponse: Injecting Security Header. Header name: \e[0m" <<
                    header.first << " Header value: " << header.second;
                Buffer headerValue(header.second);
                HeaderKey headerName(header.first);
                Maybe<void> result = modifications.appendHeader(std::move(headerName), std::move(headerValue));
                if (!result.ok()) {
                    dbgWarning(D_WAAP)
                    << "Failed to inject (Security header) buffer in requested position. Buffer: "
                    << header.second
                    << ", position: "
                    << 0
                    << ". Error: "
                    << result.getErr();
                }
            }
            isSecurityHeadersInjected = true;
            verdict = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INJECT;
        }
    }

    if (waf2Transaction.shouldInjectCSRF()) {
        if (event.isLastHeader()) {
            std::string injectStr;
            waf2Transaction.handleCsrfHeaderInjection(injectStr);
            Buffer injected_buffer(injectStr);
            HeaderKey setCookie("Set-Cookie");
            Maybe<void> result = modifications.appendHeader(std::move(setCookie), std::move(injected_buffer));
            if (!result.ok()) {
                    dbgWarning(D_WAAP)
                    << "Failed to inject (CSRF header) buffer in requested position. Buffer: "
                    << injectStr
                    << ", position: "
                    << 0
                    << ". Error: "
                    << result.getErr();
            }
            verdict = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INJECT;
        }
    }

    // Set drop verdict if waap engine decides to drop response.
    if (!waf2Transaction.decideResponse()) {
        dbgTrace(D_WAAP) << " * \e[32m HttpHeaderResponse: decideResponse: DROP\e[0m";
        verdict = drop_response.getVerdict();
    } else if (!waf2Transaction.shouldInspectResponse()) {
        // Set accept verdict if waap engine no more interested in response
        dbgTrace(D_WAAP) << " * \e[32m HttpHeaderResponse: shouldInspectResponse==false: ACCEPT\e[0m";
        verdict = accept_response.getVerdict();
    }

    if (waf2Transaction.shouldInjectSecurityHeaders() && isSecurityHeadersInjected &&
        verdict == ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INJECT
    ) {
        // disable should inject security headers after injection to avoid response body scanning when it's unnecessary
        waf2Transaction.disableShouldInjectSecurityHeaders();
    }

    // Delete state before returning any verdict which is not pending
    if (verdict != ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INSPECT &&
        verdict != ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INJECT &&
        waapStateTable->hasState<Waf2Transaction>()
    ) {
        finishTransaction(waf2Transaction);
    }

    return EventVerdict(move(modifications.getModificationList()), verdict);
}

EventVerdict
WaapComponent::Impl::respond(const HttpResponseBodyEvent &event)
{
    dbgTrace(D_WAAP) << " * \e[32mNGEN_EVENT: HttpBodyResponse data buffer event\e[0m";

    if (!waapStateTable->hasState<Waf2Transaction>()) {
        dbgWarning(D_WAAP) <<
            " * \e[31mNGEN_EVENT: HttpBodyResponse - failed to get waf2 transaction, state does not exist\e[0m";
        return drop_response;
    }

    IWaf2Transaction& waf2Transaction = waapStateTable->getState<Waf2Transaction>();
    Waf2TransactionFlags &waf2TransactionFlags = waf2Transaction.getTransactionFlags();

    // Do this only once (on first response body data packet)
    if (!waf2TransactionFlags.responseDataPushStarted) {
        dbgTrace(D_WAAP) << "first response body packet";

        // Tell waf2 transaction that all response headers are finished
        if (!waf2TransactionFlags.endResponseHeadersCalled) {
            // At this point, all response headers were received
            waf2Transaction.end_response_hdrs();
            waf2TransactionFlags.endResponseHeadersCalled = true;
        }

        waf2Transaction.start_response_body();
        waf2TransactionFlags.responseDataPushStarted = true;
    }

    dbgTrace(D_WAAP) << "HttpBodyResponse";


    // Push the response data chunk to the waf2 engine
    const char *dataBuf = (const char*)event.getData().data();
    size_t dataBufLen = event.getData().size();

    waf2Transaction.add_response_body_chunk(dataBuf, dataBufLen);

    ngx_http_cp_verdict_e verdict = pending_response.getVerdict();
    HttpBodyModification modifications;

    // Set drop verdict if waap engine decides to drop response.
    if (!waf2Transaction.decideResponse()) {
        dbgTrace(D_WAAP) << " * \e[32m HttpBodyResponse: decideResponse: DROP\e[0m";
        verdict = drop_response.getVerdict();
    }

    if (verdict == pending_response.getVerdict() &&
        waf2Transaction.shouldInjectResponse() &&
        !event.isLastChunk()
    ) {
        // Inject if needed. Note that this is only reasonable to do if there was no DROP decision above

        std::string injectionStr;
        int pos = 0;

        if(waf2Transaction.isHtmlType(dataBuf, dataBufLen)) {
            bool htmlTagFound = waf2Transaction.findHtmlTagToInject(
                dataBuf,
                dataBufLen,
                pos
            );

            pos = htmlTagFound ? pos + 1 : 0;

            waf2Transaction.completeInjectionResponseBody(injectionStr);
            dbgTrace(D_WAAP) << "HttpBodyResponse(): injectionStr: " << injectionStr << " pos: " << pos
                << " URI: " << waf2Transaction.getUriStr();
            Maybe<void> result = modifications.inject(pos, Buffer(injectionStr));
            if(!result.ok()) {
                dbgWarning(D_WAAP) << "HttpBodyResponse(): Scripts injection failed!";
            }
            verdict = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INJECT;
        } else {
            // This response body is not considered "HTML" - disable injection
            dbgTrace(D_WAAP) << "HttpBodyResponse(): the response body is not HTML - disabling injection";

            // Note that this operation might affect the shouldInspectResponse() state if injection was the only reason
            // to inspect the response body.
            waf2Transaction.clearAllInjectionReasons();
        }
    }

    if (verdict == pending_response.getVerdict() && !waf2Transaction.shouldInspectResponse()) {
        // Set accept verdict if waap engine no more interested in response
        dbgTrace(D_WAAP) << " * \e[32m HttpBodyResponse: shouldInspectResponse==false: ACCEPT\e[0m";
        verdict = accept_response.getVerdict();
    }

    // Delete state before returning any verdict which is not pending or inject
    if (verdict != ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INSPECT &&
        verdict != ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INJECT &&
        waapStateTable->hasState<Waf2Transaction>()
    ) {
        finishTransaction(waf2Transaction);
    }

    return EventVerdict(modifications.getModificationList(), verdict);
}

EventVerdict
WaapComponent::Impl::respond(const EndTransactionEvent &)
{
    if (!waapStateTable->hasState<Waf2Transaction>()) {
        dbgWarning(D_WAAP) <<
            " * \e[31mNGEN_EVENT: endTransaction - failed to get waf2 transaction, state does not exist\e[0m";
        return EventVerdict(drop_response);
    }

    IWaf2Transaction& waf2Transaction = waapStateTable->getState<Waf2Transaction>();
    Waf2TransactionFlags &waf2TransactionFlags = waf2Transaction.getTransactionFlags();

    // Do not forget to tell waf2 engine that response headers ended.
    if (!waf2TransactionFlags.endResponseHeadersCalled) {
        waf2Transaction.end_response_hdrs();
        waf2TransactionFlags.endResponseHeadersCalled = true;
    } else if (waf2TransactionFlags.responseDataPushStarted) {
        // Do not forget to tell waf2 engine that data ended (if we started response_body above...)
        waf2Transaction.end_response_body();
        waf2TransactionFlags.responseDataPushStarted = false;
    }

    waf2Transaction.end_response();

    EventVerdict verdict = accept_response;

    // Set drop verdict if waap engine decides to drop response.
    if (!waf2Transaction.decideResponse()) {
        dbgTrace(D_WAAP) << " * \e[32m endTransaction: decideResponse: DROP\e[0m";
        verdict = drop_response;
    } else if (!waf2Transaction.shouldInspectResponse()) {
        // Set accept verdict if waap engine no more interested in response
        dbgTrace(D_WAAP) << " * \e[32m endTransaction: shouldInspectResponse==false: ACCEPT\e[0m";
    }

    // This is our last chance to delete the state. The verdict must not be "PENDING" at this point.
    finishTransaction(waf2Transaction);
    return verdict;
}

EventVerdict
WaapComponent::Impl::waapDecisionAfterHeaders(IWaf2Transaction& waf2Transaction)
{
    dbgTrace(D_WAAP) << "waapDecisionAfterHeaders() started";
    if (waf2Transaction.decideAfterHeaders()) {
        dbgTrace(D_WAAP) << "WaapComponent::Impl::waapDecisionAfterHeaders(): returning DROP response.";
        return drop_response;
    }
    return pending_response;
}

EventVerdict
WaapComponent::Impl::waapDecision(IWaf2Transaction& waf2Transaction)
{
    dbgTrace(D_WAAP) << "waapDecision() started";

    static const int mode = 1;
    AnalysisResult result;
    int verdictCode = waf2Transaction.decideFinal(mode, result);

    EventVerdict verdict = accept_response;

    // Note: verdict is 0 if nothing suspicious, 1 if should block, or negative if error occurred
    // (in the latter case - decision to drop/pass should be governed by failopen setting)
    if (verdictCode == 0) {
        waf2Transaction.checkShouldInject();

        if (waf2Transaction.shouldInspectResponse()) {
            verdict = pending_response;
        } else {
            dbgTrace(D_WAAP) << "WAF VERDICT: " << verdictCode << " (\e[32mPASS\e[0m)";
            verdict = accept_response;
        }
    } else {
        std::string message = (verdictCode == 1) ? " (\e[31mBLOCK\e[0m)" : " (\e[31mERROR!\e[0m)";
        dbgTrace(D_WAAP) << "WAF VERDICT: " << verdictCode << message;
        verdict = drop_response;
    }

    dbgTrace(D_WAAP) << "waapDecision() finished";
    return verdict;
}

void
WaapComponent::Impl::finishTransaction(IWaf2Transaction& waf2Transaction)
{
    waf2Transaction.collectFoundPatterns();
    waf2Transaction.sendLog();
    ReportIS::Severity severity = waf2Transaction.computeEventSeverityFromDecision();
    validateFirstRequestForAsset(severity);
    waapStateTable->deleteState<Waf2Transaction>();
}

void WaapComponent::Impl::validateFirstRequestForAsset(const ReportIS::Severity severity)
{
    static BasicRuleConfig empty_rule;
    const BasicRuleConfig& rule_by_ctx = getConfigurationWithDefault<BasicRuleConfig>(
        empty_rule,
        "rulebase",
        "rulesConfig");
    if (rule_by_ctx.getAssetId().empty()) {
        dbgWarning(D_WAAP) << "Failed to get rule base from context. Skipping sending notification.";
        return;
    }

    if (m_seen_assets_id.find(rule_by_ctx.getAssetId()) == m_seen_assets_id.end()) {
        dbgTrace(D_WAAP) << "First request for asset id: '" << rule_by_ctx.getAssetId()
            << "'. Sending notification";
        m_seen_assets_id.insert(rule_by_ctx.getAssetId());
        sendNotificationForFirstRequest(
            rule_by_ctx.getAssetId(),
            rule_by_ctx.getAssetName(),
            severity
        );
    }
}

void WaapComponent::Impl::sendNotificationForFirstRequest(
    const std::string& asset_id,
    const std::string& asset_name,
    const ReportIS::Severity severity
)
{
    dbgTrace(D_WAAP) << "Got first request for asset: '" << asset_name<< "' sending a notification";
    FirstRequestNotificationObject obj(asset_id, asset_name, severity);
    I_MainLoop* mainloop = Singleton::Consume<I_MainLoop>::by<WaapComponent>();
    mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::System,
        [asset_name, obj]()
        {
            ReportMessaging(
                "First request for asset '" + asset_name + "'",
                ReportIS::AudienceTeam::WAAP,
                obj,
                ReportIS::Tags::WAF,
                ReportIS::Notification::FIRST_REQUEST_FOR_ASSET
            );
        },
        "Report WAAP asset first request inspection"
    );
}

bool
WaapComponent::Impl::waf2_proc_start(const std::string& waapDataFileName)
{
    // WAAP uses libxml library, which requires process-level initialization when process starts
#if 0 // TODO:: silence the error messages printed by libxml2
    xmlSetGenericErrorFunc(NULL, (xmlGenericErrorFunc)my_libxml2_err);
    xmlSetStructuredErrorFunc(NULL, my_libxml_structured_err);
#endif
    ::xmlInitParser();

    return
        Singleton::Consume<I_WaapAssetStatesManager>::by<WaapComponent>()->initBasicWaapSigs(waapDataFileName);
}

void
WaapComponent::Impl::waf2_proc_exit()
{
    ::xmlCleanupParser();
}
