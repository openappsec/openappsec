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

#include "Waf2Engine.h"
#include "waap.h"
#include "WaapAssetState.h"
#include "CidrMatch.h"
#include "ParserRaw.h"
#include "ParserUrlEncode.h"
#include "ParserMultipartForm.h"
#include "ParserXML.h"
#include "ParserJson.h"
#include "ContentTypeParser.h"
#include "Waf2Util.h"
#include "debug.h"
#include "DeepAnalyzer.h"
#include "WaapConfigApplication.h"
#include "WaapConfigApi.h"
#include "WaapDefines.h"
#include "WaapTrigger.h"
#include "WaapScores.h"
#include "WaapDecision.h"
#include "WaapConversions.h"
#include "WaapResultJson.h"
#include "WaapAssetStatesManager.h"
#include "log_generator.h"
#include "config.h"
#include "WaapOverrideFunctor.h"
#include "WaapOpenRedirect.h"
#include "WaapOpenRedirectPolicy.h"
#include "WaapErrorDisclosurePolicy.h"
#include <boost/algorithm/string.hpp>
#include "generic_rulebase/parameters_config.h"
#include <iostream>
#include "ParserDelimiter.h"
#include "OpenRedirectDecision.h"
#include "DecisionType.h"
#include "generic_rulebase/triggers_config.h"
#include "config.h"
#include "LogGenWrapper.h"
#include "reputation_features_events.h"
#include "telemetry.h"
#include "agent_core_utilities.h"

USE_DEBUG_FLAG(D_WAAP);
USE_DEBUG_FLAG(D_WAAP_ULIMITS);
USE_DEBUG_FLAG(D_WAAP_BOT_PROTECTION);
USE_DEBUG_FLAG(D_OA_SCHEMA_UPDATER);

using namespace ReportIS;

#define MAX_REQUEST_BODY_SIZE (2*1024)
#define MAX_RESPONSE_BODY_SIZE (2*1024)
#define MAX_RESPONSE_BODY_SIZE_ERR_DISCLOSURE (2*1024)
#define OVERRIDE_ACCEPT "Accept"
#define OVERRIDE_DROP "Drop"
#define OVERRIDE_IGNORE "Ignore"

// Score threshold below which the match won't be considered
#define SCORE_THRESHOLD (1.4f)

void Waf2Transaction::learnScore(ScoreBuilderData& data, const std::string &poolName)
{
    m_pWaapAssetState->scoreBuilder.analyzeFalseTruePositive(data, poolName, !m_ignoreScore);

    if (m_ignoreScore) // check if we are in building scores state
    {
        // Set the relative reputation to max to ensure learning fp in score builder
        data.m_relativeReputation = MAX_RELATIVE_REPUTATION;
    }
    m_pWaapAssetState->scoreBuilder.checkBadSourcesForLearning(
        data.m_relativeReputation,
        data.m_sourceIdentifier,
        data.m_userAgent);
}

void Waf2Transaction::start_response(int response_status, int http_version)
{
    dbgTrace(D_WAAP) << "[transaction:" << this << "] start_response(response_status=" << response_status
        << "," << " http_version=" << http_version << ")";
    m_responseStatus = response_status;

    if(m_responseStatus == 404)
    {
        // Create error limiting policy (lazy, on first request)
        if(m_siteConfig != NULL) {
            const std::shared_ptr<Waap::RateLimiting::Policy> errorLimitingPolicy =
                m_siteConfig->get_ErrorLimitingPolicy();

            if (errorLimitingPolicy && errorLimitingPolicy->getRateLimitingEnforcementStatus()) {
                if (m_pWaapAssetState->getErrorLimitingState() == nullptr) {
                    m_pWaapAssetState->createErrorLimitingState(errorLimitingPolicy);
                    dbgTrace(D_WAAP) << "Waf2Transaction::start_response: Create Error Limiting State";
                }

                bool errorLimitingLog = false;
                bool blockDueToErrorLimiting = Waap::ErrorLimiting::enforce
                    (m_source_identifier, m_uriPath, m_pWaapAssetState, errorLimitingLog);

                dbgTrace(D_WAAP) <<
                    "Waf2Transaction::start_response: response code: 404 :: Error Limiting Block : " <<
                        blockDueToErrorLimiting;

                auto decision = m_waapDecision.getDecision(ERROR_LIMITING_DECISION);
                decision->setLog(errorLimitingLog);
                decision->setBlock(blockDueToErrorLimiting);
            }
        }
    }
}

void Waf2Transaction::start_response_hdrs()
{
    dbgTrace(D_WAAP) << "[transaction:" << this << "] start_response_hdrs";
}

void Waf2Transaction::add_response_hdr(const char* name, int name_len, const char* value, int value_len)
{
    dbgTrace(D_WAAP) << "[transaction:" << this << "] add_response_hdr(name='" << std::string(name, name_len) <<
        "', value='" << std::string(value, value_len) << "')";

    // Detect location header and remember it's value
    static const char location[] = "location";

    auto openRedirectPolicy = m_siteConfig ? m_siteConfig->get_OpenRedirectPolicy() : NULL;
    if (openRedirectPolicy && openRedirectPolicy->enable &&
        memcaseinsensitivecmp(name, name_len, location, sizeof(location) - 1)) {
        std::string redirectUrl = std::string(value, value_len);
        dbgTrace(D_WAAP) << "Detected the redirect 'Location' header: '" << redirectUrl << "'";

        if (m_responseStatus >= 300 && m_responseStatus < 400 && m_openRedirectState.testRedirect(redirectUrl)) {
            dbgTrace(D_WAAP) << "Waf2Transaction::decideResponse: openRedirect detected (enforce=" <<
                openRedirectPolicy->enforce << ")";
            auto decision = std::dynamic_pointer_cast<OpenRedirectDecision>(
                m_waapDecision.getDecision(OPEN_REDIRECT_DECISION));
            decision->setLog(true);
            decision->setBlock(openRedirectPolicy->enforce);
            decision->setLink(redirectUrl);
        }
    }

    if (m_responseStatus >= 400 && m_responseStatus <= 599) {
        auto errorDisclosurePolicy = m_siteConfig ? m_siteConfig->get_ErrorDisclosurePolicy() : NULL;
        if (errorDisclosurePolicy && errorDisclosurePolicy->enable) {
            // Scan response header values
            Waf2ScanResult res;
            if (m_pWaapAssetState->apply(std::string(value, value_len), res, "resp_header")) {
                // Found some signatures in response!
                delete m_scanResult;
                m_scanResult = new Waf2ScanResult(res);
                dbgTrace(D_WAAP) << "found indicators in response header";
                auto decision = m_waapDecision.getDecision(ERROR_DISCLOSURE_DECISION);
                decision->setLog(true);
                decision->setBlock(errorDisclosurePolicy->enforce);
            }
        }
    }
}

void Waf2Transaction::end_response_hdrs()
{
    dbgTrace(D_WAAP) << "[transaction:" << this << "] end_response_hdrs";

    // Enable response body processing only if response scanning is enabled in policy
    auto errorDisclosurePolicy = m_siteConfig ? m_siteConfig->get_ErrorDisclosurePolicy() : NULL;
    m_responseInspectReasons.setErrorDisclosure(errorDisclosurePolicy && errorDisclosurePolicy->enable);

    // OpenRedirect is only interested to see response headers, the body
    m_responseInspectReasons.setOpenRedirect(false);
}

void Waf2Transaction::start_response_body()
{
    dbgTrace(D_WAAP) << "[transaction:" << this << "] start_response_body";
    m_response_body_bytes_received = 0;
    m_response_body.clear();
}

void Waf2Transaction::add_response_body_chunk(const char* data, int data_len)
{
    dbgTrace(D_WAAP) << "[transaction:" << this << "] add_response_body_chunk (" << data_len << " bytes)";
    m_response_body_bytes_received += data_len;

    auto errorDisclosurePolicy = m_siteConfig ? m_siteConfig->get_ErrorDisclosurePolicy() : NULL;
    if (errorDisclosurePolicy && errorDisclosurePolicy->enable &&
        (m_responseStatus >= 400 && m_responseStatus <= 599)) {
        // Collect up to MAX_RESPONSE_BODY_SIZE_ERR_DISCLOSURE of input data for each response
        if (m_response_body_err_disclosure.length() + data_len <= MAX_RESPONSE_BODY_SIZE_ERR_DISCLOSURE) {
            m_response_body_err_disclosure.append(data, (size_t)data_len);
        }
        else if (m_response_body_err_disclosure.length() < MAX_RESPONSE_BODY_SIZE_ERR_DISCLOSURE) {
            size_t piece = MAX_RESPONSE_BODY_SIZE_ERR_DISCLOSURE - m_response_body_err_disclosure.length();
            // Note: piece is guaranteed to be > data_len, so the write below is safe.
            m_response_body_err_disclosure.append(data, piece);
        }
        else {
            m_responseInspectReasons.setErrorDisclosure(false);
        }
    }

    if (m_response_body_err_disclosure.length() <= MAX_RESPONSE_BODY_SIZE_ERR_DISCLOSURE) {
        // Scan now, buffer is filled up.
        scanErrDisclosureBuffer();
    }

    // Collect up to MAX_RESPONSE_BODY_SIZE of input data for each response
    if (m_response_body.length() + data_len <= MAX_RESPONSE_BODY_SIZE) {
        m_response_body.append(data, (size_t)data_len);
    }
    else if (m_response_body.length() < MAX_RESPONSE_BODY_SIZE) {
        size_t piece = MAX_RESPONSE_BODY_SIZE - m_response_body.length();
        // Note: piece is guaranteed to be > data_len, so the write below is safe.
        m_response_body.append(data, piece);
    }
    else {
        // No more need to collect response body for log (got enough data - up to MAX_RESPONSE_BODY_SIZE collected)
        m_responseInspectReasons.setCollectResponseForLog(false);
    }
}

void Waf2Transaction::end_response_body()
{
    dbgTrace(D_WAAP) << "[transaction:" << this << "] end_response_body";
}

void Waf2Transaction::scanErrDisclosureBuffer()
{
    if (m_responseStatus >= 400 && m_responseStatus <= 599) {
        auto errorDisclosurePolicy = m_siteConfig ? m_siteConfig->get_ErrorDisclosurePolicy() : NULL;
        if (errorDisclosurePolicy && errorDisclosurePolicy->enable) {
                // Scan response body chunks.
                Waf2ScanResult res;
                if (m_pWaapAssetState->apply(std::string(m_response_body_err_disclosure.data(),
                    m_response_body_err_disclosure.size()), res, "resp_body")) {
                    // Found some signatures in response!
                    delete m_scanResult;
                    m_scanResult = new Waf2ScanResult(res);
                    dbgTrace(D_WAAP) << "found indicators in response body";
                    auto decision = m_waapDecision.getDecision(ERROR_DISCLOSURE_DECISION);
                    decision->setLog(true);
                    decision->setBlock(errorDisclosurePolicy->enforce);
                }
        }
    }
    m_responseInspectReasons.setErrorDisclosure(false);
}

void Waf2Transaction::end_response()
{
    dbgTrace(D_WAAP) << "[transaction:" << this << "] end_response";
}


void Waf2Transaction::setCurrentAssetState(IWaapConfig* sitePolicy)
{
    I_WaapAssetStatesManager* pWaapAssetStatesManager =
        Singleton::Consume<I_WaapAssetStatesManager>::by<WaapComponent>();
    std::shared_ptr<WaapAssetState> pCurrentWaapAssetState =
        pWaapAssetStatesManager->getWaapAssetStateById(sitePolicy->get_AssetId());

    if (!pCurrentWaapAssetState || pCurrentWaapAssetState->getSignatures()->fail())
    {
        dbgWarning(D_WAAP) << "[transaction:" << this << "] "
            "couldn't set waapAssetState for asset... using original waapAssetState";
        return;
    }

    m_pWaapAssetState = pCurrentWaapAssetState;
}

void Waf2Transaction::clearRequestParserState() {
    if (m_requestBodyParser != NULL) {
        delete m_requestBodyParser;
        m_requestBodyParser = NULL;
    }
}

Waf2Transaction::Waf2Transaction() :
    TableOpaqueSerialize<Waf2Transaction>(this),
    m_pWaapAssetState(NULL),
    m_ignoreScore(false),
    m_remote_port(0),
    m_local_port(0),
    m_csrfState(),
    m_userLimitsState(nullptr),
    m_siteConfig(NULL),
    m_contentType(Waap::Util::CONTENT_TYPE_UNKNOWN),
    m_requestBodyParser(NULL),
    m_tagHist{0},
    m_tagHistPos(0),
    m_isUrlValid(false),
    m_scanner(this),
    m_deepParser(m_pWaapAssetState, m_scanner, this),
    m_deepParserReceiver(m_deepParser),
    m_scanResult(NULL),
    m_request_body_bytes_received(0),
    m_response_body_bytes_received(0),
    m_processedUri(false),
    m_processedHeaders(false),
    m_isScanningRequired(false),
    m_responseStatus(0),
    m_responseInspectReasons(),
    m_responseInjectReasons(),
    m_index(-1),
    m_triggerLog(),
    m_waf2TransactionFlags()
{
    is_hybrid_mode =
        Singleton::exists<I_AgentDetails>() ?
        Singleton::Consume<I_AgentDetails>::by<Waf2Transaction>()->getOrchestrationMode() == OrchestrationMode::HYBRID
        : false;
    if (is_hybrid_mode) {
        max_grace_logs = getProfileAgentSettingWithDefault<int>(
            10,
            "rulebase.initialForcedSecurityLogsToLocalStorage.count"
        );
    }
}

Waf2Transaction::Waf2Transaction(std::shared_ptr<WaapAssetState> pWaapAssetState) :
    TableOpaqueSerialize<Waf2Transaction>(this),
    m_pWaapAssetState(pWaapAssetState),
    m_ignoreScore(false),
    m_remote_port(0),
    m_local_port(0),
    m_csrfState(),
    m_userLimitsState(nullptr),
    m_siteConfig(NULL),
    m_contentType(Waap::Util::CONTENT_TYPE_UNKNOWN),
    m_requestBodyParser(NULL),
    m_tagHist{0},
    m_tagHistPos(0),
    m_isUrlValid(false),
    m_scanner(this),
    m_deepParser(m_pWaapAssetState, m_scanner, this),
    m_deepParserReceiver(m_deepParser),
    m_scanResult(NULL),
    m_request_body_bytes_received(0),
    m_response_body_bytes_received(0),
    m_processedUri(false),
    m_processedHeaders(false),
    m_isScanningRequired(false),
    m_responseStatus(0),
    m_responseInspectReasons(),
    m_responseInjectReasons(),
    m_index(-1),
    m_triggerLog(),
    m_waf2TransactionFlags()
{
    is_hybrid_mode =
        Singleton::exists<I_AgentDetails>() ?
        Singleton::Consume<I_AgentDetails>::by<Waf2Transaction>()->getOrchestrationMode() == OrchestrationMode::HYBRID
        : false;
    if (is_hybrid_mode) {
        max_grace_logs = getProfileAgentSettingWithDefault<int>(
            10,
            "rulebase.initialForcedSecurityLogsToLocalStorage.count"
        );
    }
}

Waf2Transaction::~Waf2Transaction() {
    dbgTrace(D_WAAP) << "Waf2Transaction::~Waf2Transaction: deleting m_requestBodyParser";
    delete m_requestBodyParser;
    dbgTrace(D_WAAP) << "Waf2Transaction::~Waf2Transaction: deleting m_scanResult";
    delete m_scanResult;
}

HeaderType Waf2Transaction::detectHeaderType(const char* name, int name_len) {
    // Detect host header
    static const char host[] = "host";
    static const char user_agent[] = "user-agent";
    static const char content_type[] = "content-Type";
    static const char cookie[] = "cookie";
    static const char referer[] = "referer";

    if (memcaseinsensitivecmp(name, name_len, host, sizeof(host) - 1)) {
        return HeaderType::HOST_HEADER;
    }
    if (memcaseinsensitivecmp(name, name_len, user_agent, sizeof(user_agent) - 1)) {
        return HeaderType::USER_AGENT_HEADER;
    }
    if (memcaseinsensitivecmp(name, name_len, content_type, sizeof(content_type) - 1)) {
        return HeaderType::CONTENT_TYPE_HEADER;
    }
    if (memcaseinsensitivecmp(name, name_len, cookie, sizeof(cookie) - 1)) {
        return HeaderType::COOKIE_HEADER;
    }
    if (memcaseinsensitivecmp(name, name_len, referer, sizeof(referer) - 1)) {
        return HeaderType::REFERER_HEADER;
    }
    return UNKNOWN_HEADER;
}

HeaderType Waf2Transaction::checkCleanHeader(const char* name, int name_len, const char* value, int value_len) const
{
    if (m_pWaapAssetState != nullptr) {
        for (auto it = m_pWaapAssetState->getSignatures()->headers_re.begin();
            it != m_pWaapAssetState->getSignatures()->headers_re.end();
            ++it) {
            const std::string& reHeaderName = it->first;
            Regex* pRegex = it->second;
            if (memcaseinsensitivecmp(name, name_len, reHeaderName.data(), reHeaderName.size())) {
                dbgTrace(D_WAAP) << "[transaction:" << this << "] special header '" << std::string(name, name_len) <<
                    "' - scan with regex '" << pRegex->getName().c_str() << "' to determine cleanliness ...";
                if(pRegex->hasMatch(std::string(value, value_len))) {
                    dbgTrace(D_WAAP) << "[transaction:" << this << "] special header '" <<
                        std::string(name, name_len) << " is clean";
                    return CLEAN_HEADER;
                }
                return OTHER_KNOWN_HEADERS;
            }
        }

        static const std::string x_newrelic_id("x-newrelic-id");
        static const std::string x_newrelic_transaction("x-newrelic-transaction");
        if (memcaseinsensitivecmp(name, name_len, x_newrelic_id.data(), x_newrelic_id.size()) ||
                memcaseinsensitivecmp(name, name_len, x_newrelic_transaction.data(), x_newrelic_transaction.size())) {
            dbgTrace(D_WAAP) << "[transaction:" << this << "] special header '" << std::string(name, name_len) <<
                "' - detect base64 to determine cleanliness ...";

            std::string result;
            int decodedCount = 0;
            int deletedCount = 0;

            // Detect potential base64 matches
            Waap::Util::b64Decode(std::string(value, value_len), b64DecodeChunk, decodedCount, deletedCount, result);

            if (result.empty() && (decodedCount + deletedCount == 1)) {
                // Decoded 1 base64 chunk and nothing left behind it
                dbgTrace(D_WAAP) << "[transaction:" << this << "] special header '" <<
                    std::string(name, name_len) << " is clean";
                return CLEAN_HEADER;
            }
        }

        static const std::string authorization("authorization");
        if (memcaseinsensitivecmp(name, name_len, authorization.data(), authorization.size())) {
            dbgTrace(D_WAAP) << "[transaction:" << this << "] special header '" << std::string(name, name_len) <<
                "' - detect base64 to determine cleanliness ...";

            std::string result;
            int decodedCount = 0;
            int deletedCount = 0;

            std::string v(value, value_len);
            boost::algorithm::to_lower(v);
            const std::string negotiate("negotiate ");

            if (boost::algorithm::starts_with(v, negotiate)) {
                v = v.substr(negotiate.size(), v.size() - negotiate.size());

                // Detect potential base64 match after the "Negotiate " prefix
                Waap::Util::b64Decode(v, b64DecodeChunk, decodedCount, deletedCount, result);
                if (result.empty() && (deletedCount + decodedCount == 1)) {
                    // Decoded 1 base64 chunk and nothing left behind it
                    dbgTrace(D_WAAP) << "[transaction:" << this << "] special header '" <<
                        std::string(name, name_len) << " is clean";
                    return CLEAN_HEADER;
                }
            }
        }

    }
    return UNKNOWN_HEADER;
}

// Methods below are callbacks that are called during HTTP transaction processing by the front-end server/proxy
void Waf2Transaction::start() {
    dbgTrace(D_WAAP) << "[Waf2Transaction::start():" << this << "] start";
    // TODO:: maybe guard against double call of this function by buggy client.
    m_contentType = Waap::Util::CONTENT_TYPE_UNKNOWN;
    m_remote_addr.clear();
    m_remote_port = 0;
    m_local_addr.clear();
    m_local_port = 0;
    m_request_body_bytes_received = 0;
    m_response_body_bytes_received = 0;
    m_requestBodyParser = NULL;
    m_methodStr.clear();
    m_uriStr.clear();
    m_uriPath.clear();
    m_uriReferer.clear();
    m_uriQuery.clear();
    m_contentTypeStr.clear();
    m_hostStr.clear();
    m_userAgentStr.clear();
    m_cookieStr.clear();
    m_notes.clear();
    m_source_identifier.clear();
    // TODO:: remove this! refactor extraction of kv_pairs!
    m_deepParser.clear();
    hdrs_map.clear();
    m_request_body.clear();
    m_response_body.clear();
}

void Waf2Transaction::set_transaction_time(const char* log_time) {
    dbgTrace(D_WAAP) << "[transaction:" << this << "] set_transaction_time(log_time='" << log_time << "')";
    m_log_time = log_time;
}

void Waf2Transaction::set_transaction_remote(const char* remote_addr, int remote_port) {
    dbgTrace(D_WAAP) << "[transaction:" << this << "] set_transaction_remote('" << remote_addr << ":" << remote_port <<
        "')";
    m_remote_addr = remote_addr;
    m_remote_port = remote_port;
    m_source_identifier = remote_addr;
}

void Waf2Transaction::set_transaction_local(const char* local_addr, int local_port) {
    dbgTrace(D_WAAP) << "[transaction:" << this << "] set_transaction_local('" << local_addr << ":" << local_port <<
        "')";
    m_local_addr = local_addr;
    m_local_port = local_port;
}

void Waf2Transaction::set_method(const char* method) {

    dbgTrace(D_WAAP) << "[transaction:" << this << "] set_method('" << method << "')";
    m_methodStr = method;
}


bool Waf2Transaction::checkIsScanningRequired()
{
    bool result = false;
    if (WaapConfigAPI::getWaapAPIConfig(m_ngenAPIConfig)) {
        m_siteConfig = &m_ngenAPIConfig;
        auto rateLimitingPolicy = m_siteConfig ? m_siteConfig->get_RateLimitingPolicy() : NULL;
        result |= m_siteConfig->get_WebAttackMitigation();
        if(rateLimitingPolicy) {
            result |= m_siteConfig->get_RateLimitingPolicy()->getRateLimitingEnforcementStatus();
        }

        auto userLimitsPolicy = m_siteConfig ? m_siteConfig->get_UserLimitsPolicy() : nullptr;
        if (userLimitsPolicy) {
            result = true;
        }
    }

    if (WaapConfigApplication::getWaapSiteConfig(m_ngenSiteConfig)) {
        m_siteConfig = &m_ngenSiteConfig;
        auto rateLimitingPolicy = m_siteConfig ? m_siteConfig->get_RateLimitingPolicy() : NULL;
        auto errorLimitingPolicy = m_siteConfig ? m_siteConfig->get_ErrorLimitingPolicy() : NULL;
        auto csrfPolicy = m_siteConfig ? m_siteConfig->get_CsrfPolicy() : NULL;
        auto userLimitsPolicy = m_siteConfig ? m_siteConfig->get_UserLimitsPolicy() : nullptr;
        result |= m_siteConfig->get_WebAttackMitigation();
        if (rateLimitingPolicy) {
            result |= m_siteConfig->get_RateLimitingPolicy()->getRateLimitingEnforcementStatus();
        }
        if (errorLimitingPolicy) {
            result |= m_siteConfig->get_ErrorLimitingPolicy()->getRateLimitingEnforcementStatus();
        }
        if (csrfPolicy) {
            result |= m_siteConfig->get_CsrfPolicy()->enable;
        }
        if (userLimitsPolicy) {
            result = true;
        }
    }
    return result;
}

bool Waf2Transaction::setCurrentAssetContext()
{
    // the return value tells me if I need to scan traffic
    bool result = false;
    m_siteConfig = NULL;

    result |= checkIsScanningRequired();

    if (!m_siteConfig) {
        dbgWarning(D_WAAP) << "[transaction:" << this << "] "
            "Failed to set sitePolicy for asset... using the original signatures";
        return result;
    }

    setCurrentAssetState(m_siteConfig);
    m_deepParser.setWaapAssetState(m_pWaapAssetState);
    m_pWaapAssetState->updateFilterManagerPolicy(m_siteConfig);
    m_pWaapAssetState->clearFilterVerbose();

    return result;
}

void Waf2Transaction::processUri(const std::string &uri, const std::string& scanStage) {
    m_processedUri = true;
    size_t uriSize = uri.length();
    const char* p = uri.c_str();
    const char* uriEnd = p+uriSize;
    std::string baseUri;
    char querySep = '?';
    char paramSep = '&';

    // TODO:: refactor out this block to method, and the next block (parsing url parameters), too.
    {
        bool pushed = false;
        bool firstPush = true;

        // Parse URL
        ParserRaw urlParser(m_deepParserReceiver, 0, scanStage);

        // Scan the uri until '?' or ';' character found, whichever comes first (or until end of the uri string),
        // Do not account for last character as valid separator
        do {
            const char* q = strpbrk(p, "?;");

            if (q != NULL && q < uriEnd-1) {
                querySep = *q;

                // Handle special case found in customer traffic where instead of '?' there was a ';' character.
                if (querySep == ';') {
                    // Check that after ';' the parameter name is valid and terminated with '='. This would normally be
                    // the case in legit traffic, but not in attacks. This covers a case of "sap login".
                    const char *qq;
                    for (qq = q + 1;
                            qq < uriEnd && (isalpha(*qq) || isdigit(*qq) || *qq=='-' || *qq=='_' || *qq=='*');
                            ++qq);
                    if (*qq != '=') {
                        // Assume it might be attack and cancel the separation by the ';' character (scan whole URL)
                        q = NULL;
                    }
                    else {
                        const char *qqSep = strpbrk(qq, "&;");
                        // Handle special case (deprecated standard) where instead of '&' there was a ';' separator,
                        // Do not account for last character as valid separator
                        if (qqSep && qqSep < uriEnd-1) {
                            paramSep = *qqSep;
                        }
                    }
                }
            }

            if (q == NULL) {
                dbgTrace(D_WAAP) << "Query separator not found, use entire uri as baseUri";
                baseUri = std::string(uri);
                if (scanStage == "url") {
                    m_uriPath = baseUri;
                }
                if (firstPush) {
                    dbgTrace(D_WAAP) << "[transaction:" << this << "] scanning the " << scanStage.c_str();
                    firstPush = false;
                }

                // Push the last piece to URL scanner
                pushed = true;
                std::string url(uri);

                urlParser.push(url.data(), url.size());

                // We found no '?' character so set p to NULL to prevent parameters scan below.
                p = NULL;
                break;
            }

            baseUri = std::string(p, q - p);
            if (scanStage == "url") {
                m_uriPath = baseUri;
            }

            // Push data between last point (p) and the character we found ('?'), not includig the character.
            if (q != p) {
                // Just so we print this trace message only once
                if (firstPush) {
                    dbgTrace(D_WAAP) << "[transaction:" << this << "] scanning the " << scanStage.c_str();
                    firstPush = false;
                }

                pushed = true;
                std::string url(p, q-p);
                urlParser.push(url.data(), url.size());
            }

            // If we hit the '?' character, finish parsing the URL and continue parsing URL
            // parameters from the character next to '?'
            p = q + 1;
            break;
        } while (p && p < uriEnd);

        if (pushed) {
            urlParser.finish();
            m_notes.push_back(scanStage + "_scanned");
        }
    }
    // in case we found any indication in one of the URI segments and there is not one that starts with /
    // scan the whole URI
    if (m_scanResult && m_scanResult->score != 0 && (m_scanResult->location == scanStage) &&
        std::find_if(m_scanResult->keyword_matches.begin(),
            m_scanResult->keyword_matches.end(), [](std::string keyword) { return keyword[0] == '/'; }) ==
        m_scanResult->keyword_matches.end())
    {
        auto scanResultBackup = m_scanResult;
        m_scanResult = nullptr;
        bool ignoreScore = m_ignoreScore;
        m_ignoreScore = true;
        m_deepParser.m_key.push(scanStage.c_str(), scanStage.size());
        ParserDelimiter uriSegmentsParser(m_deepParserReceiver, 0, '/', scanStage);
        std::string baseUriUnescaped(baseUri);
        Waap::Util::decodePercentEncoding(baseUriUnescaped);
        uriSegmentsParser.push(baseUriUnescaped.c_str(), baseUriUnescaped.length());
        uriSegmentsParser.finish();
        m_deepParser.m_key.pop(scanStage.c_str());
        m_ignoreScore = ignoreScore;
        if (uriSegmentsParser.error())
        {
            // handle special case where there is no / in the URI - can happen in attackes
            m_deepParserReceiver.clear();
            delete m_scanResult;
            m_scanResult = scanResultBackup;
        }
        else {
            if (m_scanResult)
            {
                // keep original scan of the whole URL
                delete m_scanResult;
                m_scanResult = scanResultBackup;
            }
            else
            {
                // scan result is empty when we parsing each segments
                // i.e. scan result from using (acceptable) irregular format in the URI - discarding the original scan
                delete scanResultBackup;
            }
        }
    }
    // at this point, p can either be NULL (if there are no URL parameters),
    // or point to the parameters string (right after the '?' character)

    if (p && p < uriEnd && *p) {
        // Decode URLEncoded data and send decoded key/value pairs to deep inspection
        dbgTrace(D_WAAP) << "[transaction:" << this << "] scanning the " << scanStage.c_str() << " parameters";

        if (scanStage == "url") {
            m_uriQuery = std::string(p);
        }

        dbgTrace(D_WAAP) << "Query separator='" << querySep << "', " << "Param separator='" << paramSep << "'";

        std::string tag = scanStage + "_param";
        m_deepParser.m_key.push(tag.data(), tag.size());
        size_t buff_len = uriEnd - p;
        dbgTrace(D_WAAP) << "% will be encoded?'" << checkUrlEncoded(p, buff_len) << "'";
        ParserUrlEncode up(m_deepParserReceiver, 0, paramSep, checkUrlEncoded(p, buff_len));
        up.push(p, buff_len);
        up.finish();
        m_deepParser.m_key.pop(tag.c_str());
        m_notes.push_back(scanStage + "_params_scanned");
    }
}

void Waf2Transaction::parseContentType(const char* value, int value_len)
{
    // content type header parser
    ContentTypeParser ctp;

    ctp.push(value, value_len);
    ctp.finish();

    dbgTrace(D_WAAP) << "[transaction:" << this << "] ctp detected content type: '" <<
        ctp.contentTypeDetected.c_str() << "'";
    // The above fills m_contentTypeDetected
    m_contentType = Waap::Util::detectContentType(ctp.contentTypeDetected.c_str());

    // extract boundary string required for parsing multipart-form-data stream
    if (m_contentType == Waap::Util::CONTENT_TYPE_MULTIPART_FORM) {
        dbgTrace(D_WAAP) << "content_type detected: " << Waap::Util::getContentTypeStr(m_contentType) <<
            "; boundary='" << ctp.boundaryFound.c_str() << "'";
        m_deepParser.setMultipartBoundary(ctp.boundaryFound);
    }
    else {
        dbgTrace(D_WAAP) << "content_type detected: " << Waap::Util::getContentTypeStr(m_contentType);
    }

    std::string contentTypeFull(value, value_len);
    // Use content-type trimmed by the first ';' character
    m_contentTypeStr = contentTypeFull.substr(0, contentTypeFull.find(";"));
}

void Waf2Transaction::parseCookie(const char* value, int value_len)
{
    m_cookieStr = std::string(value, value_len);

#ifdef NO_HEADERS_SCAN
    return;
#endif

    if (value_len > 0) {
        dbgTrace(D_WAAP) << "[transaction:" << this << "] scanning the cookie value";
        m_deepParser.m_key.push("cookie", 6);
        ParserUrlEncode cookieValueParser(m_deepParserReceiver, 0, ';');
        cookieValueParser.push(value, value_len);
        cookieValueParser.finish();
        m_deepParser.m_key.pop("cookie");
        m_notes.push_back("cookie_scanned");
    }
}

void Waf2Transaction::parseReferer(const char* value, int value_len)
{
#ifdef NO_HEADERS_SCAN
    return;
#endif
    dbgTrace(D_WAAP) << "Parsed Referer. Referer URI: " << m_uriReferer;

    std::string referer(value, value_len);
    std::vector<RegexMatch> regex_matches;
    size_t uriParsedElements =
        m_pWaapAssetState->getSignatures()->uri_parser_regex.findAllMatches(referer, regex_matches);
    if(uriParsedElements > 0)
    {
        RegexMatch::MatchGroup& uriPathGroup = regex_matches[0].groups[3];
        m_uriReferer = uriPathGroup.value;
        m_uriReferer = normalize_uri(m_uriReferer);
    }
    // Parse referer value as if it was a URL
    if (value_len > 0)
    {
        processUri(std::string(value, value_len), "referer");
    }
}

void Waf2Transaction::parseUnknownHeaderName(const char* name, int name_len)
{
#ifdef NO_HEADERS_SCAN
    return;
#endif
    // Apply signatures on all other, header names, unless they are considered "good" ones to skip scanning them.
    if (name_len &&
        !m_pWaapAssetState->getSignatures()->good_header_name_re.hasMatch(std::string(name, name_len))) {
        dbgTrace(D_WAAP) << "[transaction:" << this << "] scanning the header name";
        m_deepParser.m_key.push("header", 6);
        ParserRaw headerNameParser(m_deepParserReceiver, 0, std::string(name,  name_len));
        headerNameParser.push(name, name_len);
        headerNameParser.finish();
        m_deepParser.m_key.pop("header name");
        m_notes.push_back("hn:" + std::string(name, name_len));
    }
}

void Waf2Transaction::parseGenericHeaderValue(const std::string &headerName, const char* value, int value_len)
{
#ifdef NO_HEADERS_SCAN
    return;
#endif
    if (value_len == 0) {
        return;
    }

    dbgTrace(D_WAAP) << "[transaction:" << this << "] scanning the header value";
    m_deepParser.m_key.push("header", 6);
    ParserRaw headerValueParser(m_deepParserReceiver, 0, headerName);
    headerValueParser.push(value, value_len);
    headerValueParser.finish();
    m_deepParser.m_key.pop("header value");
    m_notes.push_back("hv:" + headerName);
};

// Scan relevant headers to detect attacks inside them
void Waf2Transaction::scanSpecificHeder(const char* name, int name_len, const char* value, int value_len)
{
    HeaderType header_t = detectHeaderType(name, name_len);
    std::string headerName = std::string(name, name_len);

    switch (header_t)
    {
    case HeaderType::COOKIE_HEADER:
        parseCookie(value, value_len);
        break;
    case HeaderType::REFERER_HEADER:
        parseReferer(value, value_len);
        break;
    case HeaderType::UNKNOWN_HEADER: {
        HeaderType headerType = checkCleanHeader(name, name_len, value, value_len);
        if(headerType == HeaderType::CLEAN_HEADER) {
            break;
        }
        // Scan names of all unknown headers
        parseUnknownHeaderName(name, name_len);
        // Scan unknown headers whose values do not match "clean generic header" pattern.
        // Note that we do want to process special header named x-chkp-csrf-token header - it is treated specially.
        if (!m_pWaapAssetState->getSignatures()->good_header_value_re.hasMatch(std::string(value, value_len)) ||
                headerName == "x-chkp-csrf-token" || headerType == HeaderType::OTHER_KNOWN_HEADERS) {
            parseGenericHeaderValue(headerName, value, value_len);
        }
        break;
    }
    case HeaderType::USER_AGENT_HEADER: {
        HeaderType headerType = checkCleanHeader(name, name_len, value, value_len);
        if(headerType == HeaderType::CLEAN_HEADER) {
            break;
        }
        // In case the user agent header contains a known regex match, remove the match before scanning
        std::string hdrValue(value, value_len);
        hdrValue = NGEN::Regex::regexReplace(
            __FILE__,
            __LINE__,
            hdrValue,
            m_pWaapAssetState->getSignatures()->user_agent_prefix_re,
            ""
        );
        parseGenericHeaderValue(headerName, hdrValue.data(), hdrValue.size());
        break;
    }
    case HeaderType::CONTENT_TYPE_HEADER: {
        HeaderType headerType = checkCleanHeader(name, name_len, value, value_len);
        if(headerType == HeaderType::CLEAN_HEADER) {
            break;
        }
        // Parsing of a known header will only take place if its value does not match strict rules and is therefore
        // suspected to contain an attack
        parseGenericHeaderValue(headerName, value, value_len);
        break;
    }
    default:
        break;
    }
};

// Read headers to extract information from them (like hostname from the Host: header). Do not scan them for attacks.
void Waf2Transaction::detectSpecificHeader(const char* name, int name_len, const char* value, int value_len)
{
    HeaderType header_t = detectHeaderType(name, name_len);

    switch (header_t)
    {
    case HeaderType::CONTENT_TYPE_HEADER:
        parseContentType(value, value_len);
        break;
    case HeaderType::HOST_HEADER:
        m_hostStr = std::string(value, value_len);
        break;
    case HeaderType::USER_AGENT_HEADER:
        m_userAgentStr = std::string(value, value_len);
        break;
    default:
        break;
    }
}

void Waf2Transaction::detectHeaders()
{
    if (isUrlLimitReached(m_uriStr.size())) {
        dbgTrace(D_WAAP_ULIMITS) << "[USER LIMITS] Url limit exceeded";
        return;
    }
    else if (!isPreventModeValidMethod(getMethod())) {
        dbgTrace(D_WAAP_ULIMITS) << "[USER LIMITS] Invalid http method: " << getMethod();
        return;
    }

    for (auto it = hdrs_map.begin(); it != hdrs_map.end(); ++it)
    {
        if (isHttpHeaderLimitReached(it->first, it->second)) {
            dbgTrace(D_WAAP_ULIMITS) << "[USER LIMITS] Http header limit exceeded";
            return;
        }
        detectSpecificHeader(it->first.c_str(), it->first.size(),
            it->second.c_str(), it->second.size());
    }
}

void Waf2Transaction::scanHeaders()
{
    m_processedHeaders = true;

    // Scan relevant headers for attacks
    for (auto it = hdrs_map.begin(); it != hdrs_map.end(); ++it)
    {
        scanSpecificHeder(it->first.c_str(), it->first.size(),
            it->second.c_str(), it->second.size());
    }
}

void Waf2Transaction::set_uri(const char* uri) {
    dbgTrace(D_WAAP) << "[transaction:" << this << "] set_uri('" << uri << "')";
    m_uriStr = uri;
}

void Waf2Transaction::set_host(const char* host) {
    dbgTrace(D_WAAP) << "[transaction:" << this << "] set_host('" << host << "')";
    m_hostStr = host;
}

void Waf2Transaction::start_request_hdrs() {
    dbgTrace(D_WAAP) << "[transaction:" << this << "] start_request_hdrs";
    // Clear all things that will be filled by the incoming request headers that will follow
    m_contentType = Waap::Util::CONTENT_TYPE_UNKNOWN;
    m_requestBodyParser = NULL;
}

void Waf2Transaction::add_request_hdr(const char* name, int name_len, const char* value, int value_len) {
    dbgTrace(D_WAAP) << "[transaction:" << this << "] add_request_hdr(name='" << std::string(name, name_len) <<
        "', value='" << std::string(value, value_len) << "')";
    std::string header_name(name, name_len);
    boost::algorithm::to_lower(header_name);
    hdrs_map[header_name] = std::string(value, value_len);
}

void Waf2Transaction::end_request_hdrs() {
    dbgFlow(D_WAAP) << "[transaction:" << this << "] end_request_hdrs";
    m_isScanningRequired = setCurrentAssetContext();
    if (m_siteConfig != NULL)
    {
        // getOverrideState also extracts the source identifier and populates m_source_identifier
        // but the State itself is not needed now
        Waap::Override::State overrideState = getOverrideState(m_siteConfig);
    }
    IdentifiersEvent ids(m_source_identifier, m_pWaapAssetState->m_assetId);
    ids.notify();
    // Read relevant headers and extract meta information such as host name
    // Do this before scanning the URL because scanning URL might require this information.
    if (m_isScanningRequired) {
        createUserLimitsState();
        detectHeaders();
        if (isUserLimitReached()) {
            return;
        }
    }
    // Scan URL and url query
    if (m_isScanningRequired && !m_processedUri) {
        processUri(m_uriStr, "url");
    }
    // Scan relevant headers for attacks
    if (m_isScanningRequired && !m_processedHeaders) {
        scanHeaders();
    }


    if(m_siteConfig != NULL) {
        // Create rate limiting policy (lazy, on first request)
        const std::shared_ptr<Waap::RateLimiting::Policy> rateLimitingPolicy = m_siteConfig->get_RateLimitingPolicy();
        if(rateLimitingPolicy && rateLimitingPolicy->getRateLimitingEnforcementStatus())
        {
            if (m_pWaapAssetState->getRateLimitingState() == nullptr)
            {
                m_pWaapAssetState->createRateLimitingState(rateLimitingPolicy);
            }
            dbgTrace(D_WAAP) << "(Waf2Engine::end_request_hdrs): RateLimiting check starts.";

            // Get current clock time
            I_TimeGet* timer = Singleton::Consume<I_TimeGet>::by<WaapComponent>();

            // The rate limiting state tracks rate limiting information for all sources
            std::shared_ptr<Waap::RateLimiting::State> rateLimitingState = m_pWaapAssetState->getRateLimitingState();

            std::chrono::seconds now = std::chrono::duration_cast<std::chrono::seconds>(timer->getMonotonicTime());

            bool logRateLimiting = false;
            if (rateLimitingState && (rateLimitingState->execute
                (m_source_identifier, m_uriPath, now, logRateLimiting) == false))
            {
                dbgTrace(D_WAAP) << "(Waf2Engine::end_request_hdrs): RateLimiting  decision: Block.";
                // block request due to rate limiting
                auto decision = m_waapDecision.getDecision(RATE_LIMITING_DECISION);
                decision->setBlock(true);
                decision->setLog(logRateLimiting);
            }
        }
        else {
            dbgTrace(D_WAAP) << "(Waf2Engine::end_request_hdrs): No rate limiting policy.";
        }
    }
}

void Waf2Transaction::start_request_body() {
    dbgTrace(D_WAAP) << "[transaction:" << this << "] start_request_body: m_contentType=" << m_contentType;

    clearRequestParserState();


    m_requestBodyParser = new ParserRaw(m_deepParserReceiver, 0, "body");

    m_request_body_bytes_received = 0;
    m_request_body.clear();
}

void Waf2Transaction::add_request_body_chunk(const char* data, int data_len) {
    dbgTrace(D_WAAP) << "[transaction:" << this << "] add_request_body_chunk (" << data_len << " bytes): parser='" <<
        (m_requestBodyParser ? m_requestBodyParser->name() : "none") << "': '" << std::string(data, data_len) << "'";

    if (isHttpBodyLimitReached(data_len)) {
        dbgTrace(D_WAAP_ULIMITS) << "[USER LIMITS] Http body limit exceeded";
        return;
    }
    m_request_body_bytes_received += data_len;
    size_t maxSizeToScan = m_request_body_bytes_received;

    if (m_siteConfig != NULL)
    {
        auto waapParams = m_siteConfig->get_WaapParametersPolicy();
        if (waapParams != nullptr)
        {
            std::string maxSizeToScanStr = waapParams->getParamVal("max_body_size", "");
            if (maxSizeToScanStr != "")
            {
                maxSizeToScan = std::stoul(maxSizeToScanStr.c_str());
            }
        }
    }

    if (m_isScanningRequired && m_request_body_bytes_received <= maxSizeToScan)
    {
        if (m_requestBodyParser != NULL) {
            m_requestBodyParser->push(data, data_len);
            if (isObjectDepthLimitReached(m_deepParser.getLocalMaxObjectDepth())) {
                dbgTrace(D_WAAP_ULIMITS) << "[USER LIMITS] Object depth limit exceeded";
                return;
            }
        }
        else {
            dbgWarning(D_WAAP) << "[transaction:" << this << "] add_request_body_chunk (" << data_len <<
                " bytes): parser='NONE'. This is most probably a bug. "
                "Some parser MUST be installed for this transaction!";
        }
    }

    // Collect up to MAX_REQUEST_BODY_SIZE of input data for each request
    if (m_request_body.length() + data_len <= MAX_REQUEST_BODY_SIZE) {
        m_request_body.append(data, (size_t)data_len);
    }
    else if (m_request_body.length() < MAX_REQUEST_BODY_SIZE) {
        size_t piece = MAX_REQUEST_BODY_SIZE - m_request_body.length();
        // Note: piece is guaranteed to be > data_len, so the write below is safe.
        m_request_body.append(data, piece);
    }
}

void Waf2Transaction::end_request_body() {
    dbgTrace(D_WAAP) << "[transaction:" << this << "] end_request_body";

    if (m_requestBodyParser != NULL) {
        m_requestBodyParser->finish();
        if (isObjectDepthLimitReached(m_deepParser.getLocalMaxObjectDepth())) {
            dbgTrace(D_WAAP_ULIMITS) << "[USER LIMITS] Object depth limit exceeded";
        }

        if (m_contentType != Waap::Util::CONTENT_TYPE_UNKNOWN && m_request_body.length() > 0) {
            m_deepParser.m_key.pop("body");
        }
    }

    // Check and output [ERROR] message if keyStack is not empty (it should be empty here).
    if (!m_deepParser.m_key.empty()) {
        dbgWarning(D_WAAP) << "[transaction:" << this << "] end_request_body: parser='" <<
            (m_requestBodyParser ? m_requestBodyParser->name() : "<NONE>") <<
            "'. ERROR: m_key is not empty. full key='" << m_deepParser.m_key.c_str() << "'";
    }

    clearRequestParserState();
}

void Waf2Transaction::end_request() {
    dbgTrace(D_WAAP) << "[transaction:" << this << "] end_request";
    clearRequestParserState();

    // Enable response headers processing only if values parsed from request contained at least one URL
    auto openRedirectPolicy = m_siteConfig ? m_siteConfig->get_OpenRedirectPolicy() : NULL;
    if (openRedirectPolicy && openRedirectPolicy->enable && !m_openRedirectState.empty()) {
        m_responseInspectReasons.setOpenRedirect(true);
    }

    auto errorLimitingPolicy = m_siteConfig ? m_siteConfig->get_ErrorLimitingPolicy() : NULL;
    if (errorLimitingPolicy && errorLimitingPolicy->getRateLimitingEnforcementStatus()) {
        m_responseInspectReasons.setErrorLimiter(true);
    }

    auto rateLimitingPolicy = m_siteConfig ? m_siteConfig->get_RateLimitingPolicy() : NULL;
    if (rateLimitingPolicy && rateLimitingPolicy->getRateLimitingEnforcementStatus()) {
        m_responseInspectReasons.setRateLimiting(true);
    }

    auto securityHeadersPolicy = m_siteConfig ? m_siteConfig->get_SecurityHeadersPolicy() : NULL;
    if (securityHeadersPolicy && securityHeadersPolicy->m_securityHeaders.enable) {
        m_responseInjectReasons.setSecurityHeaders(true);
        if (m_pWaapAssetState->getSecurityHeadersState() == nullptr)
        {
            m_pWaapAssetState->createSecurityHeadersState(securityHeadersPolicy);
        }
        dbgTrace(D_WAAP) << "(Waf2Engine::end_request): Security Headers State was created";
    }


    // Enable response headers processing if response scanning is enabled in policy
    auto errorDisclosurePolicy = m_siteConfig ? m_siteConfig->get_ErrorDisclosurePolicy() : NULL;
    m_responseInspectReasons.setErrorDisclosure(errorDisclosurePolicy && errorDisclosurePolicy->enable);
}

void Waf2Transaction::extractEnvSourceIdentifier()
{
    auto env = Singleton::Consume<I_Environment>::by<WaapComponent>();
    auto env_source_identifiers = env->get<std::string>("sourceIdentifiers");
    if (!env_source_identifiers.ok() || env_source_identifiers.unpack().empty()) {
        dbgInfo(D_WAAP) << "Could not extract source identifier from the environment";
        return;
    }

    // Take the first source identifier in set provided by the environment
    dbgTrace(D_WAAP) << "Set source identifier from the Environment";
    m_source_identifier = *(env_source_identifiers);
}

void Waf2Transaction::finish() {
    dbgTrace(D_WAAP) << "[transaction:" << this << "] finish";
    clearRequestParserState();
}

void Waf2Transaction::set_ignoreScore(bool ignoreScore) {
    m_ignoreScore = ignoreScore;
}

void
Waf2Transaction::decide(
    bool& bForceBlock,
    bool& bForceException,
    int mode)
{
    dbgTrace(D_WAAP) << "[transaction:" << this << "] decide (m_scanResult=" << m_scanResult << ")...";

    int bSendResponse = false;

    // If WAF stage1 found suspicious request - send it to stage2 and wait for decision.
    if (m_scanResult) {
        bSendResponse = true;
    }

    // If mode == 2 - don't send all traffic to stage2 (it won't be logged)
    if (mode == 2) {
        bSendResponse = false;
    }

    // Normalize URL
    std::string normalizedUri = normalize_uri(m_uriStr);

    std::string json = buildWaapResultJson(
        m_scanResult,
        *this,
        bSendResponse,
        normalizedUri,
        m_uriStr,
        bForceBlock,
        bForceException
    );
    m_waapDecision.setJson(json);
}

bool
Waf2Transaction::isHtmlType(const char* data, int data_len){
    if(m_uriPath.find(".js") != std::string::npos || m_uriPath.find(".css") != std::string::npos)
    {
        dbgTrace(D_WAAP) << "Waf2Transaction::isHtmlType: false";
        return false;
    }
    std::string body(data);
    if(!m_pWaapAssetState->getSignatures()->html_regex.hasMatch(body))
    {
        dbgTrace(D_WAAP) << "Waf2Transaction::isHtmlType: false";
        return false;
    }
    dbgTrace(D_WAAP) << "Waf2Transaction::isHtmlType: true";
    return true;
}

// Search for <head> html tag - return true if found and update the injection correct position.
bool
Waf2Transaction::findHtmlTagToInject(const char* data, int data_len, int& pos)
{
    bool headFound = false;
    static const char tag[] = "<head>";
    static size_t tagSize = sizeof(tag) - 1;

    // Searching tag <head> by iterating over data and always check last 6 bytes against the required tag.
    for (pos = 0; pos<data_len && !headFound; ++pos) {
        m_tagHist[m_tagHistPos] = data[pos];
        m_tagHistPos++;
        // wrap
        if (m_tagHistPos >= tagSize) {
            m_tagHistPos = 0;
        }
        // check
        bool tagMatches = true;
        size_t tagHistPosCheck = m_tagHistPos;
        for (size_t i=0; i < tagSize; ++i) {
            if (tag[i] != ::tolower(m_tagHist[tagHistPosCheck])) {
                tagMatches = false;
                break;
            }
            tagHistPosCheck++;
            if (tagHistPosCheck >= tagSize) {
                tagHistPosCheck = 0;
            }
        }
        if (tagMatches) {
            headFound = true;
        }
    }

    if(!headFound)
    {
        return false;
    }

    return true;
}

void
Waf2Transaction::completeInjectionResponseBody(std::string& strInjection)
{
    if (m_responseInjectReasons.shouldInjectAntibot()) {
        dbgTrace(D_WAAP_BOT_PROTECTION) <<
            "Waf2Transaction::completeInjectionResponseBody(): Injecting data (antiBot)";
        strInjection += "<script src=\"cp-ab.js\"></script>";
        // No need to inject more than once
        m_responseInjectReasons.setAntibot(false);
    }

    if (m_responseInjectReasons.shouldInjectCsrf()) {
        dbgTrace(D_WAAP) << "Waf2Transaction::completeInjectionResponseBody(): Injecting data (csrf)";
        strInjection += "<script src=\"cp-csrf.js\"></script>";
        // No need to inject more than once
        m_responseInjectReasons.setCsrf(false);
    }
}

void
Waf2Transaction::handleSecurityHeadersInjection(std::vector<std::pair<std::string, std::string>>& injectHeaderStrs){
    auto securityHeadersPolicy = m_siteConfig ? m_siteConfig->get_SecurityHeadersPolicy() : NULL;
    if (securityHeadersPolicy) {
        if (!securityHeadersPolicy->m_securityHeaders.enable) {
            dbgTrace(D_WAAP) <<
                "(Waf2Engine::handleSecurityHeadersInjection): Security Headers Disabled";
        }
        else if (m_pWaapAssetState->getSecurityHeadersState() == nullptr) {
            dbgDebug(D_WAAP) <<
                "(Waf2Engine::handleSecurityHeadersInjection): Security Headers State was not created as expected";
        }
        else {
            injectHeaderStrs = m_pWaapAssetState->getSecurityHeadersState()->headersInjectStrs;
        }
    }
}

bool Waf2Transaction::shouldInjectCSRF()
{
    return m_responseInjectReasons.shouldInjectCsrf();
}

void Waf2Transaction::disableShouldInjectSecurityHeaders() {
    m_responseInjectReasons.setSecurityHeaders(false);
}

bool Waf2Transaction::shouldInjectSecurityHeaders()
{
    return m_responseInjectReasons.shouldInjectSecurityHeaders();
}

void
Waf2Transaction::checkShouldInject()
{
    dbgTrace(D_WAAP) << "Waf2Transaction::checkShouldInject(): starts";
    std::string uri = m_uriPath;
    std::string low_method = m_methodStr;
    std::transform(low_method.begin(), low_method.end(), low_method.begin(), ::tolower);

    auto csrfPolicy = m_siteConfig ? m_siteConfig->get_CsrfPolicy() : NULL;
    bool csrf = false;
    dbgTrace(D_WAAP) << "Waf2Transaction::checkShouldInject(): received the relevant Application configuration "
        "from the I/S";
    if (csrfPolicy && csrfPolicy->enable) {
        csrf = true;
    }
    else
    {
        dbgTrace(D_WAAP) << "Waf2Transaction::checkShouldInject(): Should not inject CSRF scripts.";
    }

    if(csrf) {
        dbgTrace(D_WAAP) << "Waf2Transaction::checkShouldInject(): Should inject CSRF script";
        m_responseInjectReasons.setCsrf(true);
    }
    return;
}


bool
Waf2Transaction::decideAfterHeaders()
{
    dbgFlow(D_WAAP) << "Waf2Transaction::decideAfterHeaders()";

    WaapConfigAPI ngenAPIConfig;
    WaapConfigApplication ngenSiteConfig;
    IWaapConfig *sitePolicy = NULL; // will be NULL or point to either API or SITE config.

    if (WaapConfigAPI::getWaapAPIConfig(ngenAPIConfig)) {
        dbgTrace(D_WAAP) << "Waf2Transaction::decideAfterHeaders(): got relevant API configuration from the I/S";
        sitePolicy = &ngenAPIConfig;
    }
    else if (WaapConfigApplication::getWaapSiteConfig(ngenSiteConfig)) {
        dbgTrace(D_WAAP) <<
            "Waf2Transaction::decideAfterHeaders(): got relevant Application configuration from the I/S";
        sitePolicy = &ngenSiteConfig;
    }

    if (!sitePolicy) {
        dbgTrace(D_WAAP) << "Waf2Transaaction::decideAfterHeaders(): no policy - do not block";
        return false;
    }

    m_overrideState = getOverrideState(sitePolicy);

    // Select scores pool by location (but use forced pool when forced)
    std::string realPoolName =
        (m_scanResult) ?
            Waap::Scores::getScorePoolNameByLocation(m_scanResult->location) :
            KEYWORDS_SCORE_POOL_BASE;

    // Autonomus Security
    AnalysisResult analysisResult;
    bool shouldBlock = decideAutonomousSecurity(
        *sitePolicy,
        1,
        true,
        analysisResult,
        realPoolName,
        UNKNOWN_TYPE
    );

    return finalizeDecision(sitePolicy, shouldBlock);
}

// Note: the only user of the transactionResult structure filled by this method is waap_automation.
// TODO: Consider removing this parameter (and provide access to this information by other means)
int
Waf2Transaction::decideFinal(
    int mode,
    AnalysisResult &transactionResult,
    const std::string &poolName,
    PolicyCounterType fpClassification)
{
    dbgFlow(D_WAAP) << "Waf2Transaction::decideFinal(): starts";

    // Select scores pool by location (but use forced pool when forced)
    std::string realPoolName =
        (poolName == KEYWORDS_SCORE_POOL_BASE && m_scanResult) ?
            Waap::Scores::getScorePoolNameByLocation(m_scanResult->location) :
            poolName;

    // decision of (either) API or Application module
    bool shouldBlock = false;

    // TODO:: base class for both, with common inteface
    WaapConfigAPI ngenAPIConfig;
    WaapConfigApplication ngenSiteConfig;
    IWaapConfig *sitePolicy = NULL; // will be NULL or point to either API or SITE config.

    // API config is more specific, hence if it exists it overrides anything from WaapConfigApplication
    if (WaapConfigAPI::getWaapAPIConfig(ngenAPIConfig)) {
        dbgTrace(D_WAAP) << "Waf2Transaction::decideFinal(): got relevant API configuration from the I/S";
        sitePolicy = &ngenAPIConfig;
        m_overrideState = getOverrideState(sitePolicy);

    }
    else if (WaapConfigApplication::getWaapSiteConfig(ngenSiteConfig)) {
        dbgTrace(D_WAAP) << "Waf2Transaction::decideFinal(): got relevant Application configuration from the I/S";
        sitePolicy = &ngenSiteConfig;
        m_overrideState = getOverrideState(sitePolicy);

        shouldBlock = decideAutonomousSecurity(
            *sitePolicy,
            mode,
            false,
            transactionResult,
            realPoolName,
            fpClassification);

        // CSRF Protection
        auto csrfPolicy = m_siteConfig ? m_siteConfig->get_CsrfPolicy() : nullptr;
        if(csrfPolicy && csrfPolicy->enable) {
            shouldBlock |= m_csrfState.decide(m_methodStr, m_waapDecision, csrfPolicy);
        }
        // User limits
        shouldBlock |= (getUserLimitVerdict() == ngx_http_cp_verdict_e::TRAFFIC_VERDICT_DROP);
    }

    if (mode == 2) {
        decide(
            m_overrideState.bForceBlock,
            m_overrideState.bForceException,
            mode
        );
        shouldBlock = isSuspicious();
    }

    return finalizeDecision(sitePolicy, shouldBlock);
}

int
Waf2Transaction::finalizeDecision(IWaapConfig *sitePolicy, bool shouldBlock)
{
    auto decision = std::dynamic_pointer_cast<AutonomousSecurityDecision>(
        m_waapDecision.getDecision(AUTONOMOUS_SECURITY_DECISION));
    // Send log
    if (sitePolicy)
    {
        // auto reject should have default threat level info and above
        if (m_overrideState.bForceBlock && decision->getThreatLevel() == ThreatLevel::NO_THREAT)
        {
            decision->setThreatLevel(ThreatLevel::THREAT_INFO);
        }
    }

    if (m_overrideState.bForceBlock) {
        dbgTrace(D_WAAP) << "Waf2Transaction::finalizeDecision(): setting shouldBlock to true due to override";
        shouldBlock = true; // BLOCK
    }
    else if (m_overrideState.bForceException) {
        dbgTrace(D_WAAP) << "Waf2Transaction::finalizeDecision(): setting shouldBlock to false due to override";
        shouldBlock = false; // PASS
    }

    if (m_siteConfig) {
        const std::shared_ptr<Waap::Trigger::Policy> triggerPolicy = m_siteConfig->get_TriggerPolicy();
        if (triggerPolicy) {
            const std::shared_ptr<Waap::Trigger::Log> triggerLog = getTriggerLog(triggerPolicy);
            if (triggerLog && shouldSendExtendedLog(triggerLog))
            {
                m_responseInspectReasons.setCollectResponseForLog(true);
            }
        }
    }

    dbgTrace(D_WAAP) << "Waf2Transaction::finalizeDecision(): returning shouldBlock: " << shouldBlock;
    return shouldBlock;
}

void Waf2Transaction::appendCommonLogFields(LogGen& waapLog,
    const std::shared_ptr<Waap::Trigger::Log> &triggerLog,
    bool shouldBlock,
    const std::string& logOverride,
    const std::string& incidentType) const
{
    auto env = Singleton::Consume<I_Environment>::by<WaapComponent>();
    auto active_id = env->get<std::string>("ActiveTenantId");
    if (active_id.ok()) waapLog.addToOrigin(LogField("tenantId", *active_id));
    auto proxy_ip = env->get<std::string>(HttpTransactionData::proxy_ip_ctx);
    if (proxy_ip.ok() && m_remote_addr != proxy_ip.unpack())
    {
        waapLog << LogField("proxyIP", static_cast<std::string>(proxy_ip.unpack()));
    }
    waapLog << LogField("sourceIP", m_remote_addr);
    waapLog << LogField("httpSourceId", m_source_identifier);
    waapLog << LogField("sourcePort", m_remote_port);
    waapLog << LogField("httpHostName", m_hostStr);
    waapLog << LogField("httpMethod", m_methodStr);
    const auto& autonomousSecurityDecision = std::dynamic_pointer_cast<AutonomousSecurityDecision>(
        m_waapDecision.getDecision(AUTONOMOUS_SECURITY_DECISION));
    bool send_extended_log = shouldSendExtendedLog(triggerLog);
    if (triggerLog->webUrlPath || autonomousSecurityDecision->getOverridesLog()) {
        std::string httpUriPath = m_uriPath;

        if (httpUriPath.length() > MAX_LOG_FIELD_SIZE)
        {
            httpUriPath.resize(MAX_LOG_FIELD_SIZE);
        }

        waapLog << LogField("httpUriPath", httpUriPath, LogFieldOption::XORANDB64);
    }
    if (triggerLog->webUrlQuery || autonomousSecurityDecision->getOverridesLog()) {
        std::string uriQuery = m_uriQuery;
        if (uriQuery.length() > MAX_LOG_FIELD_SIZE)
        {
            uriQuery.resize(MAX_LOG_FIELD_SIZE);
        }
        waapLog << LogField("httpUriQuery", uriQuery, LogFieldOption::XORANDB64);
    }
    if (triggerLog->webHeaders || autonomousSecurityDecision->getOverridesLog()) {
        waapLog << LogField("httpRequestHeaders", logHeadersStr(), LogFieldOption::XORANDB64);
    }
    // Log http response code if it is known
    if (m_responseStatus != 0 && send_extended_log && triggerLog->responseCode) {
        waapLog << LogField("httpResponseCode", std::to_string(m_responseStatus));
    }

    // Count of bytes available to send to the log
    std::string requestBodyToLog = (send_extended_log || triggerLog->webBody) ?
        m_request_body : std::string();
    std::string responseBodyToLog = m_response_body;
    if (!shouldBlock && responseBodyToLog.empty())
    {
        responseBodyToLog = "<EMPTY RESPONSE BODY>";
    }

    if (!requestBodyToLog.empty()) {
        size_t requestBodyMaxSize = MAX_LOG_FIELD_SIZE - std::min(MIN_RESP_BODY_LOG_FIELD_SIZE,
            responseBodyToLog.size());
        // Limit request body log field size
        if (requestBodyToLog.length() > requestBodyMaxSize)
        {
            requestBodyToLog.resize(requestBodyMaxSize);
        }
    }

    if (!m_response_body.empty()) {
        size_t responseBodyMaxSize = MAX_LOG_FIELD_SIZE - requestBodyToLog.size();
        // Limit response body log field size
        if (responseBodyToLog.length() > responseBodyMaxSize)
        {
            responseBodyToLog.resize(responseBodyMaxSize);
        }
    }

    if (!requestBodyToLog.empty())
    {
        waapLog << LogField("httpRequestBody", requestBodyToLog, LogFieldOption::XORANDB64);
    }

    if (!responseBodyToLog.empty() && send_extended_log && triggerLog->responseBody)
    {
        waapLog << LogField("httpResponseBody", responseBodyToLog, LogFieldOption::XORANDB64);
    }

    waapLog << LogField("ruleId", m_siteConfig->get_RuleId());
    waapLog << LogField("securityAction", shouldBlock ? "Prevent" : "Detect");
    waapLog << LogField("waapOverride", logOverride);
    waapLog << LogField("practiceType", "Threat Prevention");
    waapLog << LogField("practiceSubType", m_siteConfig->get_PracticeSubType());
    waapLog << LogField("ruleName", m_siteConfig->get_RuleName());
    waapLog << LogField("practiceId", m_siteConfig->get_PracticeId());
    waapLog << LogField("practiceName", m_siteConfig->get_PracticeName());
    waapLog << LogField("waapIncidentType", incidentType);

    // Registering this value would append the list of matched override IDs to the unified log
    if (!m_matchedOverrideIds.empty()) {
        // Convert set to vector and send to log as a list
        std::vector<std::string> vOverrideIds(m_matchedOverrideIds.size());
        std::copy(m_matchedOverrideIds.begin(), m_matchedOverrideIds.end(), vOverrideIds.begin());
        waapLog.addToOrigin(LogField("exceptionIdList", vOverrideIds));
        if (!m_effectiveOverrideIds.empty()) {
            std::vector<std::string> vEffectiveOverrideIds(m_effectiveOverrideIds.size());
            std::copy(m_effectiveOverrideIds.begin(), m_effectiveOverrideIds.end(), vEffectiveOverrideIds.begin());
            waapLog.addToOrigin(LogField("effectiveExceptionIdList", vEffectiveOverrideIds));
        }
    }
}


void
Waf2Transaction::sendLog()
{
    dbgFlow(D_WAAP);
    m_waapDecision.orderDecisions();
    if (m_siteConfig == NULL) {
        dbgWarning(D_WAAP) <<
            "Waf2Transaction::sendLog: no site policy associated with transaction - not sending a log";
        return;
    }
    std::string attackTypes = buildAttackTypes();
    std::string logOverride = "None";
    DecisionTelemetryData telemetryData;
    std::string assetId = m_siteConfig->get_AssetId();
    const auto& autonomousSecurityDecision = std::dynamic_pointer_cast<AutonomousSecurityDecision>(
        m_waapDecision.getDecision(AUTONOMOUS_SECURITY_DECISION));

    telemetryData.source = getSourceIdentifier();
    telemetryData.assetName = m_siteConfig->get_AssetName();
    telemetryData.practiceId = m_siteConfig->get_PracticeId();
    telemetryData.practiceName = m_siteConfig->get_PracticeName();
    if (m_scanResult) {
        telemetryData.attackTypes = m_scanResult->attack_types;
    }
    telemetryData.threat = autonomousSecurityDecision->getThreatLevel();
    if (m_overrideState.bForceBlock) {
        telemetryData.blockType = FORCE_BLOCK;
    }
    else if (m_overrideState.bForceException) {
        telemetryData.blockType = FORCE_EXCEPTION;
    }
    else if (m_waapDecision.getDecision(USER_LIMITS_DECISION)->shouldBlock()) {
        telemetryData.blockType = LIMIT_BLOCK;
    }
    else if (autonomousSecurityDecision->shouldBlock()) {
        telemetryData.blockType = WAF_BLOCK;
    }
    else if (m_waapDecision.getDecision(CSRF_DECISION)->shouldBlock()) {
        telemetryData.blockType = CSRF_BLOCK;
    }
    else {
        telemetryData.blockType = NOT_BLOCKING;
    }

    WaapTelemetryEvent(assetId, telemetryData).notify();

    if (m_overrideState.bIgnoreLog) {
        dbgTrace(D_WAAP) << "Waf2Transaction::sendLog: override is to ignore log - not sending a log";
        return;
    }

    dbgTrace(D_WAAP) << "force exception: " << m_overrideState.bForceException <<
        " force block: " << m_overrideState.bForceBlock <<
        " matched overrides count: " << m_matchedOverrideIds.size() <<
        " effective overrides count: " << m_effectiveOverrideIds.size();


    bool shouldBlock = false;
    if (m_overrideState.bForceBlock) {
        // If override forces "reject" decision, mention it in the "override" log field.
        logOverride = OVERRIDE_DROP;
        shouldBlock = true;
    } else if (m_overrideState.bForceException) {
        // If override forces "allow" decision, mention it in the "override" log field.
        logOverride = OVERRIDE_ACCEPT;
    } else if (m_scanner.getIgnoreOverride()) {
        logOverride = OVERRIDE_IGNORE;
    }

    // Get triggers
    const std::shared_ptr<Waap::Trigger::Policy> triggerPolicy = m_siteConfig->get_TriggerPolicy();

    if (!triggerPolicy || triggerPolicy->triggers.empty()) {
        dbgTrace(D_WAAP) << "Waf2Transaction::sendLog: found no triggers (or triggers are absent) - not sending a log";
        return;
    }

    const std::shared_ptr<Waap::Trigger::Log> triggerLog = getTriggerLog(triggerPolicy);

    // If there were no triggers of type Log - do not send log
    if (!triggerLog) {
        dbgTrace(D_WAAP) << "Waf2Transaction::sendLog: found no triggers of type 'Log' - not sending a log";
        return;
    }

    static int cur_grace_logs = 0;
    bool grace_period = is_hybrid_mode && cur_grace_logs < max_grace_logs;
    bool send_extended_log = shouldSendExtendedLog(triggerLog);
    if (grace_period) {
        dbgTrace(D_WAAP)
            << "Waf2Transaction::sendLog: current grace log index: "
            << cur_grace_logs + 1
            << " out of "
            << max_grace_logs;
    }

    shouldBlock |= m_waapDecision.getShouldBlockFromHighestPriorityDecision();
    // Do not send Detect log if trigger disallows it
    if (!send_extended_log && shouldBlock == false && !triggerLog->tpDetect &&
        !autonomousSecurityDecision->getOverridesLog())
    {
        dbgTrace(D_WAAP) << "Waf2Transaction::sendLog: not sending Detect log (triggers)";
        return;
    }

    // Do not send Prevent log if trigger disallows it
    if (!send_extended_log && shouldBlock == true && !triggerLog->tpPrevent &&
        !autonomousSecurityDecision->getOverridesLog())
    {
        dbgTrace(D_WAAP) << "Waf2Transaction::sendLog: not sending Prevent log (triggers)";
        return;
    }

    // In case no decision to block or log - send log if extend log or override
    if (!m_waapDecision.anyDecisionsToLogOrBlock())
    {
        if (send_extended_log || autonomousSecurityDecision->getOverridesLog())
        {
            sendAutonomousSecurityLog(triggerLog, shouldBlock, logOverride, attackTypes);
            dbgTrace(D_WAAP) << "Waf2Transaction::sendLog()::" <<
                "sending autonomous security log due to either extended log or an override";
        }
        else
        {
            dbgTrace(D_WAAP) << "Waf2Transaction::sendLog: no decision to log";
        }
        return;
    }

    DecisionType decision_type = m_waapDecision.getHighestPriorityDecisionToLog();
    if (decision_type == DecisionType::NO_WAAP_DECISION) {
        if (send_extended_log || autonomousSecurityDecision->getOverridesLog()) {
            sendAutonomousSecurityLog(triggerLog, shouldBlock, logOverride, attackTypes);
            if (grace_period) {
                dbgTrace(D_WAAP)
                    << "Waf2Transaction::sendLog: Sending log in grace period. Log "
                    << ++cur_grace_logs
                    << "out of "
                    << max_grace_logs;
            }
        }
        dbgTrace(D_WAAP) << "Waf2Transaction::sendLog: decisions marked for block only";
        return;
    }

    auto maybeLogTriggerConf = getConfiguration<LogTriggerConf>("rulebase", "log");
    switch (decision_type)
    {
    case USER_LIMITS_DECISION: {
        std::string incidentDetails;
        std::string incidentType;
        if (isIllegalMethodViolation()) {
            incidentDetails += "Http method received: ";
            incidentDetails +=  getMethod();
            incidentType += "Illegal http method violation";
        }
        else {
            auto strData = getViolatedUserLimitStrData();
            incidentDetails += "Http request ";
            incidentDetails += strData.type;
            incidentDetails += " (";
            incidentDetails += strData.policy;
            incidentDetails += ")";
            incidentType += "Http limit violation";
        }

        LogGenWrapper logGenWrapper(
                                maybeLogTriggerConf,
                                "Web Request",
                                ReportIS::Audience::SECURITY,
                                LogTriggerConf::SecurityType::ThreatPrevention,
                                Severity::HIGH,
                                Priority::HIGH,
                                shouldBlock);

        LogGen& waap_log = logGenWrapper.getLogGen();
        appendCommonLogFields(waap_log, triggerLog, shouldBlock, logOverride, incidentType);
        waap_log << LogField("waapIncidentDetails", incidentDetails);
        waap_log << LogField("eventConfidence", "High");
        if (grace_period) {
            dbgTrace(D_WAAP)
                << "Waf2Transaction::sendLog: Sending log in grace period. Log "
                << ++cur_grace_logs
                << "out of "
                << max_grace_logs;
        }
        break;
    }
    case OPEN_REDIRECT_DECISION:
    case ERROR_LIMITING_DECISION:
    case RATE_LIMITING_DECISION:
    case ERROR_DISCLOSURE_DECISION: {
        LogGenWrapper logGenWrapper(
                                maybeLogTriggerConf,
                                "API Request",
                                ReportIS::Audience::SECURITY,
                                LogTriggerConf::SecurityType::ThreatPrevention,
                                Severity::CRITICAL,
                                Priority::HIGH,
                                shouldBlock);

        LogGen& waap_log = logGenWrapper.getLogGen();
        waap_log << LogField("eventConfidence", "Very High");

        std::string incidentDetails;
        std::string incidentType;
        m_waapDecision.getIncidentLogFields(
            std::to_string(m_responseStatus),
            incidentDetails,
            incidentType
        );

        if (decision_type == ERROR_DISCLOSURE_DECISION) {
            waap_log << LogField("waapFoundIndicators", getKeywordMatchesStr(), LogFieldOption::XORANDB64);
        }

        appendCommonLogFields(waap_log, triggerLog, shouldBlock, logOverride, incidentType);


        waap_log << LogField("waapIncidentDetails", incidentDetails);
        if (grace_period) {
            dbgTrace(D_WAAP)
                << "Waf2Transaction::sendLog: Sending log in grace period. Log "
                << ++cur_grace_logs
                << "out of "
                << max_grace_logs;
        }
        break;
    }
    case CSRF_DECISION: {
        LogGenWrapper logGenWrapper(
                                maybeLogTriggerConf,
                                "CSRF Protection",
                                ReportIS::Audience::SECURITY,
                                LogTriggerConf::SecurityType::ThreatPrevention,
                                Severity::CRITICAL,
                                Priority::HIGH,
                                shouldBlock);

        LogGen& waap_log = logGenWrapper.getLogGen();
        appendCommonLogFields(waap_log, triggerLog, shouldBlock, logOverride, "Cross Site Request Forgery");
        waap_log << LogField("waapIncidentDetails", "CSRF Attack discovered.");
        if (grace_period) {
            dbgTrace(D_WAAP)
                << "Waf2Transaction::sendLog: Sending log in grace period. Log "
                << ++cur_grace_logs
                << "out of "
                << max_grace_logs;
        }
        break;
    }
    case AUTONOMOUS_SECURITY_DECISION: {
        if (triggerLog->webRequests ||
            send_extended_log ||
            autonomousSecurityDecision->getThreatLevel() != ThreatLevel::NO_THREAT ||
            autonomousSecurityDecision->getOverridesLog()) {
            sendAutonomousSecurityLog(triggerLog, shouldBlock, logOverride, attackTypes);
            if (grace_period) {
                dbgTrace(D_WAAP)
                    << "Waf2Transaction::sendLog: Sending log in grace period. Log "
                    << ++cur_grace_logs
                    << "out of "
                    << max_grace_logs;
            }
        }
        break;
    }
    default:
        static_assert(true, "Illegal DecisionType enum value");
        break;
    } // end switch
}

bool
Waf2Transaction::decideAutonomousSecurity(
    const IWaapConfig &sitePolicy,
    int mode,
    bool afterHeaders,
    AnalysisResult &transactionResult,
    const std::string &poolName,
    PolicyCounterType fpClassification)
{
    dbgFlow(D_WAAP) <<
        "Waf2Transaction::decideAutonomousSecurity(): " <<
        "mode=" << mode <<
        ", afterHeaders=" << afterHeaders <<
        ", poolName='" << poolName << "'";

    if (mode == 2)
    {
        return isSuspicious();
    }

    if (!sitePolicy.get_WebAttackMitigation()) {
        // Web security not enabled
        dbgTrace(D_WAAP) << "Autonomous security is not enabled in policy.";
        return false;
    }

    std::shared_ptr<AutonomousSecurityDecision> decision = std::dynamic_pointer_cast<AutonomousSecurityDecision>(
        m_waapDecision.getDecision(AUTONOMOUS_SECURITY_DECISION));

    // Do not call stage2 so it doesn't learn from exceptions.
    // Also do not call stage2 for attacks found in parameter name
    if (!m_overrideState.bForceException && !(m_scanResult && m_scanResult->m_isAttackInParam)) {
        if (!m_processedUri) {
            dbgWarning(D_WAAP) << "decideAutonomousSecurity(): processing URI although is was supposed "
                "to be processed earlier ...";
            processUri(m_uriStr, "url");
        }

        if (!m_processedHeaders) {
            dbgWarning(D_WAAP) << "decideAutonomousSecurity(): processing Headers although is was supposed "
                "to be processed earlier ...";
            scanHeaders();
        }

        dbgTrace(D_WAAP) << "decideAutonomousSecurity(): processing stage2 for final decision ...";

        // Call stage2
        transactionResult =
            Singleton::Consume<I_DeepAnalyzer>::by<WaapComponent>()->analyzeData(this, &sitePolicy);

        decision->setThreatLevel(transactionResult.threatLevel);

        decision->setBlock(transactionResult.shouldBlock);

        // Once these are known - fill the values to be included in the log
        decision->setRelativeReputation(transactionResult.d2Analysis.relativeReputation);
        decision->setFpMitigationScore(transactionResult.d2Analysis.fpMitigationScore);
        decision->setFinalScore(transactionResult.d2Analysis.finalScore);
        decision->setRelativeReputationMean(transactionResult.d2Analysis.reputationMean);
        decision->setVariance(transactionResult.d2Analysis.variance);

        dbgTrace(D_WAAP) << "decideAutonomousSecurity(): stage2 decision is: " <<
            decision->shouldBlock() << "; threatLevel: " << decision->getThreatLevel() <<
            "; blockingLevel: " << static_cast<std::underlying_type<BlockingLevel>::type>(
            sitePolicy.get_BlockingLevel());

        if (!afterHeaders || decision->shouldBlock()) {
            ScoreBuilderData sbData;

            sbData.m_fpClassification = transactionResult.d2Analysis.fpClassification;
            sbData.m_sourceIdentifier = getSourceIdentifier();
            sbData.m_keywordsCombinations = getKeywordsCombinations();
            sbData.m_keywordsMatches = getKeywordMatches();
            sbData.m_userAgent = getUserAgent();
            sbData.m_sample = getSample();
            sbData.m_relativeReputation = transactionResult.d2Analysis.relativeReputation;

            if (fpClassification != UNKNOWN_TYPE) {
                sbData.m_fpClassification = fpClassification;
            }

            learnScore(sbData, poolName);
        }
    }

    // Fill attack details for attacks found in parameter names
    if (!m_overrideState.bForceException && m_scanResult && m_scanResult->m_isAttackInParam) {
        // Since stage2 learning doesn't run in this case, assume stage1 score is the final score
        float finalScore = m_scanResult->score;
        ThreatLevel threat = Waap::Conversions::convertFinalScoreToThreatLevel(finalScore);
        bool shouldBlock = Waap::Conversions::shouldDoWafBlocking(&sitePolicy, threat);

        dbgTrace(D_WAAP) << "attack_in_param without stage2 analysis: final score: " << finalScore <<
            ", threat level: " << threat << "\nWAF2 decision to block: " <<
            (shouldBlock ? "block" : "pass");

        decision->setFinalScore(finalScore);
        decision->setThreatLevel(threat);
        decision->setBlock(shouldBlock);

        // Fill transactionResult
        transactionResult.d2Analysis.finalScore = finalScore;
        transactionResult.shouldBlock = shouldBlock;
        transactionResult.threatLevel = threat;
    }

    // Apply overrides
    if (m_overrideState.bForceBlock) {
        dbgTrace(D_WAAP) << "decideAutonomousSecurity(): decision was " << decision->shouldBlock() <<
            " and override forces REJECT ...";
        if (!decision->shouldBlock()) {
            m_effectiveOverrideIds.insert(m_overrideState.forceBlockIds.begin(), m_overrideState.forceBlockIds.end());
        }
        decision->setBlock(true);
        if (!m_overrideState.bIgnoreLog)
        {
            decision->setOverridesLog(true);
        }
    }
    else if (m_overrideState.bForceException) {
        dbgTrace(D_WAAP) << "decideAutonomousSecurity(): decision was " << decision->shouldBlock() <<
            " and override forces ALLOW ...";
        if (m_scanResult) {
            // on accept exception the decision is not set and needs to be calculated to determine effectivness
            ThreatLevel threat = Waap::Conversions::convertFinalScoreToThreatLevel(m_scanResult->score);
            bool shouldBlock = Waap::Conversions::shouldDoWafBlocking(&sitePolicy, threat);
            if (shouldBlock) {
                m_effectiveOverrideIds.insert(
                    m_overrideState.forceExceptionIds.begin(), m_overrideState.forceExceptionIds.end()
                );
            }
        }

        decision->setBlock(false);
        if (!m_overrideState.bIgnoreLog)
        {
            decision->setOverridesLog(true);
        }
    }


    bool log_all = false;
    const std::shared_ptr<Waap::Trigger::Policy> triggerPolicy = sitePolicy.get_TriggerPolicy();
    if (triggerPolicy) {
        const std::shared_ptr<Waap::Trigger::Log> triggerLog = getTriggerLog(triggerPolicy);
        if (triggerLog && triggerLog->webRequests) log_all = true;
    }
    if(decision->getThreatLevel() <= ThreatLevel::THREAT_INFO && !log_all) {
        decision->setLog(false);
    } else {
        decision->setLog(true);
    }

    return decision->shouldBlock();
}

void Waf2Transaction::handleCsrfHeaderInjection(std::string& injectStr)
{
    m_csrfState.injectCookieHeader(injectStr);
}

// Disables response injection (masking any pending injection reasons such as from antibot or csrf)
void
Waf2Transaction::clearAllInjectionReasons() {
    m_responseInjectReasons.clear();
}

// Returns true if WAAP engine is interested in receiving more information about response for this transaction
bool Waf2Transaction::shouldInspectResponse()
{
    return m_responseInspectReasons.shouldInspect() || m_responseInjectReasons.shouldInject();
}
bool Waf2Transaction::shouldInjectResponse()
{
    return m_responseInjectReasons.shouldInject();
}

bool Waf2Transaction::decideResponse()
{
    dbgTrace(D_WAAP) << "Waf2Transaction::decideResponse()";

    if(m_waapDecision.getDecision(ERROR_LIMITING_DECISION)->shouldBlock()) {
        return false; // block
    }
    if(m_waapDecision.getDecision(RATE_LIMITING_DECISION)->shouldBlock()) {
        return false; // block
    }

    bool openRedirectBlock = m_waapDecision.getDecision(OPEN_REDIRECT_DECISION)->shouldBlock();
    bool errorDisclosureBlock = m_waapDecision.getDecision(ERROR_DISCLOSURE_DECISION)->shouldBlock();
    if (openRedirectBlock || errorDisclosureBlock) {
        dbgTrace(D_WAAP) << "Waf2Transaction::decideResponse(): blocking due to" <<
            " OpenRedirect:" << openRedirectBlock <<
            " ErrorDisclosure:" << errorDisclosureBlock;
        return false; // block
    }


    if (m_responseInspectReasons.getApplyOverride()) {
        WaapConfigApplication ngenSiteConfig;

        dbgTrace(D_WAAP_OVERRIDE) << "Checking exceptions for response";
        if (WaapConfigApplication::getWaapSiteConfig(ngenSiteConfig)) {
            dbgTrace(D_WAAP)
                    << "Waf2Transaction::decideResponse(): got relevant Application configuration from the I/S";
            m_overrideState = getOverrideState(&ngenSiteConfig);
            // Apply overrides
            if (m_overrideState.bForceBlock) {
                dbgTrace(D_WAAP)
                        << "Waf2Transaction::decideResponse(): setting shouldBlock to true due to override";
                return false; // BLOCK
            }
            else if (m_overrideState.bForceException) {
                dbgTrace(D_WAAP)
                        << "Waf2Transaction::decideResponse(): setting shouldBlock to false due to override";
                return true; // PASS
            }
        }
    }

    if (m_siteConfig) {
        const std::shared_ptr<Waap::Trigger::Policy> triggerPolicy = m_siteConfig->get_TriggerPolicy();
        if (!triggerPolicy) {
            dbgTrace(D_WAAP) << "Trigger policy was not found. Returning true (accept)";
            return true; // accept
        }

        const std::shared_ptr<Waap::Trigger::Log> triggerLog = getTriggerLog(triggerPolicy);
        if (!triggerLog) {
            dbgTrace(D_WAAP) << "Log trigger configuration was not found. Returning true (accept)";
            return true; // accept
        }

        auto env = Singleton::Consume<I_Environment>::by<Waf2Transaction>();
        auto http_chunk_type = env->get<ngx_http_chunk_type_e>("HTTP Chunk type");
        bool should_send_extended_log = shouldSendExtendedLog(triggerLog) && http_chunk_type.ok();
        if (should_send_extended_log &&
            *http_chunk_type == ngx_http_chunk_type_e::RESPONSE_CODE &&
            !triggerLog->responseBody
        ) {
            should_send_extended_log = false;
        } else if (should_send_extended_log &&
            *http_chunk_type == ngx_http_chunk_type_e::REQUEST_END &&
            !triggerLog->responseCode &&
            !triggerLog->responseBody
        ) {
            should_send_extended_log = false;
        }

        dbgTrace(D_WAAP)
            << "Setting flag for collection of respond content logging to: "
            << (should_send_extended_log ? "True": "False");
        m_responseInspectReasons.setCollectResponseForLog(should_send_extended_log);
    }

    dbgTrace(D_WAAP) << "Waf2Transaction::decideResponse: returns true (accept)";
    return true; // accept
}

bool
Waf2Transaction::reportScanResult(const Waf2ScanResult &res) {
    if (get_ignoreScore() || (res.score >= SCORE_THRESHOLD &&
        (m_scanResult == nullptr || res.score > m_scanResult->score)))
    {
        // Forget any previous scan result and replace with new
        delete m_scanResult;
        m_scanResult = new Waf2ScanResult(res);
        return true;
    }

    return false;
}

bool
Waf2Transaction::shouldIgnoreOverride(const Waf2ScanResult &res) {
    auto exceptions = getConfiguration<ParameterException>("rulebase", "exception");
    if (!exceptions.ok()) {
        dbgInfo(D_WAAP_OVERRIDE) << "matching exceptions error:" << exceptions.getErr();
        return false;
    }
    dbgTrace(D_WAAP_OVERRIDE) << "matching exceptions";

    std::unordered_map<std::string, std::set<std::string>> exceptions_dict;

    if (res.location != "referer") {
        // collect param name
        exceptions_dict["paramName"].insert(res.param_name);
        exceptions_dict["paramName"].insert(IndicatorsFiltersManager::generateKey(res.location, res.param_name, this));

        std::set<std::string> param_name_set;
        param_name_set.insert(res.param_name);
        param_name_set.insert(IndicatorsFiltersManager::generateKey(res.location, res.param_name, this));

        // collect param value
        exceptions_dict["paramValue"].insert(res.unescaped_line);

        // collect param location
        exceptions_dict["paramLocation"].insert(res.location);

        ScopedContext ctx;
        ctx.registerValue<std::string>("paramValue", res.unescaped_line);
        ctx.registerValue<std::set<std::string>>("paramName", param_name_set);

        // collect sourceip, sourceIdentifier, url
        exceptions_dict["sourceIP"].insert(m_remote_addr);
        exceptions_dict["sourceIdentifier"].insert(m_source_identifier);
        exceptions_dict["url"].insert(getUriStr());
        exceptions_dict["hostName"].insert(m_hostStr);

        for (auto &keyword : res.keyword_matches) {
            exceptions_dict["indicator"].insert(keyword);
        }
        for (auto &it : res.found_patterns) {
            exceptions_dict["indicator"].insert(it.first);
        }

        // calling behavior and check if there is a behavior that match to this specific param name.
        auto behaviors = exceptions.unpack().getBehavior(exceptions_dict,
                getAssetState()->m_filtersMngr->getMatchedOverrideKeywords());
        for (const auto &behavior : behaviors) {
            if (behavior == action_ignore)
            {
                dbgTrace(D_WAAP_OVERRIDE) << "matched exceptions for " << res.param_name << " should ignore.";
                std::string overrideId = behavior.getId();
                if (!overrideId.empty()) {
                    m_matchedOverrideIds.insert(overrideId);
                }
                if (!res.keyword_matches.empty() || res.unescaped_line == Waap::Scanner::xmlEntityAttributeId)
                {
                    if (!overrideId.empty()) {
                        m_effectiveOverrideIds.insert(overrideId);
                    }
                }
                return true;
            }
        }
    }

    return false;
}

const std::string Waf2Transaction::buildAttackTypes() const
{
    typedef std::map<std::string, std::vector<std::string>>::const_iterator attack_types_iter;
    if (m_scanResult)
    {
        for (const std::string &regex_name : m_found_patterns)
        {
            attack_types_iter attack_types_for_regex =
                m_pWaapAssetState->getSignatures()->m_attack_types.find(regex_name);
            if (attack_types_for_regex != m_pWaapAssetState->getSignatures()->m_attack_types.end())
            {
                for (const std::string &attack_type : attack_types_for_regex->second)
                {
                    m_scanResult->attack_types.insert(attack_type);
                }
            }
            else {m_scanResult->attack_types.insert("General");}
        }

        if (Waap::Util::vectorStringContain(m_scanResult->keyword_matches, "xml_entity")) {
            m_scanResult->attack_types.insert("XML External Entity");
        }

        if (Waap::Util::vectorStringContain(m_scanResult->keyword_matches, "url_instead_of_file")) {
            m_scanResult->attack_types.insert("URL instead of file");
        }

        auto csrfDecision = m_waapDecision.getDecision(CSRF_DECISION);
        if(csrfDecision && csrfDecision->shouldBlock()) {
            m_scanResult->attack_types.insert("Cross Site Request Forgery");
        }
        auto openRedirectDecision = m_waapDecision.getDecision(OPEN_REDIRECT_DECISION);
        if (openRedirectDecision && openRedirectDecision->shouldBlock()) {
            m_scanResult->attack_types.insert("Open Redirect");
        }

        if (m_scanResult->attack_types.find("General") != m_scanResult->attack_types.end()
                && m_scanResult->attack_types.size() > 1) {
            m_scanResult->attack_types.erase("General");
        }
        return Waap::Util::setToString(m_scanResult->attack_types, false);
    }

    return "";
}

void Waf2Transaction::collectFoundPatterns()
{
    if (m_scanResult)
    {
        for (const auto &found_pattern : m_scanResult->found_patterns)
        {
            const std::string &regex_name = found_pattern.first; // the regex name (key)
            m_found_patterns.insert(regex_name);
        }
    }
}

bool Waf2Transaction::shouldSendExtendedLog(const std::shared_ptr<Waap::Trigger::Log> &trigger_log) const
{
    if (!trigger_log->extendLogging)
    {
        dbgTrace(D_WAAP) << "Should not send extended log. Extended log is disabled.";
        return false;
    }

    auto autonomousSecurityDecision = std::dynamic_pointer_cast<AutonomousSecurityDecision>(
        m_waapDecision.getDecision(AUTONOMOUS_SECURITY_DECISION));
    ReportIS::Severity severity = Waap::Util::computeSeverityFromThreatLevel(
        autonomousSecurityDecision->getThreatLevel());

    if (trigger_log->extendLoggingMinSeverity == "Critical" || trigger_log->extendLoggingMinSeverity == "critical")
    {
        if (severity == ReportIS::Severity::CRITICAL)
        {
            dbgTrace(D_WAAP) << "Should send extended logging. Min Severity Critical. Severity: " << (int) severity;
            return true;
        }
        dbgTrace(D_WAAP) << "Should not send extended logging. Min Severity Critical. Severity: " << (int) severity;
        return false;
    }
    else if (trigger_log->extendLoggingMinSeverity == "High" || trigger_log->extendLoggingMinSeverity == "high")
    {
        if (severity == ReportIS::Severity::CRITICAL || severity == ReportIS::Severity::HIGH)
        {
            dbgTrace(D_WAAP) << "Should send extended logging. Min Severity High. Severity: " << (int) severity;
            return true;
        }
        dbgTrace(D_WAAP) << "Should not send extended logging. Min Severity High. Severity: " << (int) severity;
        return false;
    }

    dbgTrace(D_WAAP) << "Should not send extended logging. Min Severity: " << trigger_log->extendLoggingMinSeverity;
    return false;
}
