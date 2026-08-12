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
#include "WaapOverrideFunctor.h"
#include <boost/uuid/uuid.hpp>            // uuid class
#include <boost/uuid/uuid_generators.hpp> // uuid generators
#include <boost/uuid/uuid_io.hpp>
#include <boost/algorithm/string.hpp>
#include "config.h"
#include "LogGenWrapper.h"
#include <memory>

USE_DEBUG_FLAG(D_WAAP_ULIMITS);
USE_DEBUG_FLAG(D_WAAP);
USE_DEBUG_FLAG(D_WAAP_OVERRIDE);

#define LOW_REPUTATION_THRESHOLD 4
#define NORMAL_REPUTATION_THRESHOLD 6
#define LOG_HEADER_MAX_LENGTH 200

bool Waf2Transaction::isTrustedSource() const
{
    auto policy = m_ngenSiteConfig.get_TrustedSourcesPolicy();
    if (policy == nullptr)
    {
        dbgTrace(D_WAAP) << "Policy for trusted sources is not set";
        return false;
    }
    auto trustedTypes = policy->getTrustedTypes();
    std::string cookieVal;
    auto env = Singleton::Consume<I_Environment>::by<WaapComponent>();
    auto proxy_ip = env->get<std::string>(HttpTransactionData::proxy_ip_ctx);
    for (auto& trustedType : trustedTypes)
    {
        switch (trustedType)
        {
        case Waap::TrustedSources::TrustedSourceType::SOURCE_IP:
            dbgTrace(D_WAAP) << "check source: " << getRemoteAddr();
            return policy->isSourceTrusted(getRemoteAddr(), trustedType);
        case Waap::TrustedSources::TrustedSourceType::X_FORWARDED_FOR:
            if (proxy_ip.ok())
            {
                return policy->isSourceTrusted(proxy_ip.unpack(), trustedType);
            } else {
                return false;
            }
        case Waap::TrustedSources::TrustedSourceType::COOKIE_OAUTH2_PROXY:
            if (cookieVal.empty())
            {
                cookieVal = getHdrContent("Cookie");
            }
            return policy->isSourceTrusted(Waap::Util::extractKeyValueFromCookie(cookieVal, "_oauth2_proxy"),
                trustedType);
        default:
            dbgWarning(D_WAAP) << "unrecognized trusted source identifier type: " << trustedType;
            break;
        }
    }
    return false;
}

std::string Waf2Transaction::getUserReputationStr(double relativeReputation) const
{
    if (isTrustedSource()) {
        return "Trusted";
    }
    if (relativeReputation < LOW_REPUTATION_THRESHOLD)
    {
        return "Low";
    }
    if (relativeReputation < NORMAL_REPUTATION_THRESHOLD)
    {
        return "Normal";
    }
    return "High";
}

const std::string Waf2Transaction::logHeadersStr() const
{
    std::vector<std::string> hdrsLog;

    for (auto hdr : hdrs_map)
    {
        std::string hdrName = hdr.first;
        std::string hdrValue = hdr.second.substr(0, LOG_HEADER_MAX_LENGTH);
        hdrsLog.push_back(hdrName + ": " + hdrValue);
    }

    return Waap::Util::vecToString(hdrsLog, ';').substr(0, MAX_LOG_FIELD_SIZE);
}


const WaapDecision&
Waf2Transaction::getWaapDecision() const
{
    return m_waapDecision;
}
std::shared_ptr<WaapAssetState> Waf2Transaction::getAssetState()
{
    return m_pWaapAssetState;
}
const std::string& Waf2Transaction::getRemoteAddr() const
{
    return m_remote_addr;
}
const std::string& Waf2Transaction::getSourceIdentifier() const
{
    return m_source_identifier;
}
const std::string Waf2Transaction::getUri() const
{
    return m_uriPath;
}
const std::string Waf2Transaction::getUriStr() const
{
    return normalize_uri(m_uriStr);
}
bool Waf2Transaction::isSuspicious() const
{
    return !!m_scanResult;
}
uint64_t Waf2Transaction::getIndex() const
{
    return m_index;
}
void Waf2Transaction::setIndex(uint64_t index)
{
    m_index = index;
}
const std::string Waf2Transaction::getUserAgent() const
{
    return m_userAgentStr;
}
const std::string Waf2Transaction::getParam() const
{
    if (m_scanResult == NULL)
    {
        return "";
    }
    return m_scanResult->param_name;
}
const std::string Waf2Transaction::getParamKey() const
{
    if (m_scanResult == NULL)
    {
        return "";
    }
    return IndicatorsFiltersManager::generateKey(m_scanResult->location, m_scanResult->param_name, this);
}
const std::vector<std::string> Waf2Transaction::getKeywordMatches() const
{
    if (m_scanResult == NULL)
    {
        return std::vector<std::string>();
    }
    return m_scanResult->keyword_matches;
}
const std::vector<std::string> Waf2Transaction::getFilteredKeywords() const
{
    if (m_scanResult == NULL)
    {
        return std::vector<std::string>();
    }
    return m_scanResult->filtered_keywords;
}
const std::map<std::string, std::vector<std::string>> Waf2Transaction::getFilteredVerbose() const
{
    if (m_pWaapAssetState == NULL)
    {
        return std::map<std::string, std::vector<std::string>>();
    }
    return m_pWaapAssetState->getFilterVerbose();
}
const std::vector<std::string> Waf2Transaction::getKeywordsCombinations() const
{
    if (m_scanResult)
    {
        return m_scanResult->keywordCombinations;
    }
    return std::vector<std::string>();
}
const std::vector<std::string> Waf2Transaction::getKeywordsAfterFilter() const
{
    if (m_scanResult)
    {
        return m_scanResult->keywordsAfterFilter;
    }
    return std::vector<std::string>();
}

const std::vector<DeepParser::KeywordInfo>& Waf2Transaction::getKeywordInfo() const
{
    return m_deepParser.m_keywordInfo;
}
const std::vector<std::pair<std::string, std::string> >& Waf2Transaction::getKvPairs() const
{
    return m_deepParser.kv_pairs;
}
const std::string Waf2Transaction::getSample() const
{
    if (m_scanResult)
    {
        return m_scanResult->unescaped_line;
    }
    return std::string();
}
const std::string Waf2Transaction::getLastScanSample() const
{
    return m_scanner.getLastScanResult().unescaped_line;
}
const std::string& Waf2Transaction::getLastScanParamName() const
{
    return m_scanner.getLastScanResult().param_name;
}
const std::string Waf2Transaction::getKeywordMatchesStr() const
{
    std::vector<std::string> vec = getKeywordMatches();
    return Waap::Util::vecToString(vec);
}
const std::string Waf2Transaction::getFilteredKeywordsStr() const
{
    std::vector<std::string> vec = getFilteredKeywords();
    return Waap::Util::vecToString(vec);
}
double Waf2Transaction::getScore() const
{
    if (m_scanResult) {
        return m_scanResult->score;
    }
    return 0;
}
// LCOV_EXCL_START Reason: model testing
double Waf2Transaction::getOtherModelScore() const
{
    if (m_scanResult) {
        return m_scanResult->other_model_score;
    }
    return 0;
}
// LCOV_EXCL_STOP
const std::vector<double> Waf2Transaction::getScoreArray() const
{
    if (m_scanResult) {
        return m_scanResult->scoreArray;
    }
    return std::vector<double>();
}
const std::string Waf2Transaction::getContentTypeStr() const
{
    return m_contentTypeStr;
}
Waap::Util::ContentType Waf2Transaction::getContentType() const
{
    return m_contentType;
}
int Waf2Transaction::getRemotePort() const
{
    return m_remote_port;
}
const std::string Waf2Transaction::getLocalAddress() const
{
    return m_local_addr;
}
int Waf2Transaction::getLocalPort() const
{
    return m_local_port;
}
const std::string Waf2Transaction::getLogTime() const
{
    return m_log_time;
}
ParserBase* Waf2Transaction::getRequestBodyParser()
{
    return m_requestBodyParser;
}


const std::string Waf2Transaction::getMethod() const
{
    return m_methodStr;
}
const std::string Waf2Transaction::getHost() const
{
    return m_hostStr;
}
const std::string Waf2Transaction::getCookie() const
{
    return m_cookieStr;
}
const std::vector<std::string> Waf2Transaction::getNotes() const
{
    return m_notes;
}
DeepParser& Waf2Transaction::getDeepParser()
{
    return m_deepParser;
}
std::vector<std::pair<std::string, std::string> > Waf2Transaction::getHdrPairs() const
{
    std::vector<std::pair<std::string, std::string> > res;
    for (auto hdr_pair : hdrs_map) {
        res.push_back(std::pair<std::string, std::string>(hdr_pair.first, hdr_pair.second));
    }
    return res;
}
const std::string Waf2Transaction::getHdrContent(std::string hdrName) const
{
    boost::algorithm::to_lower(hdrName);
    auto hdr_it = hdrs_map.find(hdrName);
    if (hdr_it != hdrs_map.end()) {
        return hdr_it->second;
    }
    return "";
}
const std::string Waf2Transaction::getRequestBody() const
{
    return m_request_body;
}
const std::string Waf2Transaction::getTransactionIdStr() const
{
    return boost::uuids::to_string(m_transaction_id);
}
const std::string Waf2Transaction::getLocation() const
{
    if (m_scanResult) {
        return m_scanResult->location;
    }
    return std::string();
}
Waap::CSRF::State& Waf2Transaction::getCsrfState()
{
    return m_csrfState;
}

void Waf2Transaction::sendAutonomousSecurityLog(
    const LogTriggerConf& triggerLog,
    bool shouldBlock,
    const std::string& logOverride,
    const std::string& attackTypes,
    bool skipSecurityAction) const
{
    auto autonomousSecurityDecision = std::dynamic_pointer_cast<AutonomousSecurityDecision>(
        m_waapDecision.getDecision(AUTONOMOUS_SECURITY_DECISION));
    ReportIS::Severity severity = Waap::Util::computeSeverityFromThreatLevel(
        autonomousSecurityDecision->getThreatLevel());
    if (autonomousSecurityDecision->shouldForceLog() && logOverride == OVERRIDE_DROP)
    {
        severity = ReportIS::Severity::MEDIUM;
    }
    else if (autonomousSecurityDecision->shouldForceLog() && logOverride == OVERRIDE_ACCEPT)
    {
        severity = ReportIS::Severity::INFO;
    }

    const ReportIS::Priority priority =
        Waap::Util::computePriorityFromThreatLevel(autonomousSecurityDecision->getThreatLevel());

    auto maybeLogTriggerConf = getConfigurationWithCache<LogTriggerConf>("rulebase", "log");
    LogGenWrapper logGenWrapper(
                            maybeLogTriggerConf,
                            "Web Request",
                            ReportIS::Audience::SECURITY,
                            LogTriggerConf::SecurityType::ThreatPrevention,
                            severity,
                            priority,
                            shouldBlock);

    LogGen& waap_log = logGenWrapper.getLogGen();
    ThreatLevel threat_level = autonomousSecurityDecision->getThreatLevel();
    if (threat_level != ThreatLevel::NO_THREAT) {
        std::string confidence = Waap::Util::computeConfidenceFromThreatLevel(threat_level);
        waap_log << LogField("eventConfidence", confidence);
    }

    appendCommonLogFields(
        waap_log,
        triggerLog,
        shouldBlock,
        logOverride,
        attackTypes,
        AUTONOMOUS_SECURITY_DECISION,
        !skipSecurityAction);

    std::string sampleString = getSample();
    if (sampleString.length() > MAX_LOG_FIELD_SIZE) {
        sampleString.resize(MAX_LOG_FIELD_SIZE);
    }
    waap_log << LogField("matchedSample", sampleString, LogFieldOption::XORANDB64);
    std::string location = getLocation();
    if (location == "url_param")
    {
        location = "url parameter";
    }
    else if (location == "referer_param")
    {
        location = "referer parameter";
    }
    waap_log << LogField("matchedLocation", location);
    waap_log << LogField("matchedParameter", getParam());

    // Patch for reporting of log4j under different name (currently only in logs)
    std::vector<std::string> keywordMatches = getKeywordMatches();
    std::replace(keywordMatches.begin(), keywordMatches.end(), std::string("jndi:"), std::string("java_1"));
    std::string keywordMatchesStr = Waap::Util::vecToString(keywordMatches);

    waap_log << LogField("waapFoundIndicators", keywordMatchesStr, LogFieldOption::XORANDB64);
    waap_log << LogField("matchedIndicators", keywordMatchesStr, LogFieldOption::XORANDB64);
    waap_log << LogField("learnedIndicators", getFilteredKeywordsStr(), LogFieldOption::XORANDB64);
    waap_log << LogField("waapUserReputationScore", (int)(
        autonomousSecurityDecision->getRelativeReputation() * 100));
    waap_log << LogField("waapUserReputation", getUserReputationStr(
        autonomousSecurityDecision->getRelativeReputation()));
    waap_log << LogField("waapUriFalsePositiveScore", (int)(
        autonomousSecurityDecision->getFpMitigationScore() * 100));
    waap_log << LogField("waapKeywordsScore", (int)(getScore() * 100));
    waap_log << LogField("reservedNgenA", (int)(getOtherModelScore() * 100));
    waap_log << LogField("waapFinalScore", (int)(autonomousSecurityDecision->getFinalScore() * 100));
    waap_log << LogField("waapCalculatedThreatLevel", autonomousSecurityDecision->getThreatLevel());
}

void Waf2Transaction::createUserLimitsState()
{
    if (!m_siteConfig || m_userLimitsState ||
        (WaapConfigBase::get_WebAttackMitigationMode(*m_siteConfig) == AttackMitigationMode::DISABLED)) {
        return;
    }

    auto userLimitsPolicy = m_siteConfig->get_UserLimitsPolicy();
    if (userLimitsPolicy) {
        m_userLimitsState = std::make_shared<Waap::UserLimits::State>(*userLimitsPolicy);
        m_userLimitsState->setAssetId(m_siteConfig->get_AssetId());
        m_deepParser.setGlobalMaxObjectDepth(userLimitsPolicy->getMaxObjectDepth());
        if (m_uriPath.empty()) {
            // Initialize uriPath so it will be available in the sent log,
            // in case a limit is reached early in the flow
            m_uriPath = m_uriStr.substr(0, LOG_HEADER_MAX_LENGTH);
        }
        dbgTrace(D_WAAP_ULIMITS) << "[USER LIMITS] state created with '" <<
            WaapConfigBase::get_WebAttackMitigationModeStr(*m_siteConfig) << "' mode\n" <<
            *userLimitsPolicy;
    }
    else {
        dbgTrace(D_WAAP_ULIMITS) << "[USER LIMITS] couldn't load policy";
    }
}

ServiceVerdict
Waf2Transaction::getUserLimitVerdict()
{
    if (!isUserLimitReached()) {
        // Either limit not reached or attack mitigation mode is DISABLED
        return ServiceVerdict::TRAFFIC_VERDICT_INSPECT;
    }

    std::string msg;
    msg = "[USER LIMITS][" +
        std::string(WaapConfigBase::get_WebAttackMitigationModeStr(*m_siteConfig)) +
        " mode] " + "Verdict is ";
    std::string reason;
    reason = "  reason: " + getViolatedUserLimitTypeStr();

    ServiceVerdict verdict = ServiceVerdict::TRAFFIC_VERDICT_INSPECT;
    const AttackMitigationMode mode = WaapConfigBase::get_WebAttackMitigationMode(*m_siteConfig);
    auto decision = m_waapDecision.getDecision(USER_LIMITS_DECISION);
    if (mode == AttackMitigationMode::LEARNING) {
        decision->setLog(true);
        if (!m_overrideStateByPractice[AUTONOMOUS_SECURITY_DECISION].bForceBlock) {
            // detect mode and no active drop exception
            decision->setBlock(false);
            if (isIllegalMethodViolation()) {
                dbgDebug(D_WAAP_ULIMITS) << msg << "INSPECT" << reason << " in detect mode";
                verdict = ServiceVerdict::TRAFFIC_VERDICT_INSPECT;
            }
            else {
                dbgDebug(D_WAAP_ULIMITS) << msg << "PASS" << reason;
                verdict = ServiceVerdict::TRAFFIC_VERDICT_ACCEPT;
            }
        } else {
            // detect mode and active drop exception
            decision->setBlock(true);
            decision->setForceBlock(true);
            dbgDebug(D_WAAP_ULIMITS) << msg << "Override Block" << reason;
            verdict = ServiceVerdict::TRAFFIC_VERDICT_DROP;
        }
    }
    else if (mode == AttackMitigationMode::PREVENT) {
        decision->setLog(true);
        if (!m_overrideStateByPractice[AUTONOMOUS_SECURITY_DECISION].bForceException) {
            // prevent mode and no active accept exception
            decision->setBlock(true);
            dbgDebug(D_WAAP_ULIMITS) << msg << "BLOCK" << reason;
            verdict = ServiceVerdict::TRAFFIC_VERDICT_DROP;
        } else {
            // prevent mode and active accept exception
            decision->setBlock(false);
            decision->setForceAllow(true);
            dbgDebug(D_WAAP_ULIMITS) << msg << "Override Accept" << reason;
            verdict = ServiceVerdict::TRAFFIC_VERDICT_ACCEPT;
        }
    }

    return verdict;
}

const std::string Waf2Transaction::getUserLimitVerdictStr() const
{
    std::stringstream verdict;
    if (!isUserLimitReached()) {
        verdict << getViolatedUserLimitTypeStr();
    }
    else if (isIllegalMethodViolation()) {
        verdict << getViolatedUserLimitTypeStr() << " (" << getMethod() << ")";
    }
    else {
        auto strData = getViolatedUserLimitStrData();
        verdict << strData.type << " (" << getViolatingUserLimitSize() <<
            "/" << strData.policy << ")";
    }
    return verdict.str();
}

bool Waf2Transaction::isUrlLimitReached(size_t size)
{
    if (!m_userLimitsState) {
        return false;
    }
    return m_userLimitsState->addUrlBytes(size);
}
bool Waf2Transaction::isHttpHeaderLimitReached(const std::string& name, const std::string& value)
{
    if (!m_userLimitsState) {
        return false;
    }
    return m_userLimitsState->addHeaderBytes(name, value);
}
bool Waf2Transaction::isHttpBodyLimitReached(size_t chunkSize)
{
    if (!m_userLimitsState) {
        return false;
    }
    return m_userLimitsState->addBodyBytes(chunkSize);
}
bool Waf2Transaction::isObjectDepthLimitReached(size_t depth)
{
    if (!m_userLimitsState) {
        return false;
    }
    return m_userLimitsState->setObjectDepth(depth);
}
bool Waf2Transaction::isPreventModeValidMethod(const std::string& method)
{
    if (!m_userLimitsState) {
        return true;
    }

    if (m_userLimitsState->isValidHttpMethod(method) ||
        (WaapConfigBase::get_WebAttackMitigationMode(*m_siteConfig) == AttackMitigationMode::LEARNING)) {
        return true;
    }
    return false;
}
bool Waf2Transaction::isUserLimitReached() const
{
    return m_userLimitsState ? m_userLimitsState->isLimitReached() : false;
}
bool Waf2Transaction::isIllegalMethodViolation() const
{
    return m_userLimitsState ? m_userLimitsState->isIllegalMethodViolation() : false;
}
const std::string Waf2Transaction::getViolatedUserLimitTypeStr() const
{
    return m_userLimitsState ? m_userLimitsState->getViolatedTypeStr() : "no enforcement";
}
const Waap::UserLimits::ViolatedStrData&
Waf2Transaction::getViolatedUserLimitStrData() const
{
    return m_userLimitsState->getViolatedStrData();
}
size_t Waf2Transaction::getViolatingUserLimitSize() const
{
    return m_userLimitsState ? m_userLimitsState->getViolatingSize() : 0;
}

const std::set<std::string> Waf2Transaction::getFoundPatterns() const
{
    return m_found_patterns;
}

bool Waf2Transaction::checkIsHeaderOverrideScanRequired()
{
    return m_isHeaderOverrideScanRequired;
}

const std::string Waf2Transaction::getCurrentWebUserResponse() {
    dbgFlow(D_WAAP);
    // INXT-53598: m_siteConfig is NULL during the post-restart pre-policy-load window; fail safe.
    if (!m_siteConfig) {
        dbgTrace(D_WAAP) << "No site config, can't set web user response";
        return "";
    }
    m_waapDecision.orderDecisions();
    DecisionType practiceType = m_waapDecision.getHighestPriorityDecisionToLog();

    dbgTrace(D_WAAP) << "set current web user response for practice: " << practiceType;

    const std::shared_ptr<Waap::Trigger::Policy> triggerPolicy = m_siteConfig->get_TriggerPolicy();
    if (!triggerPolicy) {
        dbgTrace(D_WAAP) << "No trigger policy, can't set web user response for practice: " << practiceType;
        return "";
    }
    auto responses = triggerPolicy->responseByPractice.getResponseByPractice(practiceType);
    if (responses.empty()) {
        dbgTrace(D_WAAP) << "No web user response for practice: " << practiceType;
        return "";
    }
    dbgTrace(D_WAAP) << "Found web user response trigger by practice, ID: " << responses[0];
    return responses[0];
}

const std::vector<std::pair<std::string, std::string>>&
Waf2Transaction::getLowercasedHdrPairs() const
{
    if (m_lowercased_hdr_pairs_cached) return m_lowercased_hdr_pairs;
    const auto &hdrs = getHdrPairs();
    m_lowercased_hdr_pairs.reserve(hdrs.size());
    for (const auto &hp : hdrs) {
        std::string n = hp.first;
        std::transform(n.begin(), n.end(), n.begin(), ::tolower);
        std::string v = hp.second;
        std::transform(v.begin(), v.end(), v.begin(), ::tolower);
        m_lowercased_hdr_pairs.emplace_back(std::move(n), std::move(v));
    }
    m_lowercased_hdr_pairs_cached = true;
    return m_lowercased_hdr_pairs;
}

const std::vector<std::pair<std::string, std::string>>&
Waf2Transaction::getKeywordInfoPairs() const
{
    if (m_keyword_info_pairs_cached) return m_keyword_info_pairs;
    const auto &keywords = getKeywordInfo();
    m_keyword_info_pairs.reserve(keywords.size());
    for (const DeepParser::KeywordInfo &k : keywords) {
        m_keyword_info_pairs.emplace_back(k.getName(), k.getValue());
    }
    m_keyword_info_pairs_cached = true;
    return m_keyword_info_pairs;
}

std::unordered_map<std::string, std::set<std::string>>
Waf2Transaction::getExceptionsDict(DecisionType practiceType) {
    std::unordered_map<std::string, std::set<std::string>> exceptions_dict;
    exceptions_dict["url"].insert(m_uriPath);
    exceptions_dict["sourceIP"].insert(m_remote_addr);
    exceptions_dict["method"].insert(m_methodStr);

    extractEnvSourceIdentifier();
    exceptions_dict["sourceIdentifier"].insert(m_source_identifier);
    if (practiceType == DecisionType::AUTONOMOUS_SECURITY_DECISION) {
        exceptions_dict["hostName"].insert(m_hostStr);
        for (const std::string& keywordStr : getKeywordMatches()) {
            exceptions_dict["indicator"].insert(keywordStr);
            exceptions_dict["keyword"].insert(keywordStr);
        }
        exceptions_dict["paramLocation"].insert(getLocation());
    }
    // Note: paramName, paramValue, headerName, headerValue are intentionally NOT added here.
    // They are evaluated through per-pair correlated matching in getBehaviors() to prevent
    // cross-matching across different parameters or headers (INXT-52398).
    return exceptions_dict;
}

const ParameterException &
Waf2Transaction::getCachedParameterException(const std::string &id)
{
    auto it = m_paramExceptionCache.find(id);
    if (it != m_paramExceptionCache.end()) return it->second;
    I_GenericRulebase *i_rulebase = Singleton::Consume<I_GenericRulebase>::by<Waf2Transaction>();
    auto result = m_paramExceptionCache.emplace(id, i_rulebase->getParameterException(id));
    return result.first->second;
}

static void
insertIfNotEmpty(
    std::unordered_map<std::string, std::set<std::string>> &dict,
    const std::string &key,
    const std::string &value)
{
    if (value.empty()) return;
    dict[key].insert(value);
}

std::set<ParameterBehavior>
Waf2Transaction::getBehaviors(
    const std::unordered_map<std::string, std::set<std::string>> &exceptions_dict,
    const std::vector<std::string>& exceptions,
    DecisionType practiceType,
    bool checkResponse)
{
    std::set<ParameterBehavior> all_params;

    bool doParamPairMatching = (
        practiceType == DecisionType::AUTONOMOUS_SECURITY_DECISION);

    bool doHeaderPairMatching = (
        practiceType == DecisionType::AUTONOMOUS_SECURITY_DECISION &&
        checkIsHeaderOverrideScanRequired());

    static const std::vector<std::pair<std::string, std::string>> empty_pairs;
    const auto &header_pairs_lower = doHeaderPairMatching
        ? getLowercasedHdrPairs() : empty_pairs;
    const auto &param_pairs        = doParamPairMatching
        ? getKeywordInfoPairs()    : empty_pairs;
    std::unordered_map<std::string, std::set<std::string>> base_dict = exceptions_dict;
    if (checkResponse && !getResponseBody().empty()) {
        base_dict["responseBody"].insert(getResponseBody());
    }
    std::unordered_map<std::string, std::set<std::string>> non_kv_dict = base_dict;
    for (const auto &p : header_pairs_lower) {
        non_kv_dict["headerName"].insert(p.first);
        non_kv_dict["headerValue"].insert(p.second);
    }
    for (const auto &p : param_pairs) {
        non_kv_dict["paramName"].insert(p.first);
        non_kv_dict["paramValue"].insert(p.second);
    }
    if (doParamPairMatching) {
        insertIfNotEmpty(non_kv_dict, "paramName", getParamKey());
        insertIfNotEmpty(non_kv_dict, "paramName", getParam());
        insertIfNotEmpty(non_kv_dict, "paramValue", getSample());
    }

    std::unordered_set<std::string> request_keys;
    for (const auto &kv : non_kv_dict) request_keys.insert(kv.first);

    for (const auto &id : exceptions) {
        dbgTrace(D_WAAP_OVERRIDE) << "get parameter exception for: " << id;

        const auto &paramException = getCachedParameterException(id);

        const auto &ekeys = paramException.getAllReferencedKeys();

        if (checkResponse && ekeys.count("responseBody")) {
            bool has_other_keys = false;
            for (const auto &k : ekeys) {
                if (k != "responseBody") { has_other_keys = true; break; }
            }
            bool can_still_match = !has_other_keys
                || paramException.isContainingKVPair()
                || !paramException.getBehavior(non_kv_dict, true).empty();
            if (can_still_match) {
                dbgTrace(D_WAAP_OVERRIDE) << "arming response inspection for exception: " << id;
                m_responseInspectReasons.setApplyOverride(true);
            } else {
                dbgTrace(D_WAAP_OVERRIDE) << "not arming response inspection, exception cannot match: " << id;
            }
        }

        if (!ekeys.empty()) {
            bool any_relevant = false;
            for (const auto &k : ekeys) {
                if (request_keys.count(k)) { any_relevant = true; break; }
            }
            if (!any_relevant) {
                dbgTrace(D_WAAP_OVERRIDE) << "skip exception " << id << ": no relevant keys in request";
                continue;
            }
        }

        bool exceptionHasKVPair = paramException.isContainingKVPair();

        if (exceptionHasKVPair) {
            auto params = paramException.getBehaviorForNonKVPairs(non_kv_dict);
            if (!params.empty()) all_params.insert(params.begin(), params.end());
        } else {
            auto params = paramException.getBehavior(non_kv_dict);
            if (!params.empty()) all_params.insert(params.begin(), params.end());
        }

        if (exceptionHasKVPair && (doHeaderPairMatching || doParamPairMatching)) {
            auto kvParams = paramException.getBehaviorForKVPairs(
                base_dict, header_pairs_lower, param_pairs);
            if (!kvParams.empty()) all_params.insert(kvParams.begin(), kvParams.end());
        }
    }
    return all_params;
}


bool Waf2Transaction::shouldEnforceByPracticeExceptions(DecisionType practiceType)
{
    dbgFlow(D_WAAP);
    auto decision = m_waapDecision.getDecision(practiceType);
    bool shouldEnforce = false;
    std::shared_ptr<Waap::Override::Policy> overridePolicy = m_siteConfig->get_OverridePolicy();

    if (overridePolicy) {
        auto exceptions = overridePolicy->getExceptionsByPractice().getExceptionsOfPractice(practiceType);

        if (!exceptions.empty()) {
            dbgTrace(D_WAAP_OVERRIDE) << "get behaviors for practice: " << practiceType;

            auto behaviors = getBehaviors(getExceptionsDict(practiceType), exceptions, practiceType);
            if (behaviors.size() > 0)
            {
                auto it = m_overrideStateByPractice.find(practiceType);
                if (it == m_overrideStateByPractice.end()) {
                    dbgDebug(D_WAAP_OVERRIDE) << "no override state for practice: " << practiceType;
                    return false;
                }
                setOverrideState(behaviors, it->second);
                if (it->second.bForceBlock) {
                    dbgTrace(D_WAAP_OVERRIDE)
                    << "should block by exceptions for practice: " << practiceType;
                    decision->setBlock(true);
                    decision->setForceBlock(true);
                    shouldEnforce = true;
                }
                if (it->second.bForceException) {
                    dbgTrace(D_WAAP_OVERRIDE)
                    << "should not block by exceptions for practice: " << practiceType;
                    decision->setBlock(false);
                    decision->setForceAllow(true);
                    shouldEnforce = true;
                }
            }
        }
    }

    if (shouldEnforce) {
        decision->setLog(true);
        if(!m_overrideStateByPractice[practiceType].bSupressLog) {
            decision->setForceLog(true);
        }
        std::shared_ptr<AutonomousSecurityDecision> autonomousDecision =
            std::dynamic_pointer_cast<AutonomousSecurityDecision>(
                m_waapDecision.getDecision(AUTONOMOUS_SECURITY_DECISION)
            );
        if (autonomousDecision->getThreatLevel() <= ThreatLevel::THREAT_INFO) {
            autonomousDecision->setLog(false);
        }
    } else if(!m_matchedOverrideIds.empty() && !m_overrideStateByPractice[practiceType].bSupressLog) {
        decision->setForceLog(true);
    }
    return shouldEnforce;
}

void Waf2Transaction::setOverrideState(const std::set<ParameterBehavior>& behaviors, Waap::Override::State& state) {
    dbgFlow(D_WAAP) << "setOverrideState(): from exceptions per practice";
    for (auto const &behavior : behaviors) {
        m_matchedOverrideIds.insert(behavior.getId());
        if (behavior.getKey() == BehaviorKey::ACTION) {
            if (behavior.getValue() == BehaviorValue::ACCEPT) {
                dbgTrace(D_WAAP_OVERRIDE) << "setting bForceException due to override behavior: " << behavior.getId();
                state.bForceException = true;
                state.forceExceptionIds.insert(behavior.getId());
            } else if (behavior.getValue() == BehaviorValue::REJECT) {
                dbgTrace(D_WAAP_OVERRIDE) << "setting bForceBlock due to override behavior: " << behavior.getId();
                state.bForceBlock = true;
                state.forceBlockIds.insert(behavior.getId());
            } else {
                dbgTrace(D_WAAP_OVERRIDE) << "override behavior matched with no effect on state here: "
                    << behavior.getId();
            }
        } else if(behavior.getKey() == BehaviorKey::LOG && behavior.getValue() == BehaviorValue::IGNORE) {
            dbgTrace(D_WAAP_OVERRIDE) << "setting bSupressLog due to override behavior: " << behavior.getId();
            state.bSupressLog = true;
        }
    }
}

Waap::Override::State Waf2Transaction::getOverrideState(IWaapConfig* sitePolicy)
{
    Waap::Override::State overrideState;


    std::shared_ptr<Waap::Override::Policy> overridePolicy = sitePolicy->get_OverridePolicy();
    if (overridePolicy) { // at first we will run request overrides (in order to set the source)
        auto exceptions = overridePolicy->getExceptionsByPractice().
            getExceptionsOfPractice(AUTONOMOUS_SECURITY_DECISION);
        if (!exceptions.empty()) {
            dbgTrace(D_WAAP_OVERRIDE) << "get behaviors for override state";
            m_responseInspectReasons.setApplyOverride(false);
            auto behaviors = getBehaviors(
                getExceptionsDict(AUTONOMOUS_SECURITY_DECISION),
                exceptions,
                AUTONOMOUS_SECURITY_DECISION,
                true);
            if (behaviors.size() > 0) {
                dbgTrace(D_WAAP_OVERRIDE) << "set override state by practice found behaviors";
                setOverrideState(behaviors, m_overrideStateByPractice[AUTONOMOUS_SECURITY_DECISION]);
            }
            m_isHeaderOverrideScanRequired = false;
            return m_overrideStateByPractice[AUTONOMOUS_SECURITY_DECISION];
        }
        m_responseInspectReasons.setApplyOverride(overridePolicy->isOverrideResponse());
        overrideState.applyOverride(*overridePolicy, WaapOverrideFunctor(*this), m_matchedOverrideIds, true);
    }

    if (overridePolicy) { // later we will run response overrides
        m_overrideStateByPractice[AUTONOMOUS_SECURITY_DECISION].applyOverride(
            *overridePolicy, WaapOverrideFunctor(*this), m_matchedOverrideIds, false
        );
    }
    m_isHeaderOverrideScanRequired = false;
    return m_overrideStateByPractice[AUTONOMOUS_SECURITY_DECISION];
}

Waf2TransactionFlags &Waf2Transaction::getTransactionFlags()
{
    return m_waf2TransactionFlags;
}

const Maybe<LogTriggerConf, Config::Errors> Waf2Transaction::getTriggerLog(const std::shared_ptr<
    Waap::Trigger::Policy> &triggerPolicy, DecisionType practiceType) const
{
    dbgTrace(D_WAAP) << "Getting log trigger for practice type:" << practiceType;
    std::set<std::string> triggers_set;
    auto triggers = triggerPolicy->triggersByPractice.getTriggersByPractice(practiceType);
    if (!triggers.empty()) {
        for (const auto &id : triggers) {
            triggers_set.insert(id);
            dbgTrace(D_WAAP) << "Add log trigger by practice to triggers set:" << id;
        }
    } else {
        for (const Waap::Trigger::Trigger &trigger : triggerPolicy->triggers) {
            triggers_set.insert(trigger.triggerId);
            dbgTrace(D_WAAP) << "Add log trigger waap to triggers set:" << trigger.triggerId;
        }
    }

    ScopedContext ctx;
    ctx.registerValue<std::set<GenericConfigId>>(TriggerMatcher::ctx_key, triggers_set);
    auto trigger_config = getConfigurationWithCache<LogTriggerConf>("rulebase", "log");

    if (!trigger_config.ok()) {
        dbgDebug(D_WAAP) << "Failed to get log trigger configuration, err: " << trigger_config.getErr();
    }
    return trigger_config;
}

bool Waf2Transaction::isTriggerReportExists(const std::shared_ptr<
    Waap::Trigger::Policy> &triggerPolicy)
{
    if (!triggerPolicy) {
        return false;
    }
    if (m_triggerReport) {
        return m_triggerReport;
    }
    std::set<std::string> triggers_set;
    auto triggers = triggerPolicy->triggersByPractice.getAllTriggers();
    if (!triggers.empty()) {
        for (const auto &id : triggers) {
            triggers_set.insert(id);
        }
    }
    else {
        for (const Waap::Trigger::Trigger &trigger : triggerPolicy->triggers) {
            triggers_set.insert(trigger.triggerId);
        }
    }

    ScopedContext ctx;
    ctx.registerValue<std::set<GenericConfigId>>(TriggerMatcher::ctx_key, triggers_set);
    auto trigger_config = getConfigurationWithCache<ReportTriggerConf>("rulebase", "report");
    if (!trigger_config.ok()) {
        dbgDebug(D_WAAP) << "Failed to get report trigger configuration, err: " << trigger_config.getErr();
        m_triggerReport = false;
        return false;
    }
    auto triggerName = trigger_config.unpack().getName();
    dbgTrace(D_WAAP) << "Got report trigger from rulbase: " << triggerName << ", m_triggerReport = true";
    m_triggerReport = true;
    return true;
}

ReportIS::Severity Waf2Transaction::computeEventSeverityFromDecision() const
{
    DecisionType type = m_waapDecision.getHighestPriorityDecisionToLog();
    switch (type)
    {
        case DecisionType::USER_LIMITS_DECISION:
        {
            return ReportIS::Severity::HIGH;
            break;
        }
        case DecisionType::OPEN_REDIRECT_DECISION:
        case DecisionType::ERROR_LIMITING_DECISION:
        case DecisionType::RATE_LIMITING_DECISION:
        case DecisionType::CSRF_DECISION:
        case DecisionType::ERROR_DISCLOSURE_DECISION:
        {
            return ReportIS::Severity::CRITICAL;
            break;
        }
        case DecisionType::AUTONOMOUS_SECURITY_DECISION:
        {
            auto autonomousSecurityDecision = std::dynamic_pointer_cast<AutonomousSecurityDecision>(
                m_waapDecision.getDecision(DecisionType::AUTONOMOUS_SECURITY_DECISION));
            return Waap::Util::computeSeverityFromThreatLevel(autonomousSecurityDecision->getThreatLevel());
        }
        default:
            static_assert(true, "Illegal DecisionType enum value");
            break;
    }

    return ReportIS::Severity::INFO;
}

