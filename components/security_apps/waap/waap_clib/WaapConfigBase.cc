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

#include "WaapConfigBase.h"
#include <boost/algorithm/string/case_conv.hpp>
#include "WaapConfigApplication.h"
#include "WaapOverride.h"
#include "WaapTrigger.h"
#include "WaapOpenRedirectPolicy.h"
#include "CsrfPolicy.h"
#include "WaapErrorDisclosurePolicy.h"
#include "TrustedSources.h"
#include "Waf2Util.h"

USE_DEBUG_FLAG(D_WAAP_ULIMITS);
USE_DEBUG_FLAG(D_WAAP);
USE_DEBUG_FLAG(D_OA_SCHEMA_UPDATER);

using boost::algorithm::to_lower_copy;
using namespace std;

WaapConfigBase::WaapConfigBase()
        :
    m_assetId(""),
    m_autonomousSecurityLevel(""),
    m_autonomousSecurity(false),
    m_assetName(""),
    m_practiceId(""),
    m_practiceName(""),
    m_ruleId(""),
    m_ruleName(""),
    m_overridePolicy(nullptr),
    m_triggerPolicy(nullptr),
    m_trustedSourcesPolicy(nullptr),
    m_waapParameters(nullptr),
    m_openRedirectPolicy(nullptr),
    m_errorDisclosurePolicy(nullptr),
    m_csrfPolicy(nullptr),
    m_rateLimitingPolicy(nullptr),
    m_errorLimitingPolicy(nullptr),
    m_errorLimiting(nullptr),
    m_userLimitsPolicy(nullptr),
    m_securityHeadersPolicy(nullptr)
{
    m_blockingLevel = BlockingLevel::NO_BLOCKING;
}

void WaapConfigBase::load(cereal::JSONInputArchive& ar)
{
    readJSONByCereal(ar);
    loadTriggersPolicy(ar);
    loadOverridePolicy(ar);
    loadTrustedSourcesPolicy(ar);
    loadWaapParametersPolicy(ar);
    loadUserLimitsPolicy(ar);
    loadRateLimitingPolicy(ar);
    loadErrorLimitingPolicy(ar);
}

void WaapConfigBase::readJSONByCereal(cereal::JSONInputArchive& ar)
{
    ar(
        cereal::make_nvp("webAttackMitigation", m_autonomousSecurity),
        cereal::make_nvp("webAttackMitigationAction", m_autonomousSecurityLevel),
        cereal::make_nvp("practiceId", m_practiceId),
        cereal::make_nvp("practiceName", m_practiceName),
        cereal::make_nvp("assetId", m_assetId),
        cereal::make_nvp("assetName", m_assetName),
        cereal::make_nvp("ruleId", m_ruleId),
        cereal::make_nvp("ruleName", m_ruleName)
    );

    try {
        std::string application_urls;
        ar(cereal::make_nvp("applicationUrls", application_urls));
        m_applicationUrls = split(application_urls, ';');
    } catch (std::runtime_error& e) {
        dbgWarning(D_WAAP) << "Error to load applicationUrls field in policy" << e.what();
        ar.setNextName(nullptr);
    }

    m_blockingLevel = blockingLevelBySensitivityStr(m_autonomousSecurityLevel);
}


void WaapConfigBase::loadCsrfPolicy(cereal::JSONInputArchive& ar)
{
    std::string failMessage = "Failed to load the CSRF policy of the current rule: " +
        m_ruleName + ": ";

    try {
        m_csrfPolicy = std::make_shared<Waap::Csrf::Policy>(ar);
    }
    catch (std::runtime_error& e) {
        ar.setNextName(nullptr);
        dbgWarning(D_WAAP) << failMessage << e.what();
        m_csrfPolicy = std::make_shared<Waap::Csrf::Policy>();
    }
}

void WaapConfigBase::loadSecurityHeadersPolicy(cereal::JSONInputArchive& ar)
{
    std::string failMessage = "Failed to load the Security Headers policy of the current rule: " +
        m_ruleName + ": ";

    try {
        m_securityHeadersPolicy = std::make_shared<Waap::SecurityHeaders::Policy>(ar);
    }
    catch (std::runtime_error& e) {
        ar.setNextName(nullptr);
        // Feature is currently not supported by the UI, thus changing debug level to debug.
        dbgDebug(D_WAAP) << failMessage << e.what();
        m_securityHeadersPolicy = nullptr;
    }
}

void WaapConfigBase::loadOverridePolicy(cereal::JSONInputArchive& ar)
{
    std::string failMessage = "Failed to load the WAAP Overrides of the current rule: " +
        m_ruleName + ": ";

    try {
        m_overridePolicy = std::make_shared<Waap::Override::Policy>(ar);
    }
    catch (std::runtime_error& e) {
        ar.setNextName(nullptr);
        dbgWarning(D_WAAP) << failMessage << e.what();
        m_overridePolicy = nullptr;
    }
}

void WaapConfigBase::loadTriggersPolicy(cereal::JSONInputArchive& ar)
{
    std::string failMessage = "Failed to load the WAAP Triggers of the current rule: " +
        m_ruleName + ": ";
    try {
        m_triggerPolicy = std::make_shared<Waap::Trigger::Policy>(ar);
    }
    catch (std::runtime_error& e) {
        ar.setNextName(nullptr);
        dbgWarning(D_WAAP) << failMessage << e.what();
        m_triggerPolicy = nullptr;
    }
}

void WaapConfigBase::loadTrustedSourcesPolicy(cereal::JSONInputArchive& ar)
{
    std::string failMessage = "Failed to load the WAAP Trusted sources of the current rule: " +
        m_ruleName + ": ";
    try {
        m_trustedSourcesPolicy = std::make_shared<Waap::TrustedSources::TrustedSourcesParameter>(ar);
    }
    catch (std::runtime_error & e) {
        ar.setNextName(nullptr);
        dbgWarning(D_WAAP) << failMessage << e.what();
        m_trustedSourcesPolicy = nullptr;
    }
}

void WaapConfigBase::loadWaapParametersPolicy(cereal::JSONInputArchive& ar)
{
    std::string failMessage = "Failed to load the WAAP Parameters of the current rule: " +
        m_ruleName + ": ";
    try {
        m_waapParameters = std::make_shared<Waap::Parameters::WaapParameters>(ar);
    }
    catch (std::runtime_error & e) {
        ar.setNextName(nullptr);
        dbgWarning(D_WAAP) << failMessage << e.what();
        m_waapParameters = nullptr;
    }
}

void WaapConfigBase::loadRateLimitingPolicy(cereal::JSONInputArchive& ar)
{
    std::string failMessage = "Failed to load the WAAP Rate Limiting of the current rule: " +
        m_ruleName + ": ";
    try {
        m_rateLimitingPolicy = std::make_shared<Waap::RateLimiting::Policy>(ar);
    }
    catch (std::runtime_error & e) {
        ar.setNextName(nullptr);
        // Feature is currently not supported by the UI, thus changing debug level to debug.
        dbgDebug(D_WAAP) << failMessage << e.what();
        m_rateLimitingPolicy = nullptr;
    }
}

void WaapConfigBase::loadErrorLimitingPolicy(cereal::JSONInputArchive& ar)
{
    std::string failMessage = "Failed to load the WAAP Error Limiting of the current rule: " +
        m_ruleName + ": ";

    try {

        m_errorLimiting = std::make_shared<Waap::ErrorLimiting::ErrorLimiter>(ar);
        std::shared_ptr<Waap::RateLimiting::Policy> policy;
        policy = std::make_shared<Waap::RateLimiting::Policy>();
        policy->rules.push_back(Waap::RateLimiting::Policy::Rule());
        policy->rules[0].rate.interval = m_errorLimiting->m_errorLimiterPolicy.interval;
        policy->rules[0].rate.events = m_errorLimiting->m_errorLimiterPolicy.events;
        policy->rules[0].uriFilter.groupBy = Waap::RateLimiting::Policy::Rule::UriFilter::GroupBy::GLOBAL;
        policy->rules[0].sourceFilter.groupBy = Waap::RateLimiting::Policy::Rule::SourceFilter::GroupBy::GLOBAL;
        policy->rules[0].uriFilter.scope = Waap::RateLimiting::Policy::Rule::UriFilter::Scope::ALL;
        policy->rules[0].sourceFilter.scope = Waap::RateLimiting::Policy::Rule::SourceFilter::Scope::ALL;
        policy->m_rateLimiting.enable = m_errorLimiting->getErrorLimitingEnforcementStatus();

        if (m_errorLimiting->m_errorLimiterPolicy.type == "quarantine") {
            policy->rules[0].action.type = Waap::RateLimiting::Policy::Rule::Action::Type::QUARANTINE;
            policy->rules[0].action.quarantineTimeSeconds = m_errorLimiting->m_errorLimiterPolicy.blockingTime;
        }
        else if (m_errorLimiting->m_errorLimiterPolicy.type == "rate limit") {
            policy->rules[0].action.type = Waap::RateLimiting::Policy::Rule::Action::Type::RATE_LIMIT;
        }
        else if (m_errorLimiting->m_errorLimiterPolicy.type == "detect") {
            policy->rules[0].action.type = Waap::RateLimiting::Policy::Rule::Action::Type::DETECT;
        }

        m_errorLimitingPolicy = policy;
    }
    catch (std::runtime_error & e) {
        ar.setNextName(nullptr);
        // Feature is currently not supported by the UI, thus changing debug level to debug.
        dbgDebug(D_WAAP) << failMessage << e.what();
        m_errorLimiting = nullptr;
        m_errorLimitingPolicy = nullptr;
    }

}

void WaapConfigBase::loadOpenRedirectPolicy(cereal::JSONInputArchive& ar)
{
    std::string failMessage = "Failed to load the WAAP OpenRedirect policy";
    try {
        m_openRedirectPolicy = std::make_shared<Waap::OpenRedirect::Policy>(ar);
    }
    catch (std::runtime_error & e) {
        ar.setNextName(nullptr);
        dbgWarning(D_WAAP) << failMessage << e.what();
        // TODO:: change the default back to nullptr when implemeted in hook
        // m_openRedirectPolicy = nullptr;
        // Now (until hook is implemented) the default is enabled+enforced
        m_openRedirectPolicy = std::make_shared<Waap::OpenRedirect::Policy>();
    }
}


const std::vector<std::string> &
WaapConfigBase::get_applicationUrls() const
{
    return m_applicationUrls;
}
void WaapConfigBase::loadErrorDisclosurePolicy(cereal::JSONInputArchive& ar)
{
    std::string failMessage = "Failed to load the WAAP Information Disclosure policy";
    try {
        m_errorDisclosurePolicy = std::make_shared<Waap::ErrorDisclosure::Policy>(ar);
    }
    catch (std::runtime_error & e) {
        ar.setNextName(nullptr);
        dbgWarning(D_WAAP) << failMessage << e.what();
        m_errorDisclosurePolicy = nullptr;
    }
}

void WaapConfigBase::loadUserLimitsPolicy(cereal::JSONInputArchive& ar)
{
    try {
        m_userLimitsPolicy = std::make_shared<Waap::UserLimits::Policy>(ar);
        dbgInfo(D_WAAP_ULIMITS) << "[USER LIMITS] policy loaded:\n" << *m_userLimitsPolicy;
    }
    catch (std::runtime_error & e) {
        ar.setNextName(nullptr);
        m_userLimitsPolicy = std::make_shared<Waap::UserLimits::Policy>();
        dbgInfo(D_WAAP_ULIMITS) << "[USER LIMITS] default policy loaded:\n" << *m_userLimitsPolicy;
    }
}

bool WaapConfigBase::operator==(const WaapConfigBase& other) const
{
    return
        m_autonomousSecurity == other.m_autonomousSecurity &&
        m_autonomousSecurityLevel == other.m_autonomousSecurityLevel &&
        m_practiceId == other.m_practiceId &&
        m_practiceName == other.m_practiceName &&
        m_ruleId == other.m_ruleId &&
        m_ruleName == other.m_ruleName &&
        m_assetId == other.m_assetId &&
        m_assetName == other.m_assetName &&
        Waap::Util::compareObjects(m_triggerPolicy, other.m_triggerPolicy) &&
        Waap::Util::compareObjects(m_overridePolicy, other.m_overridePolicy) &&
        Waap::Util::compareObjects(m_trustedSourcesPolicy, other.m_trustedSourcesPolicy) &&
        Waap::Util::compareObjects(m_waapParameters, other.m_waapParameters) &&
        Waap::Util::compareObjects(m_openRedirectPolicy, other.m_openRedirectPolicy) &&
        Waap::Util::compareObjects(m_errorDisclosurePolicy, other.m_errorDisclosurePolicy) &&
        Waap::Util::compareObjects(m_rateLimitingPolicy, other.m_rateLimitingPolicy) &&
        Waap::Util::compareObjects(m_errorLimitingPolicy, other.m_errorLimitingPolicy) &&
        Waap::Util::compareObjects(m_csrfPolicy, other.m_csrfPolicy) &&
        Waap::Util::compareObjects(m_userLimitsPolicy, other.m_userLimitsPolicy) &&
        Waap::Util::compareObjects(m_securityHeadersPolicy, other.m_securityHeadersPolicy);
}

void WaapConfigBase::printMe(std::ostream& os) const
{
    os << m_autonomousSecurity << ", " << m_autonomousSecurityLevel;
    os << ", " << m_ruleId << ", " << m_ruleName;
    os << ", " << m_practiceId << ", " << m_practiceName << ", " << m_assetId << ", " << m_assetName;
}

const std::string& WaapConfigBase::get_AssetId() const
{
    return m_assetId;
}

const std::string& WaapConfigBase::get_AssetName() const
{
    return m_assetName;
}

const std::string& WaapConfigBase::get_PracticeId() const
{
    return m_practiceId;
}

const std::string& WaapConfigBase::get_PracticeName() const
{
    return m_practiceName;
}

const std::string& WaapConfigBase::get_RuleId() const
{
    return m_ruleId;
}

const std::string& WaapConfigBase::get_RuleName() const
{
    return m_ruleName;
}

const bool& WaapConfigBase::get_WebAttackMitigation() const
{
    return m_autonomousSecurity;
}

const std::string& WaapConfigBase::get_WebAttackMitigationAction() const
{
    return m_autonomousSecurityLevel;
}

AttackMitigationMode
WaapConfigBase::get_WebAttackMitigationMode(const IWaapConfig& siteConfig)
{
    AttackMitigationMode attackMitigationMode = AttackMitigationMode::UNKNOWN;
    if (siteConfig.get_WebAttackMitigation()) {
        attackMitigationMode = (siteConfig.get_BlockingLevel() == BlockingLevel::NO_BLOCKING) ?
            AttackMitigationMode::LEARNING : AttackMitigationMode::PREVENT;
    }
    else {
        attackMitigationMode = AttackMitigationMode::DISABLED;
    }
    return attackMitigationMode;
}

const char*
WaapConfigBase::get_WebAttackMitigationModeStr(const IWaapConfig& siteConfig)
{
    switch(get_WebAttackMitigationMode(siteConfig)) {
        case AttackMitigationMode::DISABLED:
            return "DISABLED";
        case AttackMitigationMode::LEARNING:
            return "LEARNING";
        case AttackMitigationMode::PREVENT:
            return "PREVENT";
        default:
            return "UNKNOWN";
    }
}

const BlockingLevel& WaapConfigBase::get_BlockingLevel() const
{
    return m_blockingLevel;
}

const std::shared_ptr<Waap::Override::Policy>& WaapConfigBase::get_OverridePolicy() const
{
    return m_overridePolicy;
}

const std::shared_ptr<Waap::Trigger::Policy>& WaapConfigBase::get_TriggerPolicy() const
{
    return m_triggerPolicy;
}

const std::shared_ptr<Waap::TrustedSources::TrustedSourcesParameter>& WaapConfigBase::get_TrustedSourcesPolicy() const
{
    return m_trustedSourcesPolicy;
}


const std::shared_ptr<Waap::Csrf::Policy>& WaapConfigBase::get_CsrfPolicy() const
{
    return m_csrfPolicy;
}

const std::shared_ptr<Waap::Parameters::WaapParameters>& WaapConfigBase::get_WaapParametersPolicy() const
{
    return m_waapParameters;
}

const std::shared_ptr<Waap::RateLimiting::Policy>& WaapConfigBase::get_RateLimitingPolicy() const
{
    return m_rateLimitingPolicy;
}

const std::shared_ptr<Waap::RateLimiting::Policy>& WaapConfigBase::get_ErrorLimitingPolicy() const
{
    return m_errorLimitingPolicy;
}

const std::shared_ptr<Waap::OpenRedirect::Policy>& WaapConfigBase::get_OpenRedirectPolicy() const
{
    return m_openRedirectPolicy;
}



const std::shared_ptr<Waap::ErrorDisclosure::Policy>& WaapConfigBase::get_ErrorDisclosurePolicy() const
{
    return m_errorDisclosurePolicy;
}

const std::shared_ptr<Waap::SecurityHeaders::Policy>& WaapConfigBase::get_SecurityHeadersPolicy() const
{
    return m_securityHeadersPolicy;
}

const std::shared_ptr<Waap::UserLimits::Policy>& WaapConfigBase::get_UserLimitsPolicy() const
{
    return m_userLimitsPolicy;
}

BlockingLevel WaapConfigBase::blockingLevelBySensitivityStr(const std::string& sensitivity) const
{
    std::string sensitivityLower = to_lower_copy(sensitivity);

    if (sensitivityLower == "transparent")
    {
        return BlockingLevel::NO_BLOCKING;
    }
    else if (sensitivityLower == "low")
    {
        return BlockingLevel::LOW_BLOCKING_LEVEL;
    }
    else if (sensitivityLower == "balanced")
    {
        return BlockingLevel::MEDIUM_BLOCKING_LEVEL;
    }
    else if (sensitivityLower == "high")
    {
        return BlockingLevel::HIGH_BLOCKING_LEVEL;
    }
    return BlockingLevel::NO_BLOCKING;
}
