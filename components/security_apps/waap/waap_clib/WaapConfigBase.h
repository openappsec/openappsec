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

#pragma once
#ifndef __WAAP_CONFIG_BASE_H__
#define __WAAP_CONFIG_BASE_H__

#include "i_waapConfig.h"
#include "WaapOverride.h"
#include "WaapTrigger.h"
#include "WaapOpenRedirectPolicy.h"
#include "WaapErrorDisclosurePolicy.h"
#include "ErrorLimiting.h"
#include "CsrfPolicy.h"
#include "SecurityHeadersPolicy.h"
#include "UserLimitsPolicy.h"
#include "TrustedSources.h"
#include "Waf2Util.h"
#include "debug.h"

class WaapConfigBase : public IWaapConfig
{
public:
    static AttackMitigationMode get_WebAttackMitigationMode(const IWaapConfig& siteConfig);
    static const char* get_WebAttackMitigationModeStr(const IWaapConfig& siteConfig);

    bool operator==(const WaapConfigBase& other) const;

    virtual const std::string&   get_AssetId() const;
    virtual const std::string&   get_AssetName() const;
    virtual const BlockingLevel& get_BlockingLevel() const;
    virtual const std::string&   get_PracticeId() const;
    virtual const std::string&   get_PracticeName() const;
    virtual const std::string&   get_RuleId() const;
    virtual const std::string&   get_RuleName() const;
    virtual const bool&          get_WebAttackMitigation() const;
    virtual const std::string&   get_WebAttackMitigationAction() const;
    virtual const std::vector<std::string> & get_applicationUrls() const;

    virtual const std::shared_ptr<Waap::Override::Policy>& get_OverridePolicy() const;
    virtual const std::shared_ptr<Waap::Trigger::Policy>& get_TriggerPolicy() const;
    virtual const std::shared_ptr<Waap::TrustedSources::TrustedSourcesParameter>& get_TrustedSourcesPolicy() const;
    virtual const std::shared_ptr<Waap::Parameters::WaapParameters>& get_WaapParametersPolicy() const;
    virtual const std::shared_ptr<Waap::OpenRedirect::Policy>& get_OpenRedirectPolicy() const;
    virtual const std::shared_ptr<Waap::ErrorDisclosure::Policy>& get_ErrorDisclosurePolicy() const;
    virtual const std::shared_ptr<Waap::Csrf::Policy>& get_CsrfPolicy() const;
    virtual const std::shared_ptr<Waap::RateLimiting::Policy>& get_RateLimitingPolicy() const;
    virtual const std::shared_ptr<Waap::SecurityHeaders::Policy>& get_SecurityHeadersPolicy() const;
    virtual const std::shared_ptr<Waap::RateLimiting::Policy>& get_ErrorLimitingPolicy() const;
    virtual const std::shared_ptr<Waap::UserLimits::Policy>& get_UserLimitsPolicy() const;

    virtual void printMe(std::ostream& os) const;

protected:
    WaapConfigBase();
    void load(cereal::JSONInputArchive& ar);
    void loadOpenRedirectPolicy(cereal::JSONInputArchive& ar);
    void loadErrorDisclosurePolicy(cereal::JSONInputArchive& ar);
    void loadCsrfPolicy(cereal::JSONInputArchive& ar);
    void loadRateLimitingPolicy(cereal::JSONInputArchive& ar);
    void loadSecurityHeadersPolicy(cereal::JSONInputArchive& ar);
    void loadErrorLimitingPolicy(cereal::JSONInputArchive& ar);

    std::string m_assetId;
private:
    void loadOverridePolicy(cereal::JSONInputArchive& ar);
    void loadTriggersPolicy(cereal::JSONInputArchive& ar);
    void loadTrustedSourcesPolicy(cereal::JSONInputArchive& ar);
    void loadWaapParametersPolicy(cereal::JSONInputArchive& ar);
    void loadUserLimitsPolicy(cereal::JSONInputArchive& ar);

    void readJSONByCereal(cereal::JSONInputArchive& ar);
    BlockingLevel blockingLevelBySensitivityStr(const std::string& sensitivity) const;

    std::string   m_autonomousSecurityLevel;
    bool          m_autonomousSecurity;
    std::string   m_assetName;
    BlockingLevel m_blockingLevel;
    std::string   m_practiceId;
    std::string   m_practiceName;
    std::string   m_ruleId;
    std::string   m_ruleName;

    std::shared_ptr<Waap::Override::Policy> m_overridePolicy;
    std::shared_ptr<Waap::Trigger::Policy> m_triggerPolicy;
    std::shared_ptr<Waap::TrustedSources::TrustedSourcesParameter> m_trustedSourcesPolicy;
    std::shared_ptr<Waap::Parameters::WaapParameters> m_waapParameters;
    std::shared_ptr<Waap::OpenRedirect::Policy> m_openRedirectPolicy;
    std::vector<std::string> m_applicationUrls;
    std::shared_ptr<Waap::ErrorDisclosure::Policy> m_errorDisclosurePolicy;
    std::string m_schemaValidationPoicyStatusMessage;
    std::string m_schemaUpdaterPoicyStatusMessage;
    std::shared_ptr<Waap::Csrf::Policy> m_csrfPolicy;
    std::shared_ptr<Waap::RateLimiting::Policy> m_rateLimitingPolicy;
    std::shared_ptr<Waap::RateLimiting::Policy> m_errorLimitingPolicy;
    std::shared_ptr<Waap::ErrorLimiting::ErrorLimiter> m_errorLimiting;
    std::shared_ptr<Waap::UserLimits::Policy> m_userLimitsPolicy;
    std::shared_ptr<Waap::SecurityHeaders::Policy> m_securityHeadersPolicy;
};

#endif // __WAAP_CONFIG_BASE_H__
