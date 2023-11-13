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

#include "../waap_clib/WaapOverride.h"
#include "../waap_clib/WaapTrigger.h"
#include "../waap_clib/TrustedSources.h"
#include "../waap_clib/WaapParameters.h"
#include "../waap_clib/WaapOpenRedirectPolicy.h"
#include "../waap_clib/WaapErrorDisclosurePolicy.h"
#include "../waap_clib/CsrfPolicy.h"
#include "../waap_clib/UserLimitsPolicy.h"
#include "../waap_clib/RateLimiting.h"
#include "../waap_clib/SecurityHeadersPolicy.h"
#include <memory>

enum class BlockingLevel {
    NO_BLOCKING = 0,
    LOW_BLOCKING_LEVEL,
    MEDIUM_BLOCKING_LEVEL,
    HIGH_BLOCKING_LEVEL
};

enum class AttackMitigationMode
{
    DISABLED = 0,
    LEARNING,
    PREVENT,
    UNKNOWN
};
class IWaapConfig {
public:
    virtual const std::string&   get_AssetId() const = 0;
    virtual const std::string&   get_AssetName() const = 0;
    virtual const BlockingLevel& get_BlockingLevel() const = 0;
    virtual const std::string&   get_PracticeId() const = 0;
    virtual const std::string&   get_PracticeName() const = 0;
    virtual const std::string&   get_PracticeSubType() const = 0;
    virtual const std::string&   get_RuleId() const = 0;
    virtual const std::string&   get_RuleName() const = 0;
    virtual const bool&          get_WebAttackMitigation() const = 0;
    virtual const std::string&   get_WebAttackMitigationAction() const = 0;
    virtual const std::vector<std::string> & get_applicationUrls() const = 0;

    virtual const std::shared_ptr<Waap::Override::Policy>& get_OverridePolicy() const = 0;
    virtual const std::shared_ptr<Waap::Trigger::Policy>& get_TriggerPolicy() const = 0;
    virtual const std::shared_ptr<Waap::TrustedSources::TrustedSourcesParameter>& get_TrustedSourcesPolicy() const = 0;
    virtual const std::shared_ptr<Waap::Parameters::WaapParameters>& get_WaapParametersPolicy() const = 0;
    virtual const std::shared_ptr<Waap::OpenRedirect::Policy>& get_OpenRedirectPolicy() const = 0;
    virtual const std::shared_ptr<Waap::ErrorDisclosure::Policy>& get_ErrorDisclosurePolicy() const = 0;
    virtual const std::shared_ptr<Waap::Csrf::Policy>& get_CsrfPolicy() const = 0;
    virtual const std::shared_ptr<Waap::RateLimiting::Policy>& get_RateLimitingPolicy() const = 0;
    virtual const std::shared_ptr<Waap::RateLimiting::Policy>& get_ErrorLimitingPolicy() const = 0;
    virtual const std::shared_ptr<Waap::SecurityHeaders::Policy>& get_SecurityHeadersPolicy() const = 0;
    virtual const std::shared_ptr<Waap::UserLimits::Policy>& get_UserLimitsPolicy() const = 0;

    virtual void printMe(std::ostream& os) const = 0;
};
