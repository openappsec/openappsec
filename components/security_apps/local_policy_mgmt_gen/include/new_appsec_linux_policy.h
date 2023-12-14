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

#ifndef __NEW_APPSEC_LINUX_POLICY_H__
#define __NEW_APPSEC_LINUX_POLICY_H__

#include <list>
#include <vector>
#include <cereal/archives/json.hpp>
#include <cereal/types/list.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "config.h"
#include "debug.h"
#include "customized_cereal_map.h"
#include "new_appsec_policy_crd_parser.h"
#include "new_custom_response.h"
#include "new_exceptions.h"
#include "new_log_trigger.h"
#include "new_practice.h"
#include "access_control_practice.h"
#include "new_trusted_sources.h"
#include "new_auto_upgrade.h"

class V1beta2AppsecLinuxPolicy : Singleton::Consume<I_Environment>
{
public:
    // LCOV_EXCL_START Reason: no test exist
    V1beta2AppsecLinuxPolicy() {}

    V1beta2AppsecLinuxPolicy(
        const NewAppsecPolicySpec &_policies,
        const std::vector<NewAppSecPracticeSpec> &_threat_prevention_practices,
        const std::vector<AccessControlPracticeSpec> &_access_control_practices,
        const std::vector<NewAppsecLogTrigger> &_log_triggers,
        const std::vector<NewAppSecCustomResponse> &_custom_responses,
        const std::vector<NewAppsecException> &_exceptions,
        const std::vector<NewTrustedSourcesSpec> &_trusted_sources,
        const std::vector<NewSourcesIdentifiers> &_sources_identifiers,
        const AppSecAutoUpgradeSpec &_auto_upgrade)
            :
        policies(_policies),
        threat_prevection_practices(_threat_prevention_practices),
        access_control_practices(_access_control_practices),
        log_triggers(_log_triggers),
        custom_responses(_custom_responses),
        exceptions(_exceptions),
        trusted_sources(_trusted_sources),
        sources_identifiers(_sources_identifiers),
        auto_upgrade(_auto_upgrade) {}
    // LCOV_EXCL_STOP
    void serialize(cereal::JSONInputArchive &archive_in);

    const NewAppsecPolicySpec & getAppsecPolicySpec() const;
    const std::vector<NewAppSecPracticeSpec> & getAppSecPracticeSpecs() const;
    const std::vector<AccessControlPracticeSpec> & getAccessControlPracticeSpecs() const;
    const std::vector<NewAppsecLogTrigger> & getAppsecTriggerSpecs() const;
    const std::vector<NewAppSecCustomResponse> & getAppSecCustomResponseSpecs() const;
    const std::vector<NewAppsecException> & getAppsecExceptions() const;
    const std::vector<NewTrustedSourcesSpec> & getAppsecTrustedSourceSpecs() const;
    const std::vector<NewSourcesIdentifiers> & getAppsecSourceIdentifierSpecs() const;
    const AppSecAutoUpgradeSpec & getAppSecAutoUpgradeSpec() const;
    void addSpecificRule(const NewParsedRule &_rule);

private:
    NewAppsecPolicySpec policies;
    std::vector<NewAppSecPracticeSpec> threat_prevection_practices;
    std::vector<AccessControlPracticeSpec> access_control_practices;
    std::vector<NewAppsecLogTrigger> log_triggers;
    std::vector<NewAppSecCustomResponse> custom_responses;
    std::vector<NewAppsecException> exceptions;
    std::vector<NewTrustedSourcesSpec> trusted_sources;
    std::vector<NewSourcesIdentifiers> sources_identifiers;
    AppSecAutoUpgradeSpec auto_upgrade;
};

#endif // __NEW_APPSEC_LINUX_POLICY_H__
