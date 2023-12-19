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

#include "new_appsec_linux_policy.h"
// LCOV_EXCL_START Reason: no test exist

using namespace std;

const NewAppsecPolicySpec &
V1beta2AppsecLinuxPolicy::getAppsecPolicySpec() const
{
    return policies;
}

const vector<NewAppSecPracticeSpec> &
V1beta2AppsecLinuxPolicy::getAppSecPracticeSpecs() const
{
    return threat_prevection_practices;
}

const vector<AccessControlPracticeSpec> &
V1beta2AppsecLinuxPolicy::getAccessControlPracticeSpecs() const
{
    return access_control_practices;
}

const vector<NewAppsecLogTrigger> &
V1beta2AppsecLinuxPolicy::getAppsecTriggerSpecs() const
{
    return log_triggers;
}

const vector<NewAppSecCustomResponse> &
V1beta2AppsecLinuxPolicy::getAppSecCustomResponseSpecs() const
{
    return custom_responses;
}

const vector<NewAppsecException> &
V1beta2AppsecLinuxPolicy::getAppsecExceptions() const
{
    return exceptions;
}

const vector<NewTrustedSourcesSpec> &
V1beta2AppsecLinuxPolicy::getAppsecTrustedSourceSpecs() const
{
    return trusted_sources;
}

const vector<NewSourcesIdentifiers> &
V1beta2AppsecLinuxPolicy::getAppsecSourceIdentifierSpecs() const
{
    return sources_identifiers;
}

const AppSecAutoUpgradeSpec &
V1beta2AppsecLinuxPolicy::getAppSecAutoUpgradeSpec() const
{
    return auto_upgrade;
}

void
V1beta2AppsecLinuxPolicy::addSpecificRule(const NewParsedRule &_rule)
{
    policies.addSpecificRule(_rule);
}
// LCOV_EXCL_STOP

void
V1beta2AppsecLinuxPolicy::serialize(cereal::JSONInputArchive &archive_in)
{
    dbgInfo(D_LOCAL_POLICY) << "Loading Appsec V1Beta2 Linux Policy";

    // Check for the presence of "apiVersion" key, present only from V1Beta2
    string api_version;
    archive_in(cereal::make_nvp("apiVersion", api_version));
    if (api_version != "v1beta2") throw cereal::Exception("Failed to parse JSON as v1Beta2 version");

    parseAppsecJSONKey<NewAppsecPolicySpec>("policies", policies, archive_in);
    parseAppsecJSONKey<vector<NewAppSecPracticeSpec>>(
        "threatPreventionPractices",
        threat_prevection_practices,
        archive_in
    );
    parseAppsecJSONKey<vector<AccessControlPracticeSpec>>(
        "accessControlPractices",
        access_control_practices,
        archive_in
    );
    parseAppsecJSONKey<vector<NewAppsecLogTrigger>>("logTriggers", log_triggers, archive_in);
    parseAppsecJSONKey<vector<NewAppSecCustomResponse>>("customResponse", custom_responses, archive_in);
    parseAppsecJSONKey<vector<NewAppsecException>>("exceptions", exceptions, archive_in);
    parseAppsecJSONKey<vector<NewTrustedSourcesSpec>>("trustedSources", trusted_sources, archive_in);
    parseAppsecJSONKey<vector<NewSourcesIdentifiers>>("sourcesIdentifiers", sources_identifiers, archive_in);
    parseAppsecJSONKey<AppSecAutoUpgradeSpec>("autoUpgrade", auto_upgrade, archive_in);
}
