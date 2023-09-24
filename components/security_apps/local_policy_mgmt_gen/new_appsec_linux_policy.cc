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

void
V1beta2AppsecLinuxPolicy::addSpecificRule(const NewParsedRule &_rule)
{
    policies.addSpecificRule(_rule);
}
// LCOV_EXCL_STOP
