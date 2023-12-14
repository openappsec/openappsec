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

#include "new_appsec_policy_crd_parser.h"

using namespace std;

USE_DEBUG_FLAG(D_LOCAL_POLICY);
// LCOV_EXCL_START Reason: no test exist

static const set<string> valid_modes = {"prevent-learn", "detect-learn", "prevent", "detect", "inactive"};

void
NewParsedRule::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec NewParsedRule";
    parseAppsecJSONKey<vector<string>>("exceptions", exceptions, archive_in);
    parseAppsecJSONKey<vector<string>>("triggers", log_triggers, archive_in);
    parseAppsecJSONKey<vector<string>>("threatPreventionPractices", threat_prevention_practices, archive_in);
    parseAppsecJSONKey<vector<string>>("accessControlPractices", access_control_practices, archive_in);
    parseAppsecJSONKey<string>("mode", mode, archive_in);
    if (valid_modes.count(mode) == 0) {
        dbgWarning(D_LOCAL_POLICY) << "AppSec New Parsed Rule mode invalid: " << mode;
    }
    parseAppsecJSONKey<string>("customResponse", custom_response, archive_in);
    parseAppsecJSONKey<string>("sourceIdentifiers", source_identifiers, archive_in);
    parseAppsecJSONKey<string>("trustedSources", trusted_sources, archive_in);
    parseAppsecJSONKey<string>("autoUpgrade", upgrade_settings, archive_in);
    try {
        archive_in(cereal::make_nvp("host", host));
    } catch (const cereal::Exception &e)
    {
        // The default NewParsedRule does not hold a host, so by default it will be *
        host =  "*";
    }
}

const vector<string> &
NewParsedRule::getLogTriggers() const
{
    return log_triggers;
}
const vector<string> &

NewParsedRule::getExceptions() const
{
    return exceptions;
}

const vector<string> &
NewParsedRule::getPractices() const
{
    return threat_prevention_practices;
}

const vector<string> &
NewParsedRule::getAccessControlPractices() const
{
    return access_control_practices;
}

const string &
NewParsedRule::getSourceIdentifiers() const
{
    return source_identifiers;
}

const string &
NewParsedRule::getCustomResponse() const
{
    return custom_response;
}

const string &
NewParsedRule::getTrustedSources() const
{
    return trusted_sources;
}

const string &
NewParsedRule::getUpgradeSettings() const
{
    return upgrade_settings;
}

const string &
NewParsedRule::getHost() const
{
    return host;
}

const string &
NewParsedRule::getMode() const
{
    return mode;
}

void
NewParsedRule::setHost(const string &_host)
{
    host = _host;
}

void
NewParsedRule::setMode(const string &_mode)
{
    mode = _mode;
}

void
NewAppsecPolicySpec::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec policy spec";
    parseAppsecJSONKey<string>("appsecClassName", appsec_class_name, archive_in);
    parseAppsecJSONKey<NewParsedRule>("default", default_rule, archive_in);
    parseAppsecJSONKey<vector<NewParsedRule>>("specificRules", specific_rules, archive_in);
}

const NewParsedRule &
NewAppsecPolicySpec::getDefaultRule() const
{
    return default_rule;
}

const vector<NewParsedRule> &
NewAppsecPolicySpec::getSpecificRules() const
{
    return specific_rules;
}

const string &
NewAppsecPolicySpec::getAppSecClassName() const
{
    return appsec_class_name;
}

bool
NewAppsecPolicySpec::isAssetHostExist(const std::string &full_url) const
{
    for (const NewParsedRule &rule : specific_rules) {
        if (rule.getHost() == full_url) return true;
    }
    return false;
}

void
NewAppsecPolicySpec::addSpecificRule(const NewParsedRule &_rule)
{
    specific_rules.push_back(_rule);
}
// LCOV_EXCL_STOP
