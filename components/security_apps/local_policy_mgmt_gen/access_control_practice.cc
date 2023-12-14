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

#include "access_control_practice.h"

using namespace std;

USE_DEBUG_FLAG(D_LOCAL_POLICY);
// LCOV_EXCL_START Reason: no test exist

static const map<string, string> valid_modes_to_key = {
    {"prevent", "Active"},
    {"detect", "Detect"},
    {"inactive", "Inactive"}
};
static const set<string> valid_units    = {"minute", "second"};

static const std::unordered_map<std::string, std::string> key_to_units_val = {
    { "second", "Second"},
    { "minute", "Minute"}
};

void
RateLimitRulesTriggerSection::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("id",      id),
        cereal::make_nvp("name",    name),
        cereal::make_nvp("type",    type)
    );
}

const string &
RateLimitRulesTriggerSection::getName() const
{
    return name;
}

void
RateLimitRulesSection::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("id",              id),
        cereal::make_nvp("URI",             uri),
        cereal::make_nvp("scope",           key_to_units_val.at(scope)),
        cereal::make_nvp("triggers",        triggers),
        cereal::make_nvp("limit",           limit)
    );
}

RateLimitSection::RateLimitSection(
    const string &asset_name,
    const string &url,
    const string &uri,
    const std::string &_mode,
    const std::string &_practice_id,
    const std::string &_name,
    const std::vector<RateLimitRulesSection> &_rules)
        :
    mode(_mode),
    practice_id(_practice_id),
    name(_name),
    rules(_rules)
{
    bool any = asset_name == "Any" && url == "Any" && uri == "Any";
    string asset_id = any ? "Any" : url+uri;
    context = any ? "All()" : "assetId(" + asset_id + ")";
}

void
RateLimitSection::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("context",         context),
        cereal::make_nvp("mode",            mode),
        cereal::make_nvp("practiceId",      practice_id),
        cereal::make_nvp("name",            name),
        cereal::make_nvp("rules",           rules)
    );
}

const string &
RateLimitSection::getId() const
{
    return practice_id;
}

const string &
RateLimitSection::getName() const
{
    return name;
}

const string &
RateLimitSection::getMode() const
{
    return mode;
}

void
AccessControlRulebaseSection::save(cereal::JSONOutputArchive &out_ar) const
{
    vector<string> empty;
    out_ar(
        cereal::make_nvp("accessControl",           empty),
        cereal::make_nvp("traditionalFirewall",     empty),
        cereal::make_nvp("l4firewall",              empty),
        cereal::make_nvp("rateLimit",               rate_limit)
    );
}

void
AccessControlRulebaseWrapper::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("rulebase", rule_base)
    );
}

void
AccessControlRateLimiteRules::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading Access control rate limite rules";
    parseAppsecJSONKey<int>("limit", limit, archive_in);
    parseAppsecJSONKey<string>("uri", uri, archive_in);
    parseAppsecJSONKey<string>("unit", unit, archive_in);
    if (valid_units.count(unit) == 0) {
        dbgWarning(D_LOCAL_POLICY)
        << "Access control rate limite rules units invalid: "
        << unit;
    }
    parseAppsecJSONKey<string>("comment", comment, archive_in);
    parseAppsecJSONKey<vector<string>>("triggers", triggers, archive_in);
}

const vector<string>
AccessControlRateLimiteRules::getTriggers() const
{
    return triggers;
}

RateLimitRulesSection
AccessControlRateLimiteRules::createRateLimitRulesSection(const RateLimitRulesTriggerSection &trigger) const
{
    string id = "";
    try {
        id = to_string(boost::uuids::random_generator()());
    } catch (const boost::uuids::entropy_error &e) {
        dbgWarning(D_LOCAL_POLICY) << "Failed to create random id";
    }
    vector<RateLimitRulesTriggerSection> triggers_section;
    string trigger_name =  trigger.getName().substr(trigger.getName().find("/") + 1);
    if (find(triggers.begin(), triggers.end(), trigger_name) != triggers.end()) {
        triggers_section.push_back(trigger);
    }
    return RateLimitRulesSection(
        limit,
        id,
        uri,
        unit,
        triggers_section
    );
}

void
AccessControlRateLimit::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading Access control rate limit";
    string in_mode;
    parseAppsecJSONKey<string>("overrideMode", in_mode, archive_in, "inactive");
    if (valid_modes_to_key.find(in_mode) == valid_modes_to_key.end()) {
        dbgWarning(D_LOCAL_POLICY) << "AppSec access control rate limit override mode invalid: " << in_mode;
        mode = "Inactive";
    } else {
        mode = valid_modes_to_key.at(in_mode);
    }
    parseAppsecJSONKey<std::vector<AccessControlRateLimiteRules>>("rules", rules, archive_in);
}

vector<RateLimitRulesSection>
AccessControlRateLimit::createRateLimitRulesSection(const RateLimitRulesTriggerSection &trigger) const
{
    vector<RateLimitRulesSection> rules_section;
    for (const AccessControlRateLimiteRules &rule : rules) {
        rules_section.push_back(rule.createRateLimitRulesSection(trigger));
    }
    return rules_section;
}

const vector<AccessControlRateLimiteRules> &
AccessControlRateLimit::getRules() const
{
    return rules;
}

const string &
AccessControlRateLimit::getMode() const
{
    return mode;
}

void
AccessControlPracticeSpec::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec practice spec";

    parseAppsecJSONKey<string>("name", practice_name, archive_in);
    parseAppsecJSONKey<string>("appsecClassName", appsec_class_name, archive_in);
    parseAppsecJSONKey<AccessControlRateLimit>("rateLimit", rate_limit, archive_in);
}

void
AccessControlPracticeSpec::setName(const string &_name)
{
    practice_name = _name;
}

const AccessControlRateLimit &
AccessControlPracticeSpec::geRateLimit() const
{
    return rate_limit;
}

const string &
AccessControlPracticeSpec::getAppSecClassName() const
{
    return appsec_class_name;
}

const string &
AccessControlPracticeSpec::getName() const
{
    return practice_name;
}
// LCOV_EXCL_STOP
