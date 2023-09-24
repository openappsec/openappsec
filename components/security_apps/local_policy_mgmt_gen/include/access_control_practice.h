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

#ifndef __ACCESS_CONTROL_PRACTICE_H__
#define __ACCESS_CONTROL_PRACTICE_H__

#include <string>
#include <cereal/archives/json.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "config.h"
#include "debug.h"
#include "local_policy_common.h"

class RateLimitRulesTriggerSection
{
public:
    // LCOV_EXCL_START Reason: no test exist
    RateLimitRulesTriggerSection() {};

    RateLimitRulesTriggerSection(
    const std::string &_id,
    const std::string &_name,
    const std::string &_type
    )
        :
    id(_id),
    name(_name),
    type(_type)
    {};
    // LCOV_EXCL_STOP

    void save(cereal::JSONOutputArchive &out_ar) const;
    const std::string & getName() const;

private:
    std::string                 id;
    std::string                 name;
    std::string                 type;;
};

class RateLimitRulesSection
{
public:
    RateLimitRulesSection() {};

    // LCOV_EXCL_START Reason: no test exist
    RateLimitRulesSection(
    const int _limit,
    const std::string &_id,
    const std::string &_uri,
    const std::string &_scope,
    const std::vector<RateLimitRulesTriggerSection> &_triggers
    )
        :
    limit(_limit),
    id(_id),
    uri(_uri),
    scope(_scope),
    triggers(_triggers)
    {};
    // LCOV_EXCL_STOP

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    int                                         limit;
    std::string                                 id;
    std::string                                 uri;
    std::string                                 scope;
    std::vector<RateLimitRulesTriggerSection>   triggers;
};

class RateLimitSection
{
public:
    // LCOV_EXCL_START Reason: no test exist
    RateLimitSection() {};
    // LCOV_EXCL_STOP

    RateLimitSection(
    const std::string &asset_name,
    const std::string &url,
    const std::string &uri,
    const std::string &_mode,
    const std::string &_practice_id,
    const std::string &_name,
    const std::vector<RateLimitRulesSection> &_rules);

    void save(cereal::JSONOutputArchive &out_ar) const;
    const std::string & getId() const;
    const std::string & getName() const;
    const std::string & getMode() const;

private:
    std::string                                 context;
    std::string                                 mode;
    std::string                                 practice_id;
    std::string                                 name;
    std::vector<RateLimitRulesSection>          rules;
};

class AccessControlRulebaseSection
{
public:
    AccessControlRulebaseSection() {};

    AccessControlRulebaseSection(const std::vector<RateLimitSection> &_rate_limit) : rate_limit(_rate_limit) {};

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    std::vector<RateLimitSection> rate_limit;
};

class AccessControlRulebaseWrapper
{
public:
    AccessControlRulebaseWrapper() {};

    AccessControlRulebaseWrapper(
    const std::vector<RateLimitSection> &rate_limits
    )
        :
    rule_base(AccessControlRulebaseSection(rate_limits))
    {};

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    AccessControlRulebaseSection rule_base;
};

class AccessControlRateLimiteRules
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const std::vector<std::string> getTriggers() const;
    RateLimitRulesSection createRateLimitRulesSection(const RateLimitRulesTriggerSection &trigger) const;

private:
    int                         limit;
    std::string                 uri;
    std::string                 unit;
    std::string                 comment;
    std::vector<std::string>    triggers;
};

class AccessControlRateLimit
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const std::vector<AccessControlRateLimiteRules> & getRules() const;
    const std::string & getMode() const;
    std::vector<RateLimitRulesSection> createRateLimitRulesSection(const RateLimitRulesTriggerSection &trigger) const;

private:
    std::string                                 mode;
    std::vector<AccessControlRateLimiteRules>   rules;
};

class AccessControlPracticeSpec
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const AccessControlRateLimit & geRateLimit() const;
    const std::string & getAppSecClassName() const;
    const std::string & getName() const;
    void setName(const std::string &_name);

private:
    AccessControlRateLimit      rate_limit;
    std::string                 appsec_class_name;
    std::string                 practice_name;
};

#endif // __ACCESS_CONTROL_PRACTICE_H__
