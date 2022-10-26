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

#ifndef __RULEBASE_CONFIG_H__
#define __RULEBASE_CONFIG_H__

#include <vector>
#include <string>
#include <set>
#include <unordered_map>

#include "generic_rulebase/generic_rulebase_utils.h"
#include "environment/evaluator_templates.h"
#include "cereal/types/string.hpp"
#include "cereal/types/vector.hpp"
#include "cereal/archives/json.hpp"
#include "i_environment.h"
#include "singleton.h"
#include "maybe_res.h"
#include "config.h"

using GenericConfigId = std::string;

class RulePractice
{
public:
    RulePractice() = default;

    RulePractice(GenericConfigId &_id, std::string &_name) : practice_id(_id), practice_name(_name) {};

    void
    serialize(cereal::JSONInputArchive &ar)
    {
        parseJSONKey<GenericConfigId>("practiceId", practice_id, ar);
        parseJSONKey<std::string>("practiceName", practice_name, ar);
    }

    const GenericConfigId getId() const { return practice_id; }

    const std::string getName() const { return practice_name; }

    bool
    operator==(const RulePractice &other) const
    {
        return practice_id == other.getId() && practice_name == other.getName();
    }

private:
    GenericConfigId practice_id;
    std::string practice_name;
};

class RuleTrigger
{
public:
    void
    serialize(cereal::JSONInputArchive &ar)
    {
        parseJSONKey<GenericConfigId>("triggerId", trigger_id, ar);
        parseJSONKey<std::string>("triggerType", trigger_type, ar);
        parseJSONKey<std::string>("triggerName", trigger_name, ar);
    }

    const GenericConfigId getId() const { return trigger_id; }

    const std::string getType() const { return trigger_type; }

    const std::string getName() const { return trigger_name; }

private:
    GenericConfigId trigger_id;
    std::string trigger_type;
    std::string trigger_name;
};

class RuleParameter
{
public:
    void
    serialize(cereal::JSONInputArchive &ar)
    {
        parseJSONKey<GenericConfigId>("parameterId", parameter_id, ar);
        parseJSONKey<std::string>("parameterType", parameter_type, ar);
        parseJSONKey<std::string>("parameterName", parameter_name, ar);
    }

    const GenericConfigId getId() const { return parameter_id; }

    const std::string getType() const { return parameter_type; }

    const std::string getName() const { return parameter_name; }

private:
    GenericConfigId parameter_id;
    std::string parameter_type;
    std::string parameter_name;
};

class BasicRuleConfig
{
public:
    static void
    preload()
    {
        registerExpectedConfiguration<BasicRuleConfig>("rulebase", "rulesConfig");
        registerExpectedSetting<std::vector<BasicRuleConfig>>("rulebase", "rulesConfig");
        registerConfigLoadCb(BasicRuleConfig::updateCountMetric);
        registerConfigPrepareCb([](){ BasicRuleConfig::assets_ids_aggregation.clear(); });
    }

    void load(cereal::JSONInputArchive &ar);

    static void updateCountMetric();

    bool isPracticeActive(const GenericConfigId &practice_id) const;

    bool isTriggerActive(const GenericConfigId &trigger_id) const;

    bool isParameterActive(const GenericConfigId &parameter_id) const;

    uint8_t getPriority() const { return priority; }

    const GenericConfigId & getRuleId() const { return rule_id; }

    const std::string & getRuleName() const { return rule_name; }

    const GenericConfigId & getAssetId() const { return asset_id; }

    const std::string & getAssetName() const { return asset_name; }

    const GenericConfigId & getZoneId() const { return zone_id; }

    const std::string & getZoneName() const { return zone_name; }

    const std::vector<RulePractice> & getPractices() const { return practices; }

    const std::vector<RuleTrigger> & getTriggers() const { return triggers; }

    const std::vector<RuleParameter> & getParameters() const { return parameters; }

private:
    uint8_t priority = 0;
    GenericConfigId rule_id = "";
    std::string rule_name;
    GenericConfigId asset_id;
    std::string asset_name;
    GenericConfigId zone_id;
    std::string zone_name;
    std::vector<RulePractice> practices;
    std::vector<RuleTrigger> triggers;
    std::vector<RuleParameter> parameters;

    static std::set<std::string> assets_ids;
    static std::set<std::string> assets_ids_aggregation;
};

#endif // __RULEBASE_CONFIG_H__
