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

#ifndef __RULES_CONFIG_SECTION_H__
#define __RULES_CONFIG_SECTION_H__

#include <string>
#include <algorithm>
#include <cereal/archives/json.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "config.h"
#include "debug.h"
#include "k8s_policy_common.h"

USE_DEBUG_FLAG(D_K8S_POLICY);
// LCOV_EXCL_START Reason: no test exist
class AssetUrlParser
{
public:
    AssetUrlParser() {}

    static AssetUrlParser parse(const std::string &uri);
    std::string query_string, asset_uri, protocol, asset_url, port;
};

class PracticeSection
{
public:
    PracticeSection(
        const std::string &_id,
        const std::string &_type,
        const std::string &_practice_name);

    void save(cereal::JSONOutputArchive &out_ar) const;

    const std::string & getPracticeId() const;
    const std::string & getPracticeName() const;

private:
    std::string id;
    std::string name;
    std::string type;
};

class ParametersSection
{
public:
    ParametersSection(const std::string &_id, const std::string &_name);

    void save(cereal::JSONOutputArchive &out_ar) const;
    const std::string & getId() const;

private:
    std::string name;
    std::string id;
    std::string type = "Exception";
};

class RulesTriggerSection
{
public:
    RulesTriggerSection(
        const std::string &_name,
        const std::string &_id,
        const std::string &_type);

    void save(cereal::JSONOutputArchive &out_ar) const;

    const std::string & getId() const;
    const std::string & getName() const;

private:
    std::string name;
    std::string id;
    std::string type;
};

class RulesConfigRulebase
{
public:
    RulesConfigRulebase()
    {}

    RulesConfigRulebase(
        const std::string &_name,
        const std::string &_url,
        const std::string &_uri,
        std::vector<PracticeSection> _practices,
        std::vector<ParametersSection> _parameters,
        std::vector<RulesTriggerSection> _triggers);

    void save(cereal::JSONOutputArchive &out_ar) const;

    const std::string & getRuleId() const;
    const std::string & getAssetName() const;
    const std::string & getRuleName() const;
    const std::string & getAssetId() const;
    const std::string & getPracticeId() const;
    const std::string & getPracticeName() const;
    const std::vector<PracticeSection> & getPractice() const;
    const std::vector<ParametersSection> & getParameters() const;
    const std::vector<RulesTriggerSection> & getTriggers() const;

private:
    std::string context;
    std::string id;
    std::string name;
    std::vector<PracticeSection> practices;
    std::vector<ParametersSection> parameters;
    std::vector<RulesTriggerSection> triggers;
};

class RulesConfigWrapper
{
public:
    class RulesConfig
    {
    public:
        RulesConfig(const std::vector<RulesConfigRulebase> &_rules_config);

        void save(cereal::JSONOutputArchive &out_ar) const;

    private:
        static bool sortBySpecific(const RulesConfigRulebase &first, const RulesConfigRulebase &second);
        static bool sortBySpecificAux(const std::string &first, const std::string &second);

        std::vector<RulesConfigRulebase> rules_config;
    };

    RulesConfigWrapper(const std::vector<RulesConfigRulebase> &_rules_config)
        :
    rules_config_rulebase(RulesConfig(_rules_config))
    {}

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    RulesConfig rules_config_rulebase;
};
// LCOV_EXCL_STOP
#endif // __RULES_CONFIG_SECTION_H__
