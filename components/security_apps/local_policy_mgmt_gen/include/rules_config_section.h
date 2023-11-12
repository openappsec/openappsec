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
#include "local_policy_common.h"

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
        const std::string &_practice_name
    );

    void save(cereal::JSONOutputArchive &out_ar) const;

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
        const std::string &_type
    );

    void save(cereal::JSONOutputArchive &out_ar) const;

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
        const std::string &_port,
        const std::string &_uri,
        std::vector<PracticeSection> _practices,
        std::vector<ParametersSection> _parameters,
        std::vector<RulesTriggerSection> _triggers
    );

    void save(cereal::JSONOutputArchive &out_ar) const;

    const std::string & getAssetName() const;
    const std::string & getAssetId() const;
    const std::string & getContext() const;

private:
    std::string context;
    std::string id;
    std::string name;
    std::vector<PracticeSection> practices;
    std::vector<ParametersSection> parameters;
    std::vector<RulesTriggerSection> triggers;
};

class UsersIdentifier
{
public:
    UsersIdentifier() {}

    UsersIdentifier(
        const std::string &_source_identifier,
        std::vector<std::string> _identifier_values
    );

    const std::string & getIdentifier() const;

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    std::string source_identifier;
    std::vector<std::string> identifier_values;
};

class UsersIdentifiersRulebase
{
public:
    UsersIdentifiersRulebase()
    {}

    UsersIdentifiersRulebase(
        const std::string &_context,
        const std::string &_source_identifier,
        const std::vector<std::string> &_identifier_values,
        const std::vector<UsersIdentifier> &_source_identifiers
    );

    const std::string & getIdentifier() const;

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    std::string context;
    std::string source_identifier;
    std::vector<std::string> identifier_values;
    std::vector<UsersIdentifier> source_identifiers;
};

class RulesRulebase
{
public:
    RulesRulebase(
        const std::vector<RulesConfigRulebase> &_rules_config,
        const std::vector<UsersIdentifiersRulebase> &_users_identifiers
    );

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    static bool sortBySpecific(const RulesConfigRulebase &first, const RulesConfigRulebase &second);
    static bool sortBySpecificAux(const std::string &first, const std::string &second);

    std::vector<RulesConfigRulebase> rules_config;
    std::vector<UsersIdentifiersRulebase> users_identifiers;
};

class RulesConfigWrapper
{
public:
    RulesConfigWrapper(
        const std::vector<RulesConfigRulebase> &_rules_config,
        const std::vector<UsersIdentifiersRulebase> &_users_identifiers)
            :
        rules_config_rulebase(RulesRulebase(_rules_config, _users_identifiers))
    {}

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    RulesRulebase rules_config_rulebase;
};
#endif // __RULES_CONFIG_SECTION_H__
