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

#ifndef __SETTINGS_SECTION_H__
#define __SETTINGS_SECTION_H__

#include <cereal/archives/json.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "config.h"
#include "debug.h"
#include "k8s_policy_common.h"

USE_DEBUG_FLAG(D_K8S_POLICY);

class AgentSettingsSection
{
public:
    AgentSettingsSection(
        const std::string &_key,
        const std::string &_value)
            :
        key(_key),
        value(_value)
    {
        try {
            id = to_string(boost::uuids::random_generator()());
        } catch (const boost::uuids::entropy_error &e) {
            dbgWarning(D_K8S_POLICY) << "Failed to generate agent setting UUID. Error: " << e.what();
        }
    }

    void
    serialize(cereal::JSONOutputArchive &out_ar) const
    {
        out_ar(
            cereal::make_nvp("id",    id),
            cereal::make_nvp("key",   key),
            cereal::make_nvp("value", value)
        );
    }

    const std::string & getSettingId() const { return id; }

private:
    std::string id;
    std::string key;
    std::string value;
};

class SettingsRulebase
{
public:
    SettingsRulebase(std::vector<AgentSettingsSection> _agentSettings) : agentSettings(_agentSettings) {}

    void
    serialize(cereal::JSONOutputArchive &out_ar) const
    {
        std::string profile_type = "Kubernetes";
        std::string upgrade_mode = "automatic";
        out_ar(
            cereal::make_nvp("agentSettings",                agentSettings),
            cereal::make_nvp("agentType",                    profile_type),
            cereal::make_nvp("allowOnlyDefinedApplications", false),
            cereal::make_nvp("anyFog",                       true),
            cereal::make_nvp("maxNumberOfAgents",            10),
            cereal::make_nvp("upgradeMode",                  upgrade_mode)
        );
    }

private:
    std::vector<AgentSettingsSection> agentSettings;
};

class SettingsWrapper
{
public:
    SettingsWrapper(SettingsRulebase _agent) : agent(_agent)
    {
        try {
            id = to_string(boost::uuids::random_generator()());
        } catch (const boost::uuids::entropy_error &e) {
            dbgWarning(D_K8S_POLICY) << "Failed to generate Settings Wrapper UUID. Error: " << e.what();
        }
    }

    void
    serialize(cereal::JSONOutputArchive &out_ar) const
    {
        out_ar(
            cereal::make_nvp("profileType", profileType),
            cereal::make_nvp("tokenType",   isToken),
            cereal::make_nvp("tokenType",   tokenType),
            cereal::make_nvp("name",        name),
            cereal::make_nvp("id",          id),
            cereal::make_nvp("agent",       agent)
        );
    }

private:
    std::string profileType = "agent";
    bool isToken = true;
    std::string tokenType = "sameToken";
    std::string id;
    std::string name = "Kubernetes Agents";
    SettingsRulebase agent;
};

#endif // __SETTINGS_SECTION_H__
