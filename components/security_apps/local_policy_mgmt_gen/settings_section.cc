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

#include "settings_section.h"

using namespace std;

USE_DEBUG_FLAG(D_LOCAL_POLICY);
// LCOV_EXCL_START Reason: no test exist

AgentSettingsSection::AgentSettingsSection(
    const string &_key,
    const string &_value)
        :
    key(_key),
    value(_value)
{
    try {
        id = to_string(boost::uuids::random_generator()());
    } catch (const boost::uuids::entropy_error &e) {
        dbgWarning(D_LOCAL_POLICY) << "Failed to generate agent setting UUID. Error: " << e.what();
    }
}

void
AgentSettingsSection::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("id",    id),
        cereal::make_nvp("key",   key),
        cereal::make_nvp("value", value)
    );
}

const string &
AgentSettingsSection::getSettingId() const
{
    return id;
}

void
SettingsRulebase::save(cereal::JSONOutputArchive &out_ar) const
{
    string profile_type = "Kubernetes";
    string upgrade_mode = "automatic";
    out_ar(
        cereal::make_nvp("agentSettings",                agentSettings),
        cereal::make_nvp("agentType",                    profile_type),
        cereal::make_nvp("allowOnlyDefinedApplications", false),
        cereal::make_nvp("anyFog",                       true),
        cereal::make_nvp("maxNumberOfAgents",            10),
        cereal::make_nvp("upgradeMode",                  upgrade_mode)
    );
}

SettingsWrapper::SettingsWrapper(SettingsRulebase _agent) : agent(_agent)
{
    try {
        id = to_string(boost::uuids::random_generator()());
    } catch (const boost::uuids::entropy_error &e) {
        dbgWarning(D_LOCAL_POLICY) << "Failed to generate Settings Wrapper UUID. Error: " << e.what();
    }
}

void
SettingsWrapper::save(cereal::JSONOutputArchive &out_ar) const
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
// LCOV_EXCL_STOP
