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

#ifndef __SNORT_SECTION_H__
#define __SNORT_SECTION_H__

#include <cereal/archives/json.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "config.h"
#include "debug.h"

// LCOV_EXCL_START Reason: no test exist
class AgentSettingsSection
{
public:
    AgentSettingsSection(std::string _key, std::string _value);

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    std::string id;
    std::string key;
    std::string value;
};

class IpsSnortSigsRulebase
{
public:
    IpsSnortSigsRulebase(std::vector<AgentSettingsSection> _agentSettings) : agentSettings(_agentSettings) {}

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    std::vector<AgentSettingsSection> agentSettings;
};
// LCOV_EXCL_STOP
#endif // __SNORT_SECTION_H__
