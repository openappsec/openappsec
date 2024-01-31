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

#ifndef __PROFILE_SETTINGS_H__
#define __PROFILE_SETTINGS_H__

#include <vector>
#include <map>
#include <string>
#include <boost/algorithm/string.hpp>

class AgentProfileSettings
{
public:
    void
    load(cereal::JSONInputArchive &ar)
    {
        std::vector<SingleSetting> settings;
        cereal::load(ar, settings);

        for (const SingleSetting &setting : settings) {
            std::pair<std::string, std::string> single_setting = setting.getSetting();
            profile_settings[boost::algorithm::trim_copy(single_setting.first)] =
                boost::algorithm::trim_copy(single_setting.second);
        }
    }

    const std::map<std::string, std::string> & getSettings() const { return profile_settings; }
    static AgentProfileSettings default_profile_settings;

private:
    class SingleSetting
    {
    public:
        void
        load(cereal::JSONInputArchive &ar)
        {
            ar(
                cereal::make_nvp("key", key),
                cereal::make_nvp("value", value)
            );
        }

        std::pair<std::string, std::string> getSetting() const { return std::make_pair(key, value); }

    private:
        std::string key;
        std::string value;
    };
    std::map<std::string, std::string> profile_settings;
};

#endif // __PROFILE_SETTINGS_H__
