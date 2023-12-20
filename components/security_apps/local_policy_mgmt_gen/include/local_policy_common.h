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

#ifndef __LOCAL_POLICY_COMMON_H__
#define __LOCAL_POLICY_COMMON_H__

#include <map>
#include <set>
#include <string>
#include <cereal/archives/json.hpp>

#include "config.h"
#include "debug.h"
#include "rest.h"
#include "cereal/archives/json.hpp"
#include <cereal/types/map.hpp>
#include "customized_cereal_map.h"

USE_DEBUG_FLAG(D_LOCAL_POLICY);

enum class PracticeType { WebApplication, WebAPI, RateLimit };
enum class TriggerType { Log, WebUserResponse };
enum class MatchType { Condition, Operator };

static const std::unordered_map<std::string, MatchType> string_to_match_type = {
    { "condition", MatchType::Condition },
    { "operator", MatchType::Operator }
};

static const std::unordered_map<std::string, PracticeType> string_to_practice_type = {
    { "WebApplication", PracticeType::WebApplication },
    { "WebAPI", PracticeType::WebAPI },
    { "RateLimit", PracticeType::RateLimit }
};

static const std::unordered_map<std::string, TriggerType> string_to_trigger_type = {
    { "log", TriggerType::Log },
    { "WebUserResponse", TriggerType::WebUserResponse }
};

static const std::unordered_map<std::string, std::string> key_to_practices_val = {
    { "prevent-learn", "Prevent"},
    { "detect-learn", "Learn"},
    { "prevent", "Prevent"},
    { "detect", "Detect"},
    { "inactive", "Inactive"}
};

static const std::unordered_map<std::string, std::string> key_to_practices_val2 = {
    { "prevent-learn", "Prevent"},
    { "detect-learn", "Learn"},
    { "prevent", "Prevent"},
    { "detect", "Detect"},
    { "inactive", "Disabled"}
};

static const std::string default_appsec_url = "http://*:*";

template <typename T>
void
parseAppsecJSONKey(
    const std::string &key_name,
    T &value,
    cereal::JSONInputArchive &archive_in,
    const T &default_value = T())
{
    try {
        archive_in(cereal::make_nvp(key_name, value));
    } catch (const cereal::Exception &e) {
        archive_in.setNextName(nullptr);
        value = default_value;
        dbgDebug(D_LOCAL_POLICY)
            << "Could not parse the required key. Key: \""
            << key_name
            << "\", Error: "
            << e.what();
    }
}

class AppsecSpecParserMetaData
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_LOCAL_POLICY) << "AppsecSpecParserMetaData load";
        parseAppsecJSONKey<std::map<std::string, std::string>>("annotations", annotations, archive_in);
    }

    const std::map<std::string, std::string> &
    getAnnotations() const
    {
        return annotations;
    }

private:
    std::map<std::string, std::string> annotations;
};

template <typename T>
class AppsecSpecParser : public ClientRest
{
public:
    AppsecSpecParser() = default;
    AppsecSpecParser(const T &_spec) : spec(_spec) {}

    bool
    loadJson(const std::string &json)
    {
        std::string modified_json = json;
        modified_json.pop_back();
        std::stringstream ss;
        ss.str(modified_json);
        try {
            cereal::JSONInputArchive in_ar(ss);
            in_ar(cereal::make_nvp("spec", spec));
            in_ar(cereal::make_nvp("metadata", meta_data));
        } catch (cereal::Exception &e) {
            dbgWarning(D_LOCAL_POLICY) << "Failed to load spec JSON. Error: " << e.what();
            return false;
        }
        return true;
    }

    void
    setName(const std::string &_name)
    {
        spec.setName(_name);
    }

    const AppsecSpecParserMetaData &
    getMetaData() const
    {
        return meta_data;
    }

    const T & getSpec() const { return spec; }

private:
    T spec;
    AppsecSpecParserMetaData meta_data;
};

#endif // __LOCAL_POLICY_COMMON_H__
