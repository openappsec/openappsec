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

#ifndef __PARAMETERS_CONFIG_H__
#define __PARAMETERS_CONFIG_H__

#include <string>
#include <vector>
#include <set>
#include <unordered_map>

#include "cereal/types/string.hpp"
#include "cereal/types/vector.hpp"
#include "cereal/archives/json.hpp"
#include "generic_rulebase/generic_rulebase_utils.h"
#include "match_query.h"
#include "maybe_res.h"
#include "config.h"

enum class BehaviorKey
{
    ACTION,
    LOG,
    SOURCE_IDENTIFIER,
    HTTP_SOURCE_ID,
    HTTPS_SOURCE_ID
};

enum class BehaviorValue
{
    REJECT,
    ACCEPT,
    IGNORE,
    DROP,
    X_FORWARDED_FOR,
    COOKIE_AOUTH2_PROXY,
    COOKIE_JSESSIONID
};

static const std::unordered_map<std::string, BehaviorKey> string_to_behavior_key = {
    { "action", BehaviorKey::ACTION },
    { "log", BehaviorKey::LOG },
    { "sourceIdentifier", BehaviorKey::SOURCE_IDENTIFIER },
    { "httpSourceId", BehaviorKey::HTTP_SOURCE_ID },
    { "httpsSourceId", BehaviorKey::HTTPS_SOURCE_ID }
};

static const std::unordered_map<std::string, BehaviorValue> string_to_behavior_val = {
    { "Cookie:_oauth2_proxy", BehaviorValue::COOKIE_AOUTH2_PROXY },
    { "Cookie:JSESSIONID", BehaviorValue::COOKIE_JSESSIONID },
    { "X-Forwarded-For", BehaviorValue::X_FORWARDED_FOR },
    { "reject", BehaviorValue::REJECT },
    { "accept", BehaviorValue::ACCEPT },
    { "ignore", BehaviorValue::IGNORE },
    { "drop", BehaviorValue::DROP }
};

class ParameterOverrides
{
public:
    class ParsedBehavior
    {
    public:
        void
        serialize(cereal::JSONInputArchive &archive_in)
        {
            parseJSONKey<std::string>("log", log, archive_in);
        }

        const std::string & getParsedBehaviorLog() const { return log; }

    private:
        std::string log;
    };

    void load(cereal::JSONInputArchive &archive_in);

    const std::vector<ParsedBehavior> & getParsedBehaviors() const { return parsed_behaviors; }

private:
    std::vector<ParsedBehavior> parsed_behaviors;
};

class ParameterTrustedSources
{
public:
    class SourcesIdentifier
    {
    public:

        SourcesIdentifier() = default;

        void
        serialize(cereal::JSONInputArchive &archive_in)
        {
            parseJSONKey<std::string>("sourceIdentifier", source_identifier, archive_in);
            parseJSONKey<std::string>("value", value, archive_in);
        }

        const std::string & getSourceIdentifier() const {return source_identifier; }

        const std::string & getValue() const {return value; }

    private:
        std::string source_identifier;
        std::string value;
    };

    void load(cereal::JSONInputArchive &archive_in);

    uint getNumOfSources() const { return num_of_sources; }

    const std::vector<SourcesIdentifier> & getSourcesIdentifiers() const { return sources_identidiers; }

private:
    uint num_of_sources;
    std::vector<SourcesIdentifier> sources_identidiers;
};

class ParameterBehavior
{
public:
    ParameterBehavior() = default;
    ParameterBehavior(BehaviorKey &_key, BehaviorValue &_value) : key(_key), value(_value) {}
    ParameterBehavior(BehaviorKey &&_key, BehaviorValue &&_value)
            :
        key(std::move(_key)),
        value(std::move(_value))
    {}

    void load(cereal::JSONInputArchive &archive_in);

    const BehaviorValue & getValue() const { return value; }

    const BehaviorKey & getKey() const { return key; }

    const std::string & getId() const { return id; }

    bool
    operator<(const ParameterBehavior &other) const {
        return (key < other.key) || (key == other.key && value < other.value);
    }

    bool operator==(const ParameterBehavior &other) const { return key == other.key && value == other.value; }

private:
    std::string id;
    BehaviorKey key;
    BehaviorValue value;
};

class ParameterAntiBot
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    std::vector<std::string> & getInjected() { return injected; }

    std::vector<std::string> & getValidated() { return validated; }

private:
    std::vector<std::string> injected;
    std::vector<std::string> validated;
};

class ParameterOAS
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const std::string & getValue() const { return value; }

private:
    std::string value;
};

class ParameterException
{
public:
    static void
    preload()
    {
        registerExpectedConfiguration<ParameterException>("rulebase", "exception");
        registerConfigLoadCb([](){ is_geo_location_exception_exists = is_geo_location_exception_being_loaded; });
        registerConfigPrepareCb([](){ is_geo_location_exception_being_loaded = false; });
    }

    void load(cereal::JSONInputArchive &archive_in);

    std::set<ParameterBehavior>
    getBehavior(const std::unordered_map<std::string, std::set<std::string>> &key_value_pairs) const;

    std::set<ParameterBehavior>
    getBehavior(
            const std::unordered_map<std::string, std::set<std::string>> &key_value_pairs,
            std::set<std::string> &matched_override_keywords) const;

    static bool isGeoLocationExceptionExists() { return is_geo_location_exception_exists; }

private:
    class MatchBehaviorPair
    {
    public:
        void load(cereal::JSONInputArchive &archive_in);
        MatchQuery match;
        ParameterBehavior behavior;
    };

    std::vector<MatchBehaviorPair> match_queries;
    MatchQuery match;
    ParameterBehavior behavior;
    static bool is_geo_location_exception_exists;
    static bool is_geo_location_exception_being_loaded;
};

static const ParameterBehavior action_ignore(BehaviorKey::ACTION, BehaviorValue::IGNORE);
static const ParameterBehavior action_accept(BehaviorKey::ACTION, BehaviorValue::ACCEPT);

#endif //__PARAMETERS_CONFIG_H__
