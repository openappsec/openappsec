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

#pragma once

#include "lru_cache_map.h"
#include "RateLimiter.h"
#include <string>
#include <chrono>
#include <cereal/types/vector.hpp>
#include <cereal/types/unordered_map.hpp>
#include <cereal/archives/json.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/regex.hpp>
#include <memory>

class Waf2Transaction;

namespace Waap {
namespace RateLimiting {

struct Policy {
    struct Rule {
        struct UriFilter {
            enum class GroupBy {
                GLOBAL,
                URL
            };

            enum class Scope {
                ALL,
                SPECIFIC
            };

            // Deserialize the Type enum
            Scope strScopeToEnum(std::string const &value)
            {
                if (boost::iequals(value, "all")) {
                    return Scope::ALL;
                }
                else if (boost::iequals(value, "specific")) {
                    return Scope::SPECIFIC;
                }
                else {
                    throw cereal::Exception(
                        "Invalid value for RateLimiting::Policy::Rule::SourceFilter::GroupBy='" + value + "'");
                }
            }

            // Deserialize the Type enum
            GroupBy strGroupByToEnum(std::string const &value)
            {
                if (boost::iequals(value, "all uris")) {
                    return GroupBy::GLOBAL;
                }
                else if (boost::iequals(value, "single uri")) {
                    return GroupBy::URL;
                }
                else {
                    throw cereal::Exception(
                        "Invalid value for RateLimiting::Policy::Rule::SourceFilter::GroupBy='" + value + "'");
                }
            }

            template <typename _A>
            void serialize(_A &ar)
            {
                std::string groupByStr;
                ar(cereal::make_nvp("groupBy", groupByStr));
                groupBy = strGroupByToEnum(groupByStr);
                std::string scopeStr;
                ar(cereal::make_nvp("scope", scopeStr));
                scope = strScopeToEnum(scopeStr);

                if(scope == Scope::SPECIFIC)
                {
                    ar(cereal::make_nvp("specific_uris", specific_uri_regexes_pattern));
                    specific_uri_regexes.clear();

                    for (auto &specific_uri_pattern : specific_uri_regexes_pattern)
                    {
                        specific_uri_regexes.push_back(std::make_shared<boost::regex>(specific_uri_pattern));
                    }
                }
            }

            bool operator==(const Policy::Rule::UriFilter &other) const;

            GroupBy groupBy;
            std::vector<std::shared_ptr<boost::regex>> specific_uri_regexes;
            std::vector<std::string> specific_uri_regexes_pattern;
            Scope scope;
        };

        struct SourceFilter {
            enum class GroupBy {
                GLOBAL,
                SOURCE
            };

            enum class Scope {
                ALL,
                SPECIFIC
            };

            // Deserialize the Type enum
            Scope strScopeToEnum(std::string const &value)
            {
                if (boost::iequals(value, "all")) {
                    return Scope::ALL;
                }
                else if (boost::iequals(value, "specific")) {
                    return Scope::SPECIFIC;
                }
                else {
                    throw cereal::Exception(
                        "Invalid value for RateLimiting::Policy::Rule::SourceFilter::GroupBy='" + value + "'");
                }
            }

            // Deserialize the Type enum
            GroupBy strToEnum(std::string const &value)
            {
                if (boost::iequals(value, "all sources")) {
                    return GroupBy::GLOBAL;
                }
                else if (boost::iequals(value, "single source")) {
                    return GroupBy::SOURCE;
                }
                else {
                    throw cereal::Exception(
                        "Invalid value for RateLimiting::Policy::Rule::SourceFilter::GroupBy='" + value + "'");
                }
            }

            template <typename _A>
            void serialize(_A &ar) {
                std::string groupByStr;
                ar(cereal::make_nvp("groupBy", groupByStr));
                groupBy = strToEnum(groupByStr);

                std::string scopeStr;
                ar(cereal::make_nvp("scope", scopeStr));
                scope = strScopeToEnum(scopeStr);

                if(scope == Scope::SPECIFIC)
                {
                    ar(cereal::make_nvp("specific_sources", specific_source_regexes_pattern));
                    specific_source_regexes.clear();

                    for (auto &specific_source_pattern : specific_source_regexes_pattern) {
                        specific_source_regexes.push_back(std::make_shared<boost::regex>(specific_source_pattern));
                    }
                }
            }

            bool operator==(const Policy::Rule::SourceFilter &other) const;

            GroupBy groupBy;
            std::vector<std::shared_ptr<boost::regex>> specific_source_regexes;
            std::vector<std::string> specific_source_regexes_pattern;
            Scope scope;
        };

        struct Rate {
            template <typename _A>
            void serialize(_A &ar) {
                ar(cereal::make_nvp("interval", interval));
                ar(cereal::make_nvp("events", events));
            }

            bool operator==(const Policy::Rule::Rate &other) const;

            unsigned interval; // Interval in seconds
            unsigned events;   // Events allowed during the interval
        };

        struct Action {
            enum class Type {
                DETECT,
                QUARANTINE,
                RATE_LIMIT
            };

            // Deserialize the Type enum
            Type strToEnum(std::string const &value)
            {
                if (boost::iequals(value, "detect")) {
                    return Type::DETECT;
                }
                else if (boost::iequals(value, "quarantine")) {
                    return Type::QUARANTINE;
                }
                else if (boost::iequals(value, "rate limit")) {
                    return  Type::RATE_LIMIT;
                }
                else {
                    throw cereal::Exception(
                        "Invalid value for RateLimiting::Policy::Action::Type='" + value + "'");
                }
            }

            template <typename _A>
            void serialize(_A &ar) {
                std::string typeStr;
                ar(cereal::make_nvp("type", typeStr));
                type = strToEnum(typeStr);
                quarantineTimeSeconds = 0;
                if (type == Type::QUARANTINE) {
                    ar(cereal::make_nvp("quarantineTimeSeconds", quarantineTimeSeconds));
                }
            }

            bool operator==(const Policy::Rule::Action &other) const;

            Type type;
            unsigned quarantineTimeSeconds; // time to block (in seconds), relevant only for QUARANTINE action type
        };

        template <typename _A>
        void serialize(_A &ar) {
            ar(cereal::make_nvp("uriFilter", uriFilter));
            ar(cereal::make_nvp("sourceFilter", sourceFilter));
            ar(cereal::make_nvp("rate", rate));
            ar(cereal::make_nvp("action", action));
        }

        bool operator==(const Rule &other) const;

        UriFilter uriFilter;
        SourceFilter sourceFilter;
        Rate rate;
        Action action;
    };

    class RateLimitingEnforcement
    {
    public:
        RateLimitingEnforcement()
        :
        enable(false)
        {
        }

        template <typename _A>
        RateLimitingEnforcement(_A &ar)
        :
        enable(false)
        {
            std::string level;
            ar(cereal::make_nvp("rateLimitingEnforcement", level));
            level = boost::algorithm::to_lower_copy(level);
            if (level == "prevent") {
                enable = true;
            }
        }

        bool operator==(const Policy::RateLimitingEnforcement &other) const;

        bool enable;
    };

    std::vector<Rule> rules;
    RateLimitingEnforcement m_rateLimiting;

    Policy() {}

    bool getRateLimitingEnforcementStatus();
    bool operator==(const Policy &other) const;

    template <typename _A>
    Policy(_A& ar) : m_rateLimiting(ar) {
        ar(cereal::make_nvp("rateLimiting", rules));
    }

};

// Key used to identify specific rate limiting entry
struct EntryKey {
    std::string url;
    std::string source;
    // comparison operator should be implemented to use this struct as a key in an LRU cache.
    bool operator==(EntryKey const& other) const;
};

// Support efficient hashing for the EntryKey struct so it can participate in unordered (hashed) containers such as LRU
inline std::size_t hash_value(EntryKey const &entryKey)
{
    std::size_t hash = 0;
    boost::hash_combine(hash, entryKey.url);
    boost::hash_combine(hash, entryKey.source);
    return hash;
}

// Rate limiting tracking entry
struct TrackEntry {
    enum State {
        MEASURING,
        QUARANTINED
    };
    Waap::Util::RateLimiter eventRateLimiter;
    State state;
    std::chrono::seconds quarantinedUntil;
    TrackEntry(unsigned int events, std::chrono::seconds interval);
    bool event(std::chrono::seconds now);
    void quarantineUntil(std::chrono::seconds until);
    bool isBlocked() const;
};

// Rate limiting state maintained per asset
class State {
    public:
        typedef LruCacheMap<EntryKey, std::shared_ptr<TrackEntry>> EntriesLru;
        const std::shared_ptr<Policy> policy;
        // For each rule - hold corresponding tracking state (EntriesLru) instance
        std::vector<std::shared_ptr<EntriesLru>> perRuleTrackingTable;
        State(const std::shared_ptr<Policy> &policy);
        bool execute(
            const std::string& sourceIdentifier,
            const std::string& uriStr,
            std::chrono::seconds now,
            bool& log);
};

}
}
