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
#ifndef __WAAP_DEDICATED_PARSERS_H__
#define __WAAP_DEDICATED_PARSERS_H__

#include <string>
#include <vector>
#include <unordered_map>
#include <set>
#include <memory>
#include <cereal/types/vector.hpp>
#include <cereal/types/string.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include "debug.h"
#include "maybe_res.h"
#include "Waf2Regex.h"

namespace Waap {
namespace DedicatedParsers {

using boost::algorithm::to_lower_copy;
using boost::algorithm::to_upper_copy;

// Supported parser types that can be explicitly assigned to parameters
enum class ParserType {
    UNKNOWN,
    JSON,
    XML,
    GRAPHQL,
    HTML,
    DEFAULT_SPECIAL
};

// Convert string to ParserType enum
ParserType stringToParserType(const std::string& typeStr);

// Convert ParserType enum to string
std::string parserTypeToString(ParserType type);

// Match condition for a dedicated parser rule
// Specifies which parameters should use a dedicated parser
class ParserMatch {
public:
    ParserMatch();

    bool operator==(const ParserMatch& other) const;

    template <typename _A>
    void serialize(_A& ar) {
        ar(cereal::make_nvp("parameterName", m_parameterName));
        ar(cereal::make_nvp("location", m_locationStr));

        // Optional uri field - if not present or empty, matches any URI
        try {
            ar(cereal::make_nvp("uri", m_uri));
        } catch (const std::runtime_error&) {
            ar.setNextName(nullptr);
            m_uri = "";
        }

        // Optional method field - if not present, matches any method
        try {
            ar(cereal::make_nvp("method", m_method));
        } catch (const std::runtime_error&) {
            ar.setNextName(nullptr);
            m_method = "";
        }
    }

    // Initialize after deserialization - compiles regex patterns
    void initialize();

    // Check if request context matches this rule
    bool match(
        const std::string& paramName,
        const std::string& uri,
        const std::string& location,
        const std::string& method) const;

    // Accessors
    const std::string& getParameterName() const { return m_parameterName; }
    const std::string& getUri() const { return m_uri; }
    const std::string& getLocation() const { return m_locationStr; }
    const std::string& getMethod() const { return m_method; }
    bool isValid() const { return m_isValid; }

private:
    std::string m_parameterName;
    std::string m_uri;
    std::string m_locationStr;
    std::string m_method;

    // Compiled state
    bool m_initialized;
    bool m_isValid;
    std::shared_ptr<SingleRegex> m_paramRegex;
    std::shared_ptr<SingleRegex> m_uriRegex;
};

// Single dedicated parser rule
// Associates a match condition with a specific parser type
class ParserRule {
public:
    ParserRule();

    bool operator==(const ParserRule& other) const;

    template <typename _A>
    void serialize(_A& ar) {
        ar(cereal::make_nvp("id", m_id));
        ar(cereal::make_nvp("parserType", m_parserTypeStr));
        ar(cereal::make_nvp("match", m_match));

        // Optional name/description
        try {
            ar(cereal::make_nvp("name", m_name));
        } catch (const std::runtime_error&) {
            ar.setNextName(nullptr);
            m_name = "";
        }
    }

    // Initialize after deserialization
    void initialize();

    // Check if this rule matches the given context
    bool match(
        const std::string& paramName,
        const std::string& uri,
        const std::string& location,
        const std::string& method) const;

    // Accessors
    const std::string& getId() const { return m_id; }
    const std::string& getName() const { return m_name; }
    const std::string& getParserTypeStr() const { return m_parserTypeStr; }
    ParserType getParserType() const { return m_parserType; }
    const ParserMatch& getMatch() const { return m_match; }
    bool isValid() const { return m_isValid && m_match.isValid(); }

private:
    std::string m_id;
    std::string m_name;
    std::string m_parserTypeStr;
    ParserType m_parserType;
    ParserMatch m_match;
    bool m_isValid;
};

// Main configuration class holding all dedicated parser rules for an asset
// Provides efficient lookup of parser type for given request context
class DedicatedParsersConfig {
public:
    DedicatedParsersConfig();

    bool operator==(const DedicatedParsersConfig& other) const;
    bool operator!=(const DedicatedParsersConfig& other) const { return !(*this == other); }

    template <typename _A>
    void serialize(_A& ar) {
        ar(cereal::make_nvp("rules", m_rules));
    }

    // Initialize after deserialization - compiles regex patterns
    void initialize();

    // Find parser type for given request context
    // Returns genError if no matching rule found
    Maybe<ParserType> getParserType(
        const std::string& paramName,
        const std::string& uri,
        const std::string& location,
        const std::string& method) const;

    // String version for convenience
    Maybe<std::string> getParserTypeStr(
        const std::string& paramName,
        const std::string& uri,
        const std::string& location,
        const std::string& method) const;

    // Check if any rules are configured
    bool empty() const { return m_rules.empty(); }
    size_t size() const { return m_rules.size(); }

    // Get all rules (for debugging/logging)
    const std::vector<ParserRule>& getRules() const { return m_rules; }

    // Get rule by ID
    Maybe<const ParserRule*> getRuleById(const std::string& id) const;

private:
    std::vector<ParserRule> m_rules;

    // Valid rules in initialization order (O(n) lookup)
    std::vector<const ParserRule*> m_validRules;

    // Index by ID for fast lookup
    std::unordered_map<std::string, size_t> m_ruleIndexById;

    bool m_initialized;
};

}  // namespace DedicatedParsers
}  // namespace Waap

#endif  // __WAAP_DEDICATED_PARSERS_H__
