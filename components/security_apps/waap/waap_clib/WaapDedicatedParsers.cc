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

#include "WaapDedicatedParsers.h"
#include <algorithm>

USE_DEBUG_FLAG(D_WAAP_PARSER);

namespace Waap {
namespace DedicatedParsers {

// ============================================================================
// Utility Functions
// ============================================================================

ParserType stringToParserType(const std::string& typeStr)
{
    std::string lower = to_lower_copy(typeStr);

    if (lower == "json") return ParserType::JSON;
    if (lower == "xml") return ParserType::XML;
    if (lower == "graphql") return ParserType::GRAPHQL;
    if (lower == "html") return ParserType::HTML;
    if (lower == "default") return ParserType::DEFAULT_SPECIAL;

    dbgTrace(D_WAAP_PARSER) << "Unknown dedicated parser type: " << typeStr;
    return ParserType::UNKNOWN;
}

std::string parserTypeToString(ParserType type)
{
    switch (type) {
        case ParserType::JSON: return "json";
        case ParserType::XML: return "xml";
        case ParserType::GRAPHQL: return "graphql";
        case ParserType::HTML: return "html";
        case ParserType::DEFAULT_SPECIAL: return "default";
        default: return "unknown";
    }
}

// Anchor a pattern for full-string matching: ^(?:pattern)$
static std::string anchorPattern(const std::string& pattern)
{
    return "^(?:" + pattern + ")$";
}

// ============================================================================
// ParserMatch Implementation
// ============================================================================

ParserMatch::ParserMatch():
    m_parameterName(""),
    m_uri(""),
    m_locationStr(""),
    m_method(""),
    m_initialized(false),
    m_isValid(true)
{
}

bool ParserMatch::operator==(const ParserMatch& other) const
{
    return m_parameterName == other.m_parameterName &&
        m_uri == other.m_uri &&
        m_locationStr == other.m_locationStr &&
        m_method == other.m_method;
}

void ParserMatch::initialize()
{
    if (m_initialized) return;

    m_isValid = true;

    {
        bool error = false;
        m_paramRegex = std::make_shared<SingleRegex>(
            anchorPattern(m_parameterName), error, "dedicated_param_" + m_parameterName);
        if (error) {
            dbgWarning(D_WAAP_PARSER)
                << "Invalid parameter name pattern: "
                << m_parameterName;
            m_paramRegex.reset();
            m_isValid = false;
        } else {
            dbgTrace(D_WAAP_PARSER)
                << "Compiled parameter name pattern: "
                << m_parameterName;
        }
    }

    if (!m_uri.empty()) {
        bool error = false;
        m_uriRegex = std::make_shared<SingleRegex>(
            anchorPattern(m_uri), error, "dedicated_uri_" + m_uri);
        if (error) {
            dbgInfo(D_WAAP_PARSER)
                << "Invalid URI pattern: "
                << m_uri;
            m_uriRegex.reset();
            m_isValid = false;
        } else {
            dbgTrace(D_WAAP_PARSER)
                << "Compiled URI pattern: "
                << m_uri;
        }
    }

    m_initialized = true;

    dbgTrace(D_WAAP_PARSER)
        << "ParserMatch initialized: param="
        << m_parameterName
        << ", uri="
        << m_uri
        << ", location="
        << m_locationStr
        << ", method="
        << m_method
        << ", valid="
        << m_isValid;
}

bool ParserMatch::match(
    const std::string& paramName,
    const std::string& uri,
    const std::string& location,
    const std::string& method) const
{
    // Check location (caller always passes lowercase location label)
    if (!m_locationStr.empty()) {
        if (location != to_lower_copy(m_locationStr)) {
            return false;
        }
    }

    // Check method (caller always passes uppercase via getMethod())
    if (!m_method.empty()) {
        if (method != to_upper_copy(m_method)) {
            return false;
        }
    }

    // Check parameter name
    if (m_paramRegex) {
        if (!m_paramRegex->hasMatch(paramName)) {
            return false;
        }
    } else if (!m_parameterName.empty() && m_parameterName != paramName) {
        return false;
    }

    // Check URI (empty m_uri = match any URI)
    if (m_uri.empty()) {
        // No URI specified or empty - matches any URI
    } else if (m_uriRegex) {
        if (!m_uriRegex->hasMatch(uri)) {
            return false;
        }
    } else if (m_uri != uri) {
        return false;
    }

    return true;
}

// ============================================================================
// ParserRule Implementation
// ============================================================================

ParserRule::ParserRule():
    m_id(""),
    m_name(""),
    m_parserTypeStr(""),
    m_parserType(ParserType::UNKNOWN),
    m_isValid(true)
{
}

bool ParserRule::operator==(const ParserRule& other) const
{
    return m_id == other.m_id &&
        m_name == other.m_name &&
        m_parserTypeStr == other.m_parserTypeStr &&
        m_match == other.m_match;
}

void ParserRule::initialize()
{
    m_parserType = stringToParserType(m_parserTypeStr);
    m_match.initialize();

    m_isValid = (m_parserType != ParserType::UNKNOWN) && m_match.isValid();

    if (!m_isValid) {
        dbgWarning(D_WAAP_PARSER)
            << "Invalid dedicated parser rule: id="
            << m_id
            << ", parserType="
            << m_parserTypeStr;
    }

    dbgTrace(D_WAAP_PARSER)
        << "ParserRule initialized: id="
        << m_id
        << ", name="
        << m_name
        << ", parserType="
        << m_parserTypeStr
        << ", valid="
        << m_isValid;
}

bool ParserRule::match(
    const std::string& paramName,
    const std::string& uri,
    const std::string& location,
    const std::string& method) const
{
    return m_match.match(paramName, uri, location, method);
}

// ============================================================================
// LookupKey Implementation (removed - all matching is now regex-based)
// ============================================================================

// ============================================================================
// DedicatedParsersConfig Implementation
// ============================================================================

DedicatedParsersConfig::DedicatedParsersConfig()
    : m_initialized(false)
{
}

bool DedicatedParsersConfig::operator==(const DedicatedParsersConfig& other) const
{
    if (m_rules.size() != other.m_rules.size()) {
        return false;
    }

    for (size_t i = 0; i < m_rules.size(); ++i) {
        if (!(m_rules[i] == other.m_rules[i])) {
            return false;
        }
    }

    return true;
}

void DedicatedParsersConfig::initialize()
{
    m_validRules.clear();
    m_ruleIndexById.clear();

    size_t validRules = 0;

    for (size_t i = 0; i < m_rules.size(); ++i) {
        ParserRule& rule = m_rules[i];
        rule.initialize();

        if (!rule.isValid()) {
            dbgInfo(D_WAAP_PARSER)
                << "Skipping invalid dedicated parser rule: "
                << rule.getId();
            continue;
        }

        validRules++;

        // Build ID index
        m_ruleIndexById[rule.getId()] = i;

        m_validRules.push_back(&rule);
    }

    m_initialized = true;

    dbgInfo(D_WAAP_PARSER)
        << "DedicatedParsersConfig initialized: "
        << m_rules.size()
        << " total rules, "
        << validRules
        << " valid";
}

Maybe<ParserType> DedicatedParsersConfig::getParserType(
    const std::string& paramName,
    const std::string& uri,
    const std::string& location,
    const std::string& method) const
{
    if (m_rules.empty()) {
        return genError("No dedicated parser rules configured");
    }

    for (const ParserRule* rule : m_validRules) {
        if (rule->match(paramName, uri, location, method)) {
            dbgTrace(D_WAAP_PARSER)
                << "Dedicated parser match found: rule="
                << rule->getId()
                << ", type="
                << rule->getParserTypeStr();
            return rule->getParserType();
        }
    }

    return genError("No matching dedicated parser rule");
}

Maybe<std::string> DedicatedParsersConfig::getParserTypeStr(
    const std::string& paramName,
    const std::string& uri,
    const std::string& location,
    const std::string& method) const
{
    auto result = getParserType(paramName, uri, location, method);
    if (result.ok()) {
        return parserTypeToString(result.unpack());
    }
    return genError(result.getErr());
}

Maybe<const ParserRule*> DedicatedParsersConfig::getRuleById(const std::string& id) const
{
    auto it = m_ruleIndexById.find(id);
    if (it != m_ruleIndexById.end()) {
        return &m_rules[it->second];
    }
    return genError("Rule not found: " + id);
}

}  // namespace DedicatedParsers
}  // namespace Waap
