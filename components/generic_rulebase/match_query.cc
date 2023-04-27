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

#include "generic_rulebase/match_query.h"

#include "cereal/types/set.hpp"

#include "generic_rulebase/generic_rulebase_utils.h"
#include "config.h"
#include "ip_utilities.h"
#include "agent_core_utilities.h"

USE_DEBUG_FLAG(D_RULEBASE_CONFIG);

using namespace std;

static const unordered_map<string, MatchQuery::MatchType> string_to_match_type = {
    { "condition", MatchQuery::MatchType::Condition },
    { "operator", MatchQuery::MatchType::Operator }
};

static const unordered_map<string, MatchQuery::Operators> string_to_operator = {
    { "and", MatchQuery::Operators::And },
    { "or", MatchQuery::Operators::Or }
};

static const unordered_map<string, MatchQuery::Conditions> string_to_condition = {
    { "equals", MatchQuery::Conditions::Equals },
    { "not-equals", MatchQuery::Conditions::NotEquals },
    { "not equals", MatchQuery::Conditions::NotEquals },
    { "in", MatchQuery::Conditions::In },
    { "not-in", MatchQuery::Conditions::NotIn },
    { "not in", MatchQuery::Conditions::NotIn },
    { "exist", MatchQuery::Conditions::Exist }
};

static const string ip_addr_type_name = "IP address";
static const string port_type_name = "port";
static const string ip_proto_type_name = "IP protocol";

static const unordered_map<string, MatchQuery::StaticKeys> string_to_key = {
    { "sourceIP", MatchQuery::StaticKeys::SrcIpAddress },
    { "sourceIpAddr", MatchQuery::StaticKeys::SrcIpAddress },
    { "destinationIP", MatchQuery::StaticKeys::DstIpAddress },
    { "destinationIpAddr", MatchQuery::StaticKeys::DstIpAddress },
    { "ipAddress", MatchQuery::StaticKeys::IpAddress },
    { "sourcePort", MatchQuery::StaticKeys::SrcPort },
    { "listeningPort", MatchQuery::StaticKeys::ListeningPort },
    { "ipProtocol", MatchQuery::StaticKeys::IpProtocol },
    { "domain", MatchQuery::StaticKeys::Domain }
};

void
MatchQuery::load(cereal::JSONInputArchive &archive_in)
{
    string type_as_string;
    archive_in(cereal::make_nvp("type", type_as_string));

    string op_as_string;
    archive_in(cereal::make_nvp("op", op_as_string));

    auto maybe_type = string_to_match_type.find(type_as_string);
    if (maybe_type == string_to_match_type.end()) {
        reportConfigurationError("Illegal Zone match query type. Provided type in configuration: " + type_as_string);
    }

    type = maybe_type->second;
    switch (type) {
        case (MatchType::Condition): {
            auto maybe_condition = string_to_condition.find(op_as_string);
            if (maybe_condition == string_to_condition.end()) {
                reportConfigurationError(
                    "Illegal op provided for condition. Provided op in configuration: " +
                    op_as_string
                );
            }
            condition_type = maybe_condition->second;
            operator_type = Operators::None;
            archive_in(cereal::make_nvp("key", key));
            key_type = getKeyByName(key);
            if (key_type == StaticKeys::NotStatic) {
                if (key.rfind("containerLabels.", 0) == 0)  {
                    is_specific_label = true;
                } else {
                    is_specific_label = false;
                }
            }
            is_ignore_keyword = (key == "indicator");

            if (condition_type != Conditions::Exist) {
                archive_in(cereal::make_nvp("value", value));
                for(const auto &val: value) {
                    if (isKeyTypeIp()) {
                        auto ip_range = IPUtilities::createRangeFromString<IPRange, IpAddress>(val, ip_addr_type_name);
                        if (ip_range.ok()) {
                            ip_addr_value.push_back(ip_range.unpack());
                        } else {
                            dbgWarning(D_RULEBASE_CONFIG)
                                << "Failed to parse IP address range. Error: "
                                << ip_range.getErr();
                        }
                    } else if (isKeyTypePort()) {
                        auto port_range = IPUtilities::createRangeFromString<PortsRange, uint16_t>(
                            val,
                            port_type_name
                        );
                        if (port_range.ok()) {
                            port_value.push_back(port_range.unpack());
                        } else {
                            dbgWarning(D_RULEBASE_CONFIG)
                                << "Failed to parse port range. Error: "
                                << port_range.getErr();
                        }
                    } else if (isKeyTypeProtocol()) {
                        auto proto_range = IPUtilities::createRangeFromString<IpProtoRange, uint8_t>(
                            val,
                            ip_proto_type_name
                        );
                        if (proto_range.ok()) {
                            ip_proto_value.push_back(proto_range.unpack());
                        } else {
                            dbgWarning(D_RULEBASE_CONFIG)
                                << "Failed to parse IP protocol range. Error: "
                                << proto_range.getErr();
                        }
                    }

                    try {
                        regex_values.insert(boost::regex(val));
                    } catch (const exception &e) {
                        dbgDebug(D_RULEBASE_CONFIG) << "Failed to compile regex. Error: " << e.what();
                    }
                }
                first_value = *(value.begin());
            }
            break;
        }
        case (MatchType::Operator): {
            auto maybe_operator = string_to_operator.find(op_as_string);
            if (maybe_operator == string_to_operator.end()) {
                reportConfigurationError(
                    "Illegal op provided for operator. Provided op in configuration: " +
                    op_as_string
                );
            }
            operator_type = maybe_operator->second;
            condition_type = Conditions::None;
            archive_in(cereal::make_nvp("items", items));
            break;
        }
    }
}

MatchQuery::StaticKeys
MatchQuery::getKeyByName(const string &key_type_name)
{
    auto key = string_to_key.find(key_type_name);
    if (key == string_to_key.end()) return StaticKeys::NotStatic;
    return key->second;
}

bool
MatchQuery::isKeyTypeIp() const
{
    return (key_type >= StaticKeys::IpAddress && key_type <= StaticKeys::DstIpAddress);
}

bool
MatchQuery::isKeyTypePort() const
{
    return (key_type == StaticKeys::SrcPort || key_type == StaticKeys::ListeningPort);
}

bool
MatchQuery::isKeyTypeProtocol() const
{
    return (key_type == StaticKeys::IpProtocol);
}

bool
MatchQuery::isKeyTypeDomain() const
{
    return (key_type == StaticKeys::Domain);
}

bool
MatchQuery::isKeyTypeSpecificLabel() const
{
    return is_specific_label;
}

bool
MatchQuery::isKeyTypeStatic() const
{
    return (key_type != StaticKeys::NotStatic);
}

set<string>
MatchQuery::getAllKeys() const
{
    set<string> keys;
    if (type == MatchType::Condition) {
        if (!key.empty()) keys.insert(key);
        return keys;
    }

    for (const MatchQuery &inner_match: items) {
        set<string> iner_keys = inner_match.getAllKeys();
        keys.insert(iner_keys.begin(), iner_keys.end());
    }

    return keys;
}

bool
MatchQuery::matchAttributes(
        const unordered_map<string, set<string>> &key_value_pairs,
        set<string> &matched_override_keywords ) const
{

    if (type == MatchType::Condition) {
        auto key_value_pair = key_value_pairs.find(key);
        if (key_value_pair == key_value_pairs.end()) {
            dbgTrace(D_RULEBASE_CONFIG) << "Ignoring irrelevant key: " << key;
            return false;
        }
        return matchAttributes(key_value_pair->second, matched_override_keywords);
    } else if (type == MatchType::Operator && operator_type == Operators::And) {
        for (const MatchQuery &inner_match: items) {
            if (!inner_match.matchAttributes(key_value_pairs, matched_override_keywords)) {
                return false;
            }
        }
        return true;
    } else if (type == MatchType::Operator && operator_type == Operators::Or) {
        // With 'or' condition, evaluate matched override keywords first and add the ones that were fully matched
        set<string> inner_override_keywords;
        bool res = false;
        for (const MatchQuery &inner_match: items) {
            inner_override_keywords.clear();
            if (inner_match.matchAttributes(key_value_pairs, inner_override_keywords)) {
                matched_override_keywords.insert(inner_override_keywords.begin(), inner_override_keywords.end());
                res = true;
            }
        }
        return res;
    } else {
        dbgWarning(D_RULEBASE_CONFIG) << "Unsupported match query type";
    }
    return false;
}

MatchQuery::MatchResult
MatchQuery::getMatch( const unordered_map<string, set<string>> &key_value_pairs) const
{
    MatchQuery::MatchResult matches;
    matches.matched_keywords = make_shared<set<string>>();
    matches.is_match = matchAttributes(key_value_pairs, *matches.matched_keywords);
    return matches;
}

bool
MatchQuery::matchAttributes(
        const unordered_map<string, set<string>> &key_value_pairs) const
{
    return getMatch(key_value_pairs).is_match;
}

bool
MatchQuery::matchAttributes(
        const set<string> &values,
        set<string> &matched_override_keywords) const
{
    auto &type = condition_type;
    bool negate = type == MatchQuery::Conditions::NotEquals || type == MatchQuery::Conditions::NotIn;
    bool match = isRegEx() ? matchAttributesRegEx(values, matched_override_keywords) : matchAttributesString(values);
    return negate ? !match : match;
}

bool
MatchQuery::matchAttributesRegEx(
        const set<string> &values,
        set<string> &matched_override_keywords) const
{
    bool res = false;
    boost::cmatch value_matcher;
    for (const boost::regex &val_regex : regex_values) {
        for (const string &requested_match_value : values) {
            if (NGEN::Regex::regexMatch(
                __FILE__,
                __LINE__,
                requested_match_value.c_str(),
                value_matcher,
                val_regex))
            {
                res = true;
                if (is_ignore_keyword) {
                    matched_override_keywords.insert(requested_match_value);
                } else {
                    return res;
                }
            }
        }
    }
    return res;
}

bool
MatchQuery::matchAttributesString(const set<string> &values) const
{
    for (const string &requested_value : values) {
        if (value.find(requested_value) != value.end()) return true;
    }
    return false;
}

bool
MatchQuery::isRegEx() const
{
    return key != "protectionName";
}
