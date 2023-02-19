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

#ifndef __MATCH_QUERY_H__
#define __MATCH_QUERY_H__

#include <vector>
#include <string>
#include <set>
#include <map>
#include <memory>
#include <arpa/inet.h>

#include "cereal/types/string.hpp"
#include "cereal/types/vector.hpp"
#include "cereal/archives/json.hpp"

#include <boost/regex.hpp>

#include "c_common/ip_common.h"

class MatchQuery
{
public:
    enum class MatchType { Condition, Operator };
    enum class Operators { And, Or, None };
    enum class Conditions { Equals, NotEquals, In, NotIn, Exist, None };
    enum class StaticKeys
    {
        IpAddress,
        SrcIpAddress,
        DstIpAddress,
        SrcPort,
        ListeningPort,
        IpProtocol,
        Domain,
        NotStatic
    };
    struct MatchResult
    {
        bool is_match;
        std::shared_ptr<std::set<std::string>> matched_keywords;
    };

    MatchQuery(): is_specific_label(false), is_ignore_keyword(false) {}

    void load(cereal::JSONInputArchive &archive_in);

    MatchType getType() const { return type; }
    Operators getOperatorType() const { return operator_type; }
    Conditions getConditionType() const { return condition_type; }
    const std::string & getKey() const { return key; }
    const std::set<std::string> & getValue() const { return value; }
    const std::vector<IPRange> & getIpAddrValue() const { return ip_addr_value; }
    const std::vector<PortsRange> & getPortValue() const { return port_value; }
    const std::vector<IpProtoRange> & getProtoValue() const { return ip_proto_value; }
    const std::vector<MatchQuery> & getItems() const { return items; }
    std::string getFirstValue() const { return first_value; }
    MatchResult getMatch(const std::unordered_map<std::string, std::set<std::string>> &key_value_pairs) const;
    bool matchAttributes(const std::unordered_map<std::string, std::set<std::string>> &key_value_pairs) const;
    bool matchException(const std::string &behaviorKey, const std::string &behaviorValue) const;
    bool isKeyTypeIp() const;
    bool isKeyTypePort() const;
    bool isKeyTypeProtocol() const;
    bool isKeyTypeDomain() const;
    bool isKeyTypeSpecificLabel() const;
    bool isKeyTypeStatic() const;
    std::set<std::string> getAllKeys() const;

private:
    bool matchAttributes(
            const std::unordered_map<std::string, std::set<std::string>> &key_value_pairs,
            std::set<std::string> &matched_override_keywords) const;
    StaticKeys getKeyByName(const std::string &key_type_name);
    bool matchAttributes(const std::set<std::string> &values,
            std::set<std::string> &matched_override_keywords) const;
    bool matchAttributesRegEx(const std::set<std::string> &values,
            std::set<std::string> &matched_override_keywords) const;
    bool matchAttributesString(const std::set<std::string> &values) const;
    bool isRegEx() const;

    MatchType type;
    Operators operator_type;
    Conditions condition_type;
    std::string key;
    StaticKeys key_type;
    bool is_specific_label;
    std::string first_value;
    std::set<std::string> value;
    std::set<boost::regex> regex_values;
    std::vector<IPRange> ip_addr_value;
    std::vector<PortsRange> port_value;
    std::vector<IpProtoRange> ip_proto_value;
    std::vector<MatchQuery> items;
    bool is_ignore_keyword;
};

#endif // __MATCH_QUERY_H__
