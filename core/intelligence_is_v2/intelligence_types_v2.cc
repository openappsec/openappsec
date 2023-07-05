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

#include "intelligence_is_v2/intelligence_types_v2.h"

using namespace std;
using namespace Intelligence_IS_V2;

struct EnumClassHash
{
    template <typename T>
    std::size_t operator()(T t) const
    {
        return static_cast<std::size_t>(t);
    }
};

const string &
Intelligence_IS_V2::convertConditionTypeToString(const Condition &condition_type)
{
    static const unordered_map<Condition, string, EnumClassHash> condition_type_to_string_map = {
        {Condition::EQUALS, "equals"},
        {Condition::NOT_EQUALS, "notEquals"},
        {Condition::MATCH, "match"},
        {Condition::STARTS_WITH, "startsWith"},
        {Condition::CONTAINS, "contains"},
        {Condition::IN, "in"},
        {Condition::NOT_IN, "notIn"},
        {Condition::GREATER_THAN, "greaterThan"},
        {Condition::LESS_THAN, "lessThan"},
    };

    auto condition_str = condition_type_to_string_map.find(condition_type);
    if (condition_str != condition_type_to_string_map.end()) {
        return condition_str->second;
    }

    throw IntelligenceException("Received illegal Condition Type.");
}

const string &
Intelligence_IS_V2::convertOperationTypeToString(const Operator &operation_type)
{
    static const unordered_map<Operator, string, EnumClassHash> operation_type_to_string_map = {
        {Operator::AND, "and"},
        {Operator::OR, "or"}
    };

    if (operation_type_to_string_map.find(operation_type) != operation_type_to_string_map.end()) {
        return operation_type_to_string_map.at(operation_type);
    }

    if (operation_type == Operator::NONE) throw IntelligenceException("Received illegal \'NONE\' operation Type.");
    throw IntelligenceException("Received illegal Operation Type.");
}

string
Intelligence_IS_V2::createAttributeString(const string &key, AttributeKeyType attribute_type)
{
    string attribute_string;
    switch (attribute_type) {
        case AttributeKeyType::MAIN:
            attribute_string = "mainAttributes." + key;
            return attribute_string;
        case AttributeKeyType::REGULAR:
            attribute_string = "attributes." + key;
            return attribute_string;
        case AttributeKeyType::NONE:
            attribute_string = key;
            return attribute_string;
    }

    throw IntelligenceException("Received illegal Attribute Type.");
    return attribute_string;
}

ResponseStatus
Intelligence_IS_V2::convertStringToResponseStatus(const string &status)
{
    if (status == "done") return ResponseStatus::DONE;
    if (status == "inProgress")  return ResponseStatus::IN_PROGRESS;
    throw IntelligenceException("Received illegal Response Status. Status: " + status);
}
