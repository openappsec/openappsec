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

#include "intelligence_is_v2/query_filter_v2.h"
#include "intelligence_is_v2/intelligence_types_v2.h"

#include "cereal/archives/json.hpp"
#include "cereal/types/string.hpp"
#include "debug.h"

using namespace std;
using namespace Intelligence_IS_V2;

USE_DEBUG_FLAG(D_INTELLIGENCE);

void
SerializableQueryCondition::save(cereal::JSONOutputArchive &ar) const
{
    ar(
        cereal::make_nvp("operator", string(convertConditionTypeToString(condition_type))),
        cereal::make_nvp("key", key),
        cereal::make_nvp("value", value)
    );
}

SerializableQueryFilter::SerializableQueryFilter(Condition condition_type, const string &key, const string &value)
{
    condition_operands.push_back(SerializableQueryCondition(condition_type, key, value));
}

void
SerializableQueryFilter::save(cereal::JSONOutputArchive &ar) const
{
    if (operator_type == Operator::NONE) {
        saveCondition(ar);
    } else {
        saveOperation(ar);
    }
}

void
SerializableQueryFilter::addCondition(Condition condition_type, const string &key, const string &value)
{
    if (queries_operands.size() > 0) {
        SerializableQueryFilter new_query_filter(condition_type, key, value);
        queries_operands.push_back(new_query_filter);
        return;
    }
    if (condition_operands.size() == 1 && operator_type == Operator::NONE) {
        operator_type = Operator::AND;
    }
    SerializableQueryCondition cond(condition_type, key, value);
    condition_operands.push_back(cond);
}

void
SerializableQueryFilter::saveCondition(cereal::JSONOutputArchive &ar) const
{
    SerializableQueryCondition cond = *condition_operands.begin();
    Condition condition_type = cond.getConditionType();
    string condition_str = convertConditionTypeToString(condition_type);
    string filter_key = cond.getKey();
    string filter_value = cond.getValue();

    ar(
        cereal::make_nvp("operator", condition_str),
        cereal::make_nvp("key", filter_key),
        cereal::make_nvp("value", filter_value)
    );
}

void
SerializableQueryFilter::saveOperation(cereal::JSONOutputArchive &ar) const
{
    string operator_str = convertOperationTypeToString(operator_type);

    if (condition_operands.size() > 0) {
        ar(
            cereal::make_nvp("operator", operator_str),
            cereal::make_nvp("operands", condition_operands)
        );
    } else if (queries_operands.size() == 1) {
        queries_operands[0].saveCondition(ar);
    } else if (queries_operands.size() > 0) {
        ar(
            cereal::make_nvp("operator", operator_str),
            cereal::make_nvp("operands", queries_operands)
        );
    } else {
        dbgWarning(D_INTELLIGENCE) << "No conditions or queries to save";
    }
}

const string &
SerializableQueryFilter::getConditionValueByKey(const string &key) const
{
    for (const SerializableQueryCondition &condition : condition_operands) {
        if (condition.getConditionType() == Condition::EQUALS && condition.getKey() == key) {
            return condition.getValue();
        }
    }

    static string empty_str = "";
    return empty_str;
}

SerializableQueryFilter
SerializableQueryFilter::calcOperator(const SerializableQueryFilter &other_query, const Operator &operator_type)
{
    SerializableQueryFilter query_filter_res;
    vector<SerializableQueryFilter> new_queries_operands;

    new_queries_operands.push_back(*this);
    new_queries_operands.push_back(other_query);

    query_filter_res.queries_operands = new_queries_operands;
    query_filter_res.operator_type = operator_type;
    return query_filter_res;
}

SerializableQueryFilter
SerializableQueryFilter::operator &&(const SerializableQueryFilter &other_query)
{
    return calcOperator(other_query, Operator::AND);
}

SerializableQueryFilter
SerializableQueryFilter::operator ||(const SerializableQueryFilter &other_query)
{
    return calcOperator(other_query, Operator::OR);
}
