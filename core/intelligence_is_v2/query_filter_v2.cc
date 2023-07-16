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

struct Visitor : public boost::static_visitor<void>
{
    Visitor(cereal::JSONOutputArchive& _ar) : ar(_ar) {}

    template <typename T>
    void operator()(const T& value)
    {
        ar(cereal::make_nvp("value", value));
    }

private:
    cereal::JSONOutputArchive &ar;
};

void
SerializableQueryCondition::save(cereal::JSONOutputArchive &ar) const
{
    ar(
        cereal::make_nvp("operator", string(convertConditionTypeToString(condition_type))),
        cereal::make_nvp("key", key)
    );

    Visitor visitor(ar);
    boost::apply_visitor(visitor, value);
}

SerializableQueryFilter::SerializableQueryFilter(
    Condition condition_type,
    const std::string &key,
    const std::string &value
) {
    condition_operands.emplace_back(condition_type, key, value);
}

SerializableQueryFilter::SerializableQueryFilter(
    Condition condition_type,
    const std::string &key,
    const int64_t &value
) {
    condition_operands.emplace_back(condition_type, key, value);
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
        queries_operands.emplace_back(condition_type, key, value);
        return;
    }
    if (condition_operands.size() == 1 && operator_type == Operator::NONE) operator_type = Operator::AND;
    condition_operands.emplace_back(condition_type, key, value);
}

void
SerializableQueryFilter::addCondition(Condition condition_type, const string &key, const int64_t &value)
{
    if (queries_operands.size() > 0) {
        queries_operands.emplace_back(condition_type, key, value);
        return;
    }
    if (condition_operands.size() == 1 && operator_type == Operator::NONE) operator_type = Operator::AND;
    condition_operands.emplace_back(condition_type, key, value);
}

void
SerializableQueryFilter::saveCondition(cereal::JSONOutputArchive &ar) const
{
    condition_operands.begin()->save(ar);
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

Maybe<SerializableQueryCondition::ValueVariant>
SerializableQueryFilter::getConditionValueByKey(const string &key) const
{
    for (const SerializableQueryCondition &condition : condition_operands) {
        if (condition.getConditionType() == Condition::EQUALS && condition.getKey() == key) {
            return condition.getValue();
        }
    }

    return genError("Key not found.");
}

bool
SerializableQueryFilter::isOperatorComp(const Operator &oper) const
{
    return operator_type == Operator::NONE || operator_type == oper;
}

SerializableQueryFilter
SerializableQueryFilter::calcOperator(const SerializableQueryFilter &other_query, const Operator &oper)
{
    SerializableQueryFilter query_filter_res;

    query_filter_res.operator_type = oper;

    if (isOperatorComp(oper) && other_query.isOperatorComp(oper)) {
        size_t queries_size = queries_operands.size() + other_query.queries_operands.size();
        size_t conditions_size = condition_operands.size() + other_query.condition_operands.size();
        query_filter_res.queries_operands.reserve(queries_size);
        query_filter_res.condition_operands.reserve(conditions_size);

        for (const auto &subquery : queries_operands) {
            query_filter_res.queries_operands.push_back(subquery);
        }

        for (const auto &condition : condition_operands) {
            query_filter_res.condition_operands.push_back(condition);
        }

        for (const auto &subquery : other_query.queries_operands) {
            query_filter_res.queries_operands.push_back(subquery);
        }

        for (const auto &condition : other_query.condition_operands) {
            query_filter_res.condition_operands.push_back(condition);
        }
    } else {
        query_filter_res.queries_operands.reserve(2);
        query_filter_res.queries_operands.push_back(*this);
        query_filter_res.queries_operands.push_back(other_query);
    }

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
