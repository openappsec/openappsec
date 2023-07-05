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

#ifndef __QUERY_FILTER_V2_H__
#define __QUERY_FILTER_V2_H__

#include <boost/variant.hpp>
#include <string>
#include <chrono>
#include <boost/functional/hash.hpp>

#include "cereal/archives/json.hpp"
#include "cereal/types/vector.hpp"
#include "debug.h"
#include "intelligence_types_v2.h"
#include "maybe_res.h"

using namespace Intelligence_IS_V2;

class SerializableQueryCondition
{
public:
    typedef boost::variant<int64_t, std::string> ValueVariant;

    SerializableQueryCondition() {}

    SerializableQueryCondition(Condition _condition_type, std::string _key, std::string _value)
            :
        condition_type(_condition_type),
        key(_key),
        value(_value)
        {}

    SerializableQueryCondition(Condition _condition_type, std::string _key, int64_t _value)
            :
        condition_type(_condition_type),
        key(_key),
        value(_value)
        {}

    void save(cereal::JSONOutputArchive &ar) const;

    Condition getConditionType() const { return condition_type; }
    const std::string & getKey() const { return key; }
    const ValueVariant & getValue() const { return value; }

private:
    Condition condition_type = Condition::EQUALS;
    std::string key = "";
    ValueVariant value = "";
};

class SerializableQueryFilter
{
public:
    SerializableQueryFilter() {}
    SerializableQueryFilter(Condition condition_type, const std::string &key, const std::string &value);
    SerializableQueryFilter(Condition condition_type, const std::string &key, const int64_t &value);

    void save(cereal::JSONOutputArchive &ar) const;

    void addCondition(Condition condition_type, const std::string &key, const std::string &value);
    void addCondition(Condition condition_type, const std::string &key, const int64_t &value);

    Operator getOperator() const { return operator_type; }
    const std::vector<SerializableQueryCondition> & getConditionOperands() const { return condition_operands; }
    const std::vector<SerializableQueryFilter> & getQueriesOperands() const { return queries_operands; }

    Maybe<SerializableQueryCondition::ValueVariant> getConditionValueByKey(const std::string &key) const;

    bool empty() const { return condition_operands.empty() && queries_operands.empty(); }

    SerializableQueryFilter operator &&(const SerializableQueryFilter &other_query);
    SerializableQueryFilter operator ||(const SerializableQueryFilter &other_query);

private:
    void saveCondition(cereal::JSONOutputArchive &ar) const;
    void saveOperation(cereal::JSONOutputArchive &ar) const;
    bool isOperatorComp(const Operator &oper) const;
    SerializableQueryFilter calcOperator(const SerializableQueryFilter &other_query, const Operator &oper);

    Operator operator_type = Operator::NONE;
    std::vector<SerializableQueryFilter> queries_operands = {};
    std::vector<SerializableQueryCondition> condition_operands = {};
};

#endif // __QUERY_FILTER_V2_H__
