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

#ifndef __QUERY_EVAL_H__
#define __QUERY_EVAL_H__

#include "environment/evaluator_templates.h"
#include "i_environment.h"
#include "i_generic_rulebase.h"
#include "singleton.h"

class QueryMatcher
        :
    public EnvironmentEvaluator<bool>,
    Singleton::Consume<I_Environment>,
    Singleton::Consume<I_GenericRulebase>
{
public:
    QueryMatcher(const std::vector<std::string> &query_params);

    static std::string getName() { return "matchQuery"; }

    Maybe<bool, Context::Error> evalVariable() const override;

private:
    static const std::string contextKeyToString(Context::MetaDataType type);

    std::string key;
    std::unordered_set<std::string> values;
    bool is_any = false;
};

#endif // __QUERY_EVAL_H__
