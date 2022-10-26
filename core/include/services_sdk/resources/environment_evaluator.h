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

#ifndef __ENVIRONMENT_EVALUATOR_H__
#define __ENVIRONMENT_EVALUATOR_H__

#include "maybe_res.h"
#include "context.h"

// All evaluators in the system must inherit from `EnvironmentEvaluator` and be templated on their return type.
// In addition to implementing `evalVariable()`, they also need to have `static std::string getName()` function.
// The constructor of the inherited class should take `const std::vector<std::string> &` as a parameter, this should
// be passed as the parameters to the evaluator.
template <typename Value>
class EnvironmentEvaluator
{
public:
    virtual ~EnvironmentEvaluator() {}
    virtual Maybe<Value, Context::Error> evalVariable() const = 0;

    using Type = Value;
};

// These functions are used in the construction of an Evaluator to report errors. They throw an exception, so that
// the creation process stops.
void
reportWrongNumberOfParams(
    const std::string &eval_name,
    uint no_params_given,
    uint min_expected,
    uint max_expected = -1
);
void reportWrongParamType(const std::string &eval_name, const std::string &param, const std::string &reason);
void reportUnknownEvaluatorType(const std::string &eval_name);

#include "environment/evaluators_repo.h"

// This function is used in the creation of an evaluator. For every parameter the constractor can pass the parameter
// to getMatcher (with expected return type as Type) and get a pointer to an evaluator the equals to that parameter.
template <typename Type>
std::unique_ptr<EnvironmentEvaluator<Type>>
getMatcher(const std::string &param)
{
    auto ptr = EnvironmentHelper::EvaluatorsRepo<Type>::getRepo();
    return ptr->getMatcher(param);
}

// This function takes an entire string and attempts to interpret it as a (possibly compound) evaluator that returns
// the type `Value`.
template <typename Value>
Maybe<std::function<Maybe<Value, Context::Error>()>>
genEvaluator(const std::string &str)
{
    return EnvironmentHelper::genEvaluator<Value>(str);
}

// This function adds a matcher to the the repository of possible evaluators.
template <typename Matcher>
bool
addMatcher()
{
    auto ptr = EnvironmentHelper::EvaluatorsRepo<typename Matcher::Type>::getRepo();
    return ptr->template addMatcher<Matcher>();
}

#endif // __ENVIRONMENT_EVALUATOR_H__
