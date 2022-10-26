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

#ifndef __BASE_EVALUATORS_H__
#define __BASE_EVALUATORS_H__

// This file is only supposed to be included from "environment_evaluator.h", so this is simply a safeguard.
#ifndef __ENVIRONMENT_EVALUATOR_H__
#error "environment/evaluators_repo.h should not be included directly"
#endif // __ENVIRONMENT_EVALUATOR_H__

#include "i_environment.h"
#include "environment.h"

namespace EnvironmentHelper
{

template <typename Value>
class GetEvaluator : public EnvironmentEvaluator<Value>
{
public:
    GetEvaluator(const std::vector<std::string> &params)
    {
        if (params.size() != 1) reportWrongNumberOfParams("Get", params.size(), 1, 1);
        name = params[0];
    }

    Maybe<Value, Context::Error>
    evalVariable() const override
    {
        return Singleton::Consume<I_Environment>::from<Environment>()->get<Value>(name);
    }

    static std::string getName() { return "Get"; }

private:
    std::string name;
};

template <typename Value>
class SelectEvaluator : public EnvironmentEvaluator<Value>
{
public:
    SelectEvaluator(const std::vector<std::string> &params)
    {
        if (params.size() < 2) reportWrongNumberOfParams("Select", params.size(), 2);
        auto ptr = EvaluatorsRepo<Value>::getRepo();
        for (const auto &param : params) {
            vars.push_back(ptr->getMatcher(param));
        }
    }

    Maybe<Value, Context::Error>
    evalVariable() const override
    {
        for (const auto &var : vars) {
            auto value = var->evalVariable();
            if (value.ok()) return value;
        }

        return genError(Context::Error::NO_EVAL);
    }

    static std::string getName() { return "Select"; }

private:
    std::vector<EvaluatorPtr<Value>> vars;
};

} // EnvironmentHelper

#endif // __BASE_EVALUATORS_H__
