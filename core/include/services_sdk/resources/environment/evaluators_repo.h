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

#ifndef __EVALUATORS_REPO_H__
#define __EVALUATORS_REPO_H__

#include <map>
#include <vector>
#include <string>
#include <functional>
#include "singleton.h"
#include "debug.h"

USE_DEBUG_FLAG(D_ENVIRONMENT);

// This file is only supposed to be included from "environment_evaluator.h", so this is simply a safeguard.
#ifndef __ENVIRONMENT_EVALUATOR_H__
#error "environment/evaluators_repo.h should not be included directly"
#endif // __ENVIRONMENT_EVALUATOR_H__

namespace EnvironmentHelper
{

template <typename Value> using EvaluatorPtr = std::unique_ptr<EnvironmentEvaluator<Value>>;

template <typename Value>
class EvaluatorsRepo : public Singleton::OwnedSingleton
{
    using Constructor = std::function<EvaluatorPtr<Value>(const std::vector<std::string> &)>;
public:
    EvaluatorsRepo();

    template <typename Matcher>
    bool addMatcher();

    EvaluatorPtr<Value> getMatcher(const std::string &str);

    static EvaluatorsRepo * getRepo();

private:
    std::map<std::string, Constructor> constructors;
};

} // EnvironmentHelper

#include "environment/parsing_functions.h"
#include "environment/base_evaluators.h"

template <typename Value>
EnvironmentHelper::EvaluatorsRepo<Value>::EvaluatorsRepo()
{
    addMatcher<GetEvaluator<Value>>();
    addMatcher<SelectEvaluator<Value>>();
}

template <typename Value>
template <typename Matcher>
bool
EnvironmentHelper::EvaluatorsRepo<Value>::addMatcher()
{
    if (constructors.find(Matcher::getName()) != constructors.end()) {
        dbgTrace(D_ENVIRONMENT) << "Matcher was already added. Matcher: " << Matcher::getName();
        return false;
    }
    Constructor func = [] (const std::vector<std::string> &params) { return std::make_unique<Matcher>(params); };
    constructors[Matcher::getName()] = func;
    dbgTrace(D_ENVIRONMENT) << "Matcher was added successfully. Matcher: " << Matcher::getName();
    return true;
}

template <typename Value>
EnvironmentHelper::EvaluatorPtr<Value>
EnvironmentHelper::EvaluatorsRepo<Value>::getMatcher(const std::string &str)
{
    auto matcher = breakEvaluatorString(str);
    auto iter = constructors.find(matcher.first);
    if (iter == constructors.end()) {
        dbgTrace(D_ENVIRONMENT) << "Matcher was not found. Matcher: " << matcher.first;
        reportUnknownEvaluatorType(matcher.first);
    }
    dbgTrace(D_ENVIRONMENT) << "Matcher was found. Matcher: " << matcher.first;
    return iter->second(matcher.second);
}

template <typename Value>
EnvironmentHelper::EvaluatorsRepo<Value> *
EnvironmentHelper::EvaluatorsRepo<Value>::getRepo()
{
    using Repo = EnvironmentHelper::EvaluatorsRepo<Value>;

    if (!Singleton::existsOwned<Repo>()) {
        Singleton::newOwned<Repo>();
    }
    return Singleton::getOwned<Repo>();
}

#endif // __EVALUATORS_REPO_H__
