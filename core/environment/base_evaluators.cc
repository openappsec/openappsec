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

#include "environment_evaluator.h"
#include "evaluator_registration.h"

using namespace std;
using namespace EnvironmentHelper;

class AllEvaluator : public EnvironmentEvaluator<bool>
{
public:
    AllEvaluator(const vector<string> &params)
    {
        for (const auto &param : params) {
            conditions.push_back(getMatcher<bool>(param));
        }
    }

    Maybe<bool, Context::Error>
    evalVariable() const override
    {
        for (auto &cond : conditions) {
            auto res = cond->evalVariable();
            if (!res.ok()) return res;
            if (res.unpack() == false) return false;
        }
        return true;
    }

    static std::string getName() { return "All"; }

private:
    vector<EvaluatorPtr<bool>> conditions;
};

class AnyEvaluator : public EnvironmentEvaluator<bool>
{
public:
    AnyEvaluator(const vector<string> &params)
    {
        for (const auto &param : params) {
            conditions.push_back(getMatcher<bool>(param));
        }
    }

    Maybe<bool, Context::Error>
    evalVariable() const override
    {
        for (auto &cond : conditions) {
            auto res = cond->evalVariable();
            if (!res.ok()) return res;
            if (res.unpack() == true) return true;
        }
        return false;
    }

    static std::string getName() { return "Any"; }

private:
    vector<EvaluatorPtr<bool>> conditions;
};

class NotEvaluator : public EnvironmentEvaluator<bool>
{
public:
    NotEvaluator(const vector<string> &params)
    {
        if (params.size() != 1) reportWrongNumberOfParams(getName(), params.size(), 1, 1);
        cond = getMatcher<bool>(params[0]);
    }

    Maybe<bool, Context::Error>
    evalVariable() const override
    {
        auto res = cond->evalVariable();
        if (!res.ok()) return res;
        return !(res.unpack());
    }

    static std::string getName() { return "Not"; }

private:
    EvaluatorPtr<bool> cond;
};

void
registerBaseEvaluators()
{
    addMatcher<AllEvaluator>();
    addMatcher<AnyEvaluator>();
    addMatcher<NotEvaluator>();
}
