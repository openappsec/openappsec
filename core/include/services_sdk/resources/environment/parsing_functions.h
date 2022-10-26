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

#ifndef __PARSING_FUNCTIONS_H__
#define __PARSING_FUNCTIONS_H__

namespace EnvironmentHelper
{

// The EvaluatorParseError is the exception class for the evaluator parsing process.
class EvaluatorParseError
{
public:
    EvaluatorParseError(const std::string &_str) : str(_str) {}
    const std::string & getError() const { return str; }

private:
    std::string str;
};

// The EvaluatorWrapper is used to bypass the fact that lambda expressions can't capture std::unique_ptr.
template <typename Value>
class EvaluatorWrapper
{
public:
    EvaluatorWrapper(EvaluatorPtr<Value> &&_ptr) : ptr(std::move(_ptr)) {}
    EvaluatorWrapper(const EvaluatorWrapper &other)
    {
        auto p_other = const_cast<EvaluatorWrapper *>(&other);
        ptr = std::move(p_other->ptr);
    }

    Maybe<Value, Context::Error>
    evalVariable() const
    {
        auto res = ptr->evalVariable();
        // The lack of value during evaluation results in no evaluation, so change the error accordingly.
        if (!res.ok() && res.getErr()==Context::Error::NO_VALUE) return genError(Context::Error::NO_EVAL);
        return res;
    }

private:
    EvaluatorPtr<Value> ptr;
};

std::pair<std::string, std::vector<std::string>> breakEvaluatorString(const std::string &str);

template <typename Value>
Maybe<std::function<Maybe<Value, Context::Error>()>>
genEvaluator(const std::string &str)
{
    EvaluatorPtr<Value> res;
    try {
        res = EvaluatorsRepo<Value>::getRepo()->getMatcher(str);
    } catch (const EvaluatorParseError &e) {
        return genError(e.getError());
    }

    EvaluatorWrapper<Value> wrapper(std::move(res));
    std::function<Maybe<Value, Context::Error>()> func = [wrapper] () { return wrapper.evalVariable(); };

    return func;
}

} // EnvironmentHelper

#endif // __PARSING_FUNCTIONS_H__
