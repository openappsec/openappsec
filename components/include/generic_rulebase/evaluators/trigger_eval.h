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

#ifndef __TRIGGER_EVAL_H__
#define __TRIGGER_EVAL_H__

#include "environment/evaluator_templates.h"
#include "i_environment.h"
#include "singleton.h"

class TriggerMatcher : public EnvironmentEvaluator<bool>, Singleton::Consume<I_Environment>
{
public:
    TriggerMatcher(const std::vector<std::string> &params);

    static std::string getName() { return "triggerId"; }

    Maybe<bool, Context::Error> evalVariable() const override;

    static std::string ctx_key;

private:
    std::string trigger_id;
};

#endif // __TRIGGER_EVAL_H__
