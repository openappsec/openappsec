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

#ifndef __GENERIC_RULEBASE_CONTEXT_H__
#define __GENERIC_RULEBASE_CONTEXT_H__

#include "rulebase_config.h"
#include "context.h"
#include "config.h"

enum class RuleRegistrationState {REGISTERED, UNREGISTERED, UNINITIALIZED};

class GenericRulebaseContext
{
public:
    GenericRulebaseContext() : ctx(), registration_state(RuleRegistrationState::UNINITIALIZED) {}

    void activate(const BasicRuleConfig &rule);

    void activate();

    void deactivate() { if (registration_state == RuleRegistrationState::REGISTERED) ctx.deactivate(); }

private:
    Context ctx;
    RuleRegistrationState registration_state;
};

#endif //__GENERIC_RULEBASE_CONTEXT_H__
