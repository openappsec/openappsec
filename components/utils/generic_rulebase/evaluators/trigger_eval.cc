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

#include "generic_rulebase/evaluators/trigger_eval.h"

#include <vector>
#include <string>

#include "generic_rulebase/rulebase_config.h"
#include "config.h"
#include "debug.h"

using namespace std;

USE_DEBUG_FLAG(D_RULEBASE_CONFIG);

string TriggerMatcher::ctx_key = "triggers";

TriggerMatcher::TriggerMatcher(const vector<string> &params)
{
    if (params.size() != 1) reportWrongNumberOfParams(TriggerMatcher::getName(), params.size(), 1, 1);
    trigger_id = params[0];
}

Maybe<bool, Context::Error>
TriggerMatcher::evalVariable() const
{
    I_Environment *env = Singleton::Consume<I_Environment>::by<TriggerMatcher>();
    auto ac_bc_trigger_id_ctx = env->get<set<GenericConfigId>>("ac_trigger_id");
    dbgTrace(D_RULEBASE_CONFIG)
        << "Trying to match trigger for access control rule. ID: "
        << trigger_id << ", Current set IDs: "
        << makeSeparatedStr(ac_bc_trigger_id_ctx.ok() ? *ac_bc_trigger_id_ctx : set<GenericConfigId>(), ", ");
    if (ac_bc_trigger_id_ctx.ok()) {
        return ac_bc_trigger_id_ctx.unpack().count(trigger_id) > 0;
    }

    auto bc_trigger_id_ctx = env->get<set<GenericConfigId>>(TriggerMatcher::ctx_key);
    dbgTrace(D_RULEBASE_CONFIG)
        << "Trying to match trigger. ID: "
        << trigger_id << ", Current set IDs: "
        << makeSeparatedStr(bc_trigger_id_ctx.ok() ? *bc_trigger_id_ctx : set<GenericConfigId>(), ", ");
    if (bc_trigger_id_ctx.ok() && bc_trigger_id_ctx.unpack().count(trigger_id) > 0 ) return true;

    auto rule = getConfiguration<BasicRuleConfig>("rulebase", "rulesConfig");
    return rule.ok() && rule.unpack().isTriggerActive(trigger_id);
}
