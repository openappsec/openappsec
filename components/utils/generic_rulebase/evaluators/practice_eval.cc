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

#include "generic_rulebase/evaluators/practice_eval.h"

#include <vector>
#include <string>

#include "generic_rulebase/rulebase_config.h"
#include "config.h"
#include "debug.h"

USE_DEBUG_FLAG(D_RULEBASE_CONFIG);

using namespace std;

string PracticeMatcher::ctx_key = "practices";

PracticeMatcher::PracticeMatcher(const vector<string> &params)
{
    if (params.size() != 1) reportWrongNumberOfParams(PracticeMatcher::getName(), params.size(), 1, 1);
    practice_id = params[0];
}

Maybe<bool, Context::Error>
PracticeMatcher::evalVariable() const
{
    I_Environment *env = Singleton::Consume<I_Environment>::by<PracticeMatcher>();
    auto bc_practice_id_ctx = env->get<set<GenericConfigId>>(PracticeMatcher::ctx_key);
    dbgTrace(D_RULEBASE_CONFIG)
        << "Trying to match practice. ID: "
        << practice_id << ", Current set IDs: "
        << makeSeparatedStr(bc_practice_id_ctx.ok() ? *bc_practice_id_ctx : set<GenericConfigId>(), ", ");
    if (bc_practice_id_ctx.ok()) {
        return bc_practice_id_ctx.unpack().count(practice_id) > 0;
    }

    auto rule = getConfiguration<BasicRuleConfig>("rulebase", "rulesConfig");
    return rule.ok() && rule.unpack().isPracticeActive(practice_id);
}
