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

#include "generic_rulebase/generic_rulebase_context.h"

#include <vector>

#include "context.h"
#include "config.h"
#include "generic_rulebase/evaluators/trigger_eval.h"
#include "generic_rulebase/evaluators/parameter_eval.h"
#include "generic_rulebase/evaluators/practice_eval.h"
#include "generic_rulebase/evaluators/zone_eval.h"
#include "generic_rulebase/evaluators/asset_eval.h"

USE_DEBUG_FLAG(D_RULEBASE_CONFIG);

using namespace std;

template<typename Configs>
set<GenericConfigId>
extractIds(const vector<Configs> &configurations)
{
    set<GenericConfigId> ids;
    for (const Configs &conf : configurations) {
        ids.insert(conf.getId());
    }
    return ids;
}

void
GenericRulebaseContext::activate(const BasicRuleConfig &rule)
{
    switch(registration_state) {
        case RuleRegistrationState::UNINITIALIZED: {
            registration_state = RuleRegistrationState::REGISTERED;
            ctx.registerValue<set<GenericConfigId>>(
                TriggerMatcher::ctx_key,
                extractIds<RuleTrigger>(rule.getTriggers())
            );
            ctx.registerValue<set<GenericConfigId>>(
                PracticeMatcher::ctx_key,
                extractIds<RulePractice>(rule.getPractices())
            );
            dbgTrace(D_RULEBASE_CONFIG)
                << "Activating current practices. Current practice IDs: "
                << makeSeparatedStr(extractIds<RulePractice>(rule.getPractices()), ", ");

            ctx.registerValue<set<GenericConfigId>>(
                ParameterMatcher::ctx_key,
                extractIds<RuleParameter>(rule.getParameters())
            );
            ctx.registerValue<GenericConfigId>(
                ZoneMatcher::ctx_key,
                rule.getZoneId()
            );
            ctx.registerValue<GenericConfigId>(
                AssetMatcher::ctx_key,
                rule.getAssetId()
            );
            ctx.activate();
            break;
        }
        case RuleRegistrationState::REGISTERED: {
            dbgTrace(D_RULEBASE_CONFIG) << "Activating registered rule values";
            ctx.activate();
            break;
        }
        case RuleRegistrationState::UNREGISTERED: {
            dbgTrace(D_RULEBASE_CONFIG) << "Failed to register rule values";
        }
    }
}

void
GenericRulebaseContext::activate()
{
    switch(registration_state) {
        case RuleRegistrationState::UNINITIALIZED: {
            auto maybe_rule = getConfiguration<BasicRuleConfig>("rulebase", "rulesConfig");
            if (!maybe_rule.ok()) {
                registration_state = RuleRegistrationState::UNREGISTERED;
                return;
            }
            dbgTrace(D_RULEBASE_CONFIG) << "Registering new rule values";
            activate(maybe_rule.unpack());
            registration_state = RuleRegistrationState::REGISTERED;
            break;
        }
        case RuleRegistrationState::REGISTERED: {
            dbgTrace(D_RULEBASE_CONFIG) << "Activating registered rule values";
            ctx.activate();
            break;
        }
        case RuleRegistrationState::UNREGISTERED: {
            dbgTrace(D_RULEBASE_CONFIG) << "Failed to register rule values";
        }
    }
}
