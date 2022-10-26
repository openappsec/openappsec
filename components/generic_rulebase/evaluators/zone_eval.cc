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

#include "generic_rulebase/evaluators/zone_eval.h"

#include <vector>
#include <string>

#include "generic_rulebase/zone.h"
#include "generic_rulebase/rulebase_config.h"
#include "config.h"

using namespace std;

string ZoneMatcher::ctx_key = "zone_id";

ZoneMatcher::ZoneMatcher(const vector<string> &params)
{
    if (params.size() != 1) reportWrongNumberOfParams(ZoneMatcher::getName(), params.size(), 1, 1);
    zone_id = params[0];
}

Maybe<bool, Context::Error>
ZoneMatcher::evalVariable() const
{
    I_Environment *env = Singleton::Consume<I_Environment>::by<ZoneMatcher>();
    auto bc_zone_id_ctx = env->get<GenericConfigId>(ZoneMatcher::ctx_key);
    if (bc_zone_id_ctx.ok() && *bc_zone_id_ctx == zone_id) return true;

    if (!getProfileAgentSettingWithDefault<bool>(false, "rulebase.enableQueryBasedMatch")) return false;

    auto zone = getConfiguration<Zone>("rulebase", "zones");
    return zone.ok() && zone.unpack().getId() == zone_id;
}
