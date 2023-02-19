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

#include "generic_rulebase/evaluators/asset_eval.h"

#include <vector>
#include <string>

#include "generic_rulebase/assets_config.h"
#include "config.h"
#include "debug.h"

using namespace std;

USE_DEBUG_FLAG(D_RULEBASE_CONFIG);

string AssetMatcher::ctx_key = "asset_id";

AssetMatcher::AssetMatcher(const vector<string> &params)
{
    if (params.size() != 1) reportWrongNumberOfParams(AssetMatcher::getName(), params.size(), 1, 1);
    asset_id = params[0];
}

Maybe<bool, Context::Error>
AssetMatcher::evalVariable() const
{
    I_Environment *env = Singleton::Consume<I_Environment>::by<AssetMatcher>();
    auto bc_asset_id_ctx = env->get<GenericConfigId>(AssetMatcher::ctx_key);

    if (bc_asset_id_ctx.ok()) {
        dbgTrace(D_RULEBASE_CONFIG)
            << "Asset ID: "
            << asset_id
            << "; Current set assetId context: "
            << *bc_asset_id_ctx;
    } else {
        dbgTrace(D_RULEBASE_CONFIG) << "Asset ID: " << asset_id << ". Empty context";
    }

    return bc_asset_id_ctx.ok() && *bc_asset_id_ctx == asset_id;
}
