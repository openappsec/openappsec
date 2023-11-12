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

#include "WaapConfigApi.h"
#include "Waf2Util.h"

#include "telemetry.h"

using namespace std;

USE_DEBUG_FLAG(D_WAAP);

const string WaapConfigAPI::s_PracticeSubType = "Web API";
set<string> WaapConfigAPI::assets_ids{};
set<string> WaapConfigAPI::assets_ids_aggregation{};

bool
WaapConfigAPI::getWaapAPIConfig(WaapConfigAPI& ngenAPIConfig) {
    auto &maybe_ngen_config = getConfiguration<WaapConfigAPI>(
        "WAAP",
        "WebAPISecurity"
    );

    if (!maybe_ngen_config.ok()) {
        dbgDebug(D_WAAP) << "Unable to get WAAP WebAPISecurity from configuration" << maybe_ngen_config.getErr();
        return false;
    }

    ngenAPIConfig = maybe_ngen_config.unpack();
    return true;
}

WaapConfigAPI::WaapConfigAPI() : WaapConfigBase()
{}

void
WaapConfigAPI::notifyAssetsCount()
{
    WaapConfigAPI::assets_ids = WaapConfigAPI::assets_ids_aggregation;
    AssetCountEvent(AssetType::API, WaapConfigAPI::assets_ids.size()).notify();
}

void
WaapConfigAPI::clearAssetsCount()
{
    WaapConfigAPI::assets_ids_aggregation.clear();
}

void WaapConfigAPI::load(cereal::JSONInputArchive& ar)
{
    // order has affect - we need to call base last because of triggers and overrides
    WaapConfigBase::load(ar);
    assets_ids_aggregation.insert(m_assetId);
}

bool WaapConfigAPI::operator==(const WaapConfigAPI& other) const
{
    const WaapConfigBase* configBase = this;
    const WaapConfigBase& configBaseOther = other;

    return *configBase == configBaseOther;
}

void WaapConfigAPI::printMe(ostream& os) const
{
    WaapConfigBase::printMe(os);
}

const string& WaapConfigAPI::get_PracticeSubType() const
{
    return s_PracticeSubType;
}
