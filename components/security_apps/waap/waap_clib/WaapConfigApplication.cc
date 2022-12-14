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

#include "WaapConfigApplication.h"
#include "telemetry.h"

using namespace std;

USE_DEBUG_FLAG(D_WAAP);

const string WaapConfigApplication::s_PracticeSubType = "Web Application";
set<string> WaapConfigApplication::assets_ids{};
set<string> WaapConfigApplication::assets_ids_aggregation{};

bool WaapConfigApplication::getWaapSiteConfig(WaapConfigApplication& ngenSiteConfig) {
    auto &maybe_ngen_config = getConfiguration<WaapConfigApplication>(
        "WAAP",
        "WebApplicationSecurity"
        );

    if (!maybe_ngen_config.ok())
    {
        dbgDebug(D_WAAP) << maybe_ngen_config.getErr();
        return false;
    }

    ngenSiteConfig = maybe_ngen_config.unpack();
    return true;
}

WaapConfigApplication::WaapConfigApplication() :
    WaapConfigBase()
{
}

void
WaapConfigApplication::notifyAssetsCount()
{
    WaapConfigApplication::assets_ids = WaapConfigApplication::assets_ids_aggregation;
    AssetCountEvent(AssetType::WEB, WaapConfigApplication::assets_ids.size()).notify();
}

void
WaapConfigApplication::clearAssetsCount()
{
    WaapConfigApplication::assets_ids_aggregation.clear();
}

const string& WaapConfigApplication::get_PracticeSubType() const
{
    return s_PracticeSubType;
}

void WaapConfigApplication::load(cereal::JSONInputArchive& ar)
{
    WaapConfigBase::load(ar);
    loadOpenRedirectPolicy(ar);
    loadErrorDisclosurePolicy(ar);
    loadCsrfPolicy(ar);
    loadSecurityHeadersPolicy(ar);

    assets_ids_aggregation.insert(m_assetId);
}


bool WaapConfigApplication::operator==(const WaapConfigApplication& other) const
{
    const WaapConfigBase* configBase = this;
    const WaapConfigBase& configBaseOther = other;

    return *configBase==configBaseOther;
}

void WaapConfigApplication::printMe(ostream& os) const
{
    WaapConfigBase::printMe(os);
}
