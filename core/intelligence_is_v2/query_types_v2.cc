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

#include "intelligence_is_v2/query_types_v2.h"

using namespace std;
using namespace Intelligence_IS_V2;

void
SerializableQueryTypes::serializeMultiTenant(cereal::JSONOutputArchive &ar) const
{
    ar(cereal::make_nvp("multiTenant", *tenants));
}

void
SerializableQueryTypes::serializeCrossTenantAssetDB(cereal::JSONOutputArchive &ar) const
{
    ar(cereal::make_nvp("queryCrossTenantAssetDB", *query_cross_tenant_asset_db));
}

void
SerializableQueryTypes::save(cereal::JSONOutputArchive &ar) const
{
    if (!tenants.ok() && !query_cross_tenant_asset_db.ok()) return;

    ar.setNextName("queryTypes");
    ar.startNode();
    if (tenants.ok()) serializeMultiTenant(ar);
    if (query_cross_tenant_asset_db.ok()) serializeCrossTenantAssetDB(ar);
    ar.finishNode();
}

void
SerializableQueryTypes::setSerializableTenantList(const vector<string> &tenant_list)
{
    tenants = tenant_list;
};

void
SerializableQueryTypes::setQueryCrossTenantAssetDB(bool cross_tenant_asset_db)
{
    query_cross_tenant_asset_db = cross_tenant_asset_db;
}
