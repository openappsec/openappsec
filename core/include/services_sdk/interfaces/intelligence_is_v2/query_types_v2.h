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

#ifndef __QUERY_TYPES_V2_H__
#define __QUERY_TYPES_V2_H__

#include "cereal/archives/json.hpp"
#include "cereal/types/string.hpp"
#include "cereal/types/tuple.hpp"
#include "cereal/types/vector.hpp"
#include "intelligence_types_v2.h"
#include "maybe_res.h"

#include <vector>
#include <unordered_map>

class SerializableQueryTypes
{
public:
    SerializableQueryTypes() {};

    void save(cereal::JSONOutputArchive &ar) const;
    void setSerializableTenantList(const std::vector<std::string> &tenant_list);
    void setQueryCrossTenantAssetDB(bool query_cross_tenant_asset_db);

private:
    void serializeMultiTenant(cereal::JSONOutputArchive &ar) const;
    void serializeCrossTenantAssetDB(cereal::JSONOutputArchive &ar) const;

    Maybe<std::vector<std::string>> tenants = genError("tenant list is uninitialized");
    Maybe<bool> query_cross_tenant_asset_db = genError("cross tenant asset db query is uninitialized");
};

#endif // __QUERY_TYPES_V2_H__
