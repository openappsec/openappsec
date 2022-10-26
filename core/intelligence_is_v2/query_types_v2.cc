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
serializableTenantList::serialize(cereal::JSONOutputArchive &ar) const
{
    ar(cereal::make_nvp("multiTenant", tenants));
}

void
SerializableQueryTypes::save(cereal::JSONOutputArchive &ar) const
{
    if (!is_nsaas) return;
    serializableTenantList serializable_tenants(tenants);
    ar(cereal::make_nvp("queryTypes", serializable_tenants));
}

void
SerializableQueryTypes::setSerializableTenantList(const std::vector<std::string> _tenants)
{
    tenants = _tenants;
    is_nsaas = true;
};
