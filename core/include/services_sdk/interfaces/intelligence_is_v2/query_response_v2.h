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

#ifndef __QUERY_RESPONSE_V2_H__
#define __QUERY_RESPONSE_V2_H__

#include <sstream>
#include <vector>
#include <map>

#include "cereal/archives/json.hpp"
#include "cereal/types/vector.hpp"
#include "cereal/types/map.hpp"

#include "debug.h"
#include "maybe_res.h"
#include "customized_cereal_map.h"
#include "customized_cereal_multimap.h"
#include "intelligence_types_v2.h"
#include "asset_source_v2.h"

USE_DEBUG_FLAG(D_INTELLIGENCE);

template <typename UserSerializableReplyAttr>
class AssetReply
{
public:
    AssetReply() {}

    void load(cereal::JSONInputArchive &ar);
    std::vector<UserSerializableReplyAttr> getData() const;
    const std::map<std::string, std::vector<std::string>> & getMainAttributes() const { return main_attributes; }
    const std::vector<SerializableAssetSource<UserSerializableReplyAttr>> & getSources() const { return sources; }

    uint getAssetSchemaVersion() const { return asset_schema_version; }
    const std::string & getAssetType() const { return asset_type; }
    uint getAssetTypeSchemaVersion() const { return asset_type_schema_version; }
    const std::string & getAssetPermissionGroupId() const { return asset_permission_group_id; }
    const std::string & getAssetName() const { return asset_name; }
    const std::string & getAssetID() const { return asset_id; }
    const std::string & getAssetClass() const { return asset_class; }
    const std::string & getAssetCategory() const { return asset_category; }
    const std::string & getAssetFamily() const { return asset_family; }
    const std::string & getAssetGroup() const { return asset_group; }
    const std::string & getAssetOrder() const { return asset_order; }
    const std::string & getAssetKind() const { return asset_kind; }

    UserSerializableReplyAttr
    mergeReplyData() const
    {
        UserSerializableReplyAttr reply_data;
        for (const SerializableAssetSource<UserSerializableReplyAttr> &source : sources) {
            UserSerializableReplyAttr data_by_source = source.mergeReplyData();
            reply_data.insert(data_by_source);
        }
        return reply_data;
    }

    template <typename Values>
    bool
    matchValues(const Values &values) const
    {
        for (const SerializableAssetSource<UserSerializableReplyAttr> &source : sources) {
            if (source.template matchValues<Values>(values)) return true;
        }
        return false;
    }

private:
    uint asset_schema_version = 0;
    std::string asset_type = "";
    uint asset_type_schema_version = 0;
    std::string asset_permission_group_id = "";
    std::string asset_name = "";
    std::string asset_id = "";
    std::string asset_class = "";
    std::string asset_category = "";
    std::string asset_family = "";
    std::string asset_group = "";
    std::string asset_order = "";
    std::string asset_kind = "";

    std::map<std::string, std::vector<std::string>> main_attributes;
    std::vector<SerializableAssetSource<UserSerializableReplyAttr>> sources;
};

template <typename UserSerializableReplyAttr>
class IntelligenceQueryResponse
{
public:
    IntelligenceQueryResponse() {}

    void loadFromJson(cereal::JSONInputArchive &ar);

    template<class Archive>
    void serialize(Archive &ar);

    Intelligence_IS_V2::ResponseStatus getResponseStatus() const;
    uint getAmountOfAssets() const;
    const std::string & getCursor() const;
    int getAssetCollectionsSize() const;
    const std::vector<AssetReply<UserSerializableReplyAttr>> & getData() const;
    bool isValidInBulk() const;
    void setFailInBulk();

private:
    Intelligence_IS_V2::ResponseStatus status = Intelligence_IS_V2::ResponseStatus::IN_PROGRESS;
    uint total_num_assets = 0;
    std::string cursor = "";
    std::vector<AssetReply<UserSerializableReplyAttr>> asset_collections;
    bool partial_fail_in_bulk = false;
};

#include "query_response_v2_impl.h"

#endif // __QUERY_RESPONSE_V2_H__
