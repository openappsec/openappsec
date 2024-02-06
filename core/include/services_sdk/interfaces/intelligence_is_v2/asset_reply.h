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

#ifndef __ASSET_REPLY_H__
#define __ASSET_REPLY_H__

#include <map>
#include <string>
#include <vector>

#include "asset_source.h"
#include "query_request_v2.h"
#include "intelligence_types_v2.h"
#include "maybe_res.h"

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

    UserSerializableReplyAttr mergeReplyData() const;

    template <typename Values>
    bool matchValues(const Values &values) const;

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

class IntelligenceQueryResponse
{
public:
    IntelligenceQueryResponse() {}

    void loadFromJson(const std::string &json_response);

    template<class Archive>
    void serialize(Archive &ar);

    Intelligence_IS_V2::ResponseStatus getResponseStatus() const { return status; }
    const std::string & getCursor() const { return cursor; }
    uint getAmountOfAssets() const { return total_num_assets; }
    bool isValidInBulk() const { return !partial_fail_in_bulk; }
    void setFailInBulk() { partial_fail_in_bulk = true; }

private:
    Intelligence_IS_V2::ResponseStatus status = Intelligence_IS_V2::ResponseStatus::IN_PROGRESS;
    uint total_num_assets = 0;
    std::string cursor = "";
    bool partial_fail_in_bulk = false;
};

template <typename UserSerializableReplyAttr>
class IntelligenceQueryResponseT : public IntelligenceQueryResponse
{
public:
    void loadFromJson(const std::string &json_response);

    template<class Archive>
    void serialize(Archive &ar);

    uint getAssetCollectionsSize() const;

    bool isLast(uint asset_limit);

    const std::vector<AssetReply<UserSerializableReplyAttr>> & getData() const;

private:
    std::vector<AssetReply<UserSerializableReplyAttr>> asset_collections;
};

#include "asset_replay_impl.h"

#endif // __ASSET_REPLY_H__
