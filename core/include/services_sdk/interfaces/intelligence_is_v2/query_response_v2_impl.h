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

#ifndef __QUERY_RESPONSE_V2_IMPL_H_
#define __QUERY_RESPONSE_V2_IMPL_H_

#ifndef __QUERY_RESPONSE_V2_H__
#error intelligence_query_response_v2_impl.h should not be included directly!
#endif // __QUERY_RESPONSE_V2_H__

#include "debug.h"
#include "intelligence_types_v2.h"

USE_DEBUG_FLAG(D_INTELLIGENCE);

template <typename UserSerializableReplyAttr>
void
AssetReply<UserSerializableReplyAttr>::load(cereal::JSONInputArchive &ar)
{
    SerializableMultiMap<std::string, std::vector<std::string>> tmp_multimap;
    ar(
        cereal::make_nvp("schemaVersion", asset_schema_version),
        cereal::make_nvp("assetTypeSchemaVersion", asset_type_schema_version),
        cereal::make_nvp("class", asset_class),
        cereal::make_nvp("category", asset_category),
        cereal::make_nvp("family", asset_family),
        cereal::make_nvp("mainAttributes", tmp_multimap)
    );

    for (auto const &attr : tmp_multimap.getMap<std::string>()) {
        std::vector<std::string> attr_vec = { attr.second };
        main_attributes[attr.first] = attr_vec;
    }

    for (auto const &attr : tmp_multimap.getMap<std::vector<std::string>>()) {
        main_attributes[attr.first] = attr.second;
    }

    try {
        ar(cereal::make_nvp("permissionGroupId", asset_permission_group_id));
    } catch(...) {}

    try {
        ar(cereal::make_nvp("name", asset_name));
    } catch(...) {}

    try {
        ar(cereal::make_nvp("group", asset_group));
    } catch(...) {}

    try {
        ar(cereal::make_nvp("order", asset_order));
    } catch(...) {}

    try {
        ar(cereal::make_nvp("kind", asset_kind));
    } catch(...) {}

    ar(cereal::make_nvp("sources", sources));
    ar(cereal::make_nvp("assetType", asset_type));
}

template <typename UserSerializableReplyAttr>
std::vector<UserSerializableReplyAttr>
AssetReply<UserSerializableReplyAttr>::getData() const
{
    std::vector<UserSerializableReplyAttr> all_attributes;
    for (SerializableAssetSource<UserSerializableReplyAttr> const &asset_source : sources) {
        for (UserSerializableReplyAttr const &attribute : asset_source.getAttributes()) {
            all_attributes.push_back(attribute);
        }
    }
    return all_attributes;
}

template <typename UserSerializableReplyAttr>
void
IntelligenceQueryResponse<UserSerializableReplyAttr>::loadFromJson(cereal::JSONInputArchive &ar)
{
    std::string raw_data;
    ar(
        cereal::make_nvp("status", raw_data),
        cereal::make_nvp("totalNumAssets", total_num_assets),
        cereal::make_nvp("assetCollections", asset_collections)
    );
    status = Intelligence_IS_V2::convertStringToResponseStatus(raw_data);

    try {
        ar(cereal::make_nvp("cursor", cursor));
    } catch(...) {}
}

template<typename UserSerializableReplyAttr>
template<class Archive>
void
IntelligenceQueryResponse<UserSerializableReplyAttr>::serialize(Archive &ar)
{
    std::string raw_data;
    ar(
        cereal::make_nvp("status", raw_data),
        cereal::make_nvp("totalNumAssets", total_num_assets),
        cereal::make_nvp("assetCollections", asset_collections)
    );
    status = Intelligence_IS_V2::convertStringToResponseStatus(raw_data);

    try {
        ar(cereal::make_nvp("cursor", cursor));
    } catch(...) {}
}

template <typename UserSerializableReplyAttr>
Intelligence_IS_V2::ResponseStatus
IntelligenceQueryResponse<UserSerializableReplyAttr>::getResponseStatus() const
{
    return status;
}

template <typename UserSerializableReplyAttr>
uint
IntelligenceQueryResponse<UserSerializableReplyAttr>::getAmountOfAssets() const
{
    return total_num_assets;
}

template <typename UserSerializableReplyAttr>
const std::string &
IntelligenceQueryResponse<UserSerializableReplyAttr>::getCursor() const
{
    return cursor;
}

template <typename UserSerializableReplyAttr>
int
IntelligenceQueryResponse<UserSerializableReplyAttr>::getAssetCollectionsSize() const
{
    return asset_collections.size();
}

template <typename UserSerializableReplyAttr>
const std::vector<AssetReply<UserSerializableReplyAttr>> &
IntelligenceQueryResponse<UserSerializableReplyAttr>::getData() const
{
    return asset_collections;
}

template <typename UserSerializableReplyAttr>
bool
IntelligenceQueryResponse<UserSerializableReplyAttr>::isValidInBulk() const
{
    return !partial_fail_in_bulk;
}

template <typename UserSerializableReplyAttr>
void
IntelligenceQueryResponse<UserSerializableReplyAttr>::setFailInBulk()
{
    partial_fail_in_bulk = true;
}

#endif // __QUERY_RESPONSE_V2_IMPL_H_
