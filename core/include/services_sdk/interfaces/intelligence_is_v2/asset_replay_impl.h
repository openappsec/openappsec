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

#ifndef __ASSET_REPLAY_IMPL_H__
#define __ASSET_REPLAY_IMPL_H__

#ifndef __ASSET_REPLY_H__
#error asset_replay_impl.h should not be included directly!
#endif // __ASSET_REPLY_H__

#include "customized_cereal_multimap.h"
#include "intelligence_types_v2.h"

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
template <typename Values>
bool
AssetReply<UserSerializableReplyAttr>::matchValues(const Values &values) const
{
    for (const SerializableAssetSource<UserSerializableReplyAttr> &source : sources) {
        if (source.template matchValues<Values>(values)) return true;
    }
    return false;
}

template <typename UserSerializableReplyAttr>
UserSerializableReplyAttr
AssetReply<UserSerializableReplyAttr>::mergeReplyData() const
{
    UserSerializableReplyAttr reply_data;
    for (const SerializableAssetSource<UserSerializableReplyAttr> &source : sources) {
        UserSerializableReplyAttr data_by_source = source.mergeReplyData();
        reply_data.insert(data_by_source);
    }
    return reply_data;
}

template<typename UserSerializableReplyAttr>
void
IntelligenceQueryResponseT<UserSerializableReplyAttr>::loadFromJson(const std::string &json_response)
{
    std::stringstream in;
    in.str(json_response);
    cereal::JSONInputArchive in_ar(in);
    serialize(in_ar);
}

template<typename UserSerializableReplyAttr>
template<class Archive>
void
IntelligenceQueryResponseT<UserSerializableReplyAttr>::serialize(Archive &ar)
{
    ar(
        cereal::make_nvp("assetCollections", asset_collections)
    );

    try {
        IntelligenceQueryResponse::serialize(ar);
    } catch(...) {}
}


template <typename UserSerializableReplyAttr>
uint
IntelligenceQueryResponseT<UserSerializableReplyAttr>::getAssetCollectionsSize() const
{
    return asset_collections.size();
}

template <typename UserSerializableReplyAttr>
const std::vector<AssetReply<UserSerializableReplyAttr>> &
IntelligenceQueryResponseT<UserSerializableReplyAttr>::getData() const
{
    return asset_collections;
}

template <typename UserSerializableReplyAttr>
bool
IntelligenceQueryResponseT<UserSerializableReplyAttr>::isLast(uint asset_limit)
{
    return getResponseStatus() ==  ResponseStatus::DONE && getAssetCollectionsSize() < asset_limit;
}

#endif // __ASSET_REPLAY_IMPL_H__
