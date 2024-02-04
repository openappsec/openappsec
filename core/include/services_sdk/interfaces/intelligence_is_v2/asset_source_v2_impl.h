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

#ifndef __ASSET_SOURCE_V2_IMPL_H__
#define __ASSET_SOURCE_V2_IMPL_H__

#ifndef __ASSET_SOURCE_V2_H__
#error intelligence_query_impl_8_0.h should not be included directly!
#endif //__ASSET_V2_SOURCE_H__

USE_DEBUG_FLAG(D_INTELLIGENCE);

template <typename UserSerializableReplyAttr>
void
SerializableAssetSource<UserSerializableReplyAttr>::load(cereal::JSONInputArchive &ar)
{
    uint raw_seconds;
    ar(
        cereal::make_nvp("tenantId", tenant_id),
        cereal::make_nvp("sourceId", source_id),
        cereal::make_nvp("assetId", asset_id),
        cereal::make_nvp("ttl", raw_seconds),
        cereal::make_nvp("expirationTime", expiration_time),
        cereal::make_nvp("confidence", confidence)
    );
    ttl = std::chrono::seconds(raw_seconds);

    UserSerializableReplyAttr raw_attribute;
    try {
        ar(cereal::make_nvp("attributes", raw_attribute));
        attributes.clear();
        attributes.push_back(raw_attribute);
    } catch(const std::exception &e) {}

}

#endif //__ASSET_SOURCE_V2_IMPL_H__
