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

#ifndef __ASSET_SOURCE_V2_H__
#define __ASSET_SOURCE_V2_H__

#include "debug.h"
#include "intelligence_types_v2.h"
#include "cereal/archives/json.hpp"
#include "cereal/types/vector.hpp"
#include "customized_cereal_map.h"

template <typename UserSerializableReplyAttr>
class SerializableAssetSource
{
public:
    SerializableAssetSource() {}

    void load(cereal::JSONInputArchive &ar);

    const std::string & getTenantId() const { return tenant_id; }
    const std::string & getSourceId() const { return source_id; }
    const std::string & getAssetId() const { return asset_id; }
    const std::chrono::seconds getTTL() const { return ttl; }
    const std::string & getExpirationTime() const { return expiration_time; }
    uint getConfidence() const { return confidence; }
    const std::vector<UserSerializableReplyAttr> & getAttributes() const { return attributes; }

    UserSerializableReplyAttr
    mergeReplyData() const
    {
        UserSerializableReplyAttr reply_data;
        for (const UserSerializableReplyAttr &reply_attr : attributes) {
            reply_data.insert(reply_attr);
        }
        return reply_data;
    }

    template <typename Values>
    bool
    matchValues(const Values &requested_vals) const
    {
        for (const UserSerializableReplyAttr &recieved_attr : attributes) {
            if (recieved_attr.matchValues(requested_vals)) return true;
        }
        return false;
    }

private:
    std::string tenant_id = "";
    std::string source_id = "";
    std::string asset_id = "";
    std::chrono::seconds ttl = std::chrono::seconds::zero();
    std::string expiration_time = "";
    uint confidence = 0;
    std::vector<UserSerializableReplyAttr> attributes;
};

#include "asset_source_v2_impl.h"

#endif //__ASSET_SOURCE_V2_H__
