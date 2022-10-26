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

#ifndef __REQUESTED_ATTRIBUTES_V2_H__
#define __REQUESTED_ATTRIBUTES_V2_H__

#include "cereal/archives/json.hpp"
#include "cereal/types/string.hpp"
#include "cereal/types/tuple.hpp"
#include "cereal/types/vector.hpp"
#include "intelligence_types_v2.h"

#include <vector>
#include <unordered_map>

class serializableAttribute
{
public:
    serializableAttribute(std::string _key, uint _min_confidence)
            :
        key(_key),
        min_confidence(_min_confidence)
    {}

    void serialize(cereal::JSONOutputArchive &ar) const;

private:
    std::string key;
    uint min_confidence;
};

class SerializableAttributesMap
{
public:
    SerializableAttributesMap() {};

    void save(cereal::JSONOutputArchive &ar) const;

    void setSerializableAttribute(const std::string &attribute, uint confidence = 500);
    uint getAttributeByKey(const std::string &key) const;
    uint getSize() const { return requested_attributes.size(); }
    bool isRequestedAttributesMapEmpty() const { return requested_attributes.empty(); }

    bool checkMinConfidence(uint upper_confidence_limit);

private:
    std::unordered_map<std::string, uint> requested_attributes;
};

#endif // __REQUESTED_ATTRIBUTES_V2_H__
