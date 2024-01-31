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

#include "intelligence_is_v2/requested_attributes_v2.h"

#include <tuple>

using namespace std;
using namespace Intelligence_IS_V2;

void
serializableAttribute::serialize(cereal::JSONOutputArchive &ar) const
{
    ar(
        cereal::make_nvp("key", key),
        cereal::make_nvp("minConfidence", min_confidence)
    );
}

void
SerializableAttributesMap::save(cereal::JSONOutputArchive &ar) const
{
    if (requested_attributes.empty()) return;

    vector<serializableAttribute> all_attributes;
    for (auto const & iter : requested_attributes) {
        serializableAttribute attribute(iter.first, iter.second);
        all_attributes.push_back(attribute);
    }

    ar(cereal::make_nvp("requestedAttributes", all_attributes));
}

void
SerializableAttributesMap::setSerializableAttribute(const string &attribute, uint confidence)
{
    requested_attributes[attribute] = confidence;
};

uint
SerializableAttributesMap::getAttributeByKey(const string &key) const
{
    return requested_attributes.at(key);
}

bool
SerializableAttributesMap::checkMinConfidence(uint upper_confidence_limit)
{
    for (auto const &attribute : requested_attributes) {
        if (attribute.second == 0 || attribute.second > upper_confidence_limit) return false;
    }
    return true;
}
