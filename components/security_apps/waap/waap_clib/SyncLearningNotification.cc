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

#include "SyncLearningNotification.h"

SyncLearningNotificationObject::SyncLearningNotificationObject(const std::string& asset_id,
    const std::string& type,
    const std::string& window_id) :
    m_asset_id(asset_id),
    m_type(type),
    m_window_id(window_id)
{

}

SyncLearningNotificationObject::~SyncLearningNotificationObject()
{

}

void SyncLearningNotificationObject::serialize(cereal::JSONOutputArchive& ar) const
{
    ar.setNextName("notificationConsumerData");
    ar.startNode();
    ar.setNextName("syncLearnNotificationConsumers");
    ar.startNode();
    ar(cereal::make_nvp("assetId", m_asset_id));
    ar(cereal::make_nvp("type", m_type));
    ar(cereal::make_nvp("windowId", m_window_id));
    ar.finishNode();
    ar.finishNode();
}

std::string SyncLearningNotificationObject::toString() const
{
    std::stringstream ss;
    {
        cereal::JSONOutputArchive ar(ss);
        serialize(ar);
    }

    return ss.str();
}

std::ostream& operator<<(std::ostream& os, const SyncLearningNotificationObject& obj)
{
    return os << obj.toString();
}
