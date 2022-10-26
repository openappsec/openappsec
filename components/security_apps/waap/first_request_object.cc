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

#include "first_request_object.h"
#include "tag_and_enum_management.h"

FirstRequestNotificationObject::FirstRequestNotificationObject(
    std::string asset_id,
    std::string asset_name,
    ReportIS::Severity severity
):
    m_asset_id(asset_id),
    m_asset_name(asset_name),
    m_severity(severity)
{}

FirstRequestNotificationObject::~FirstRequestNotificationObject()
{}

void FirstRequestNotificationObject::serialize(cereal::JSONOutputArchive& ar) const
{
    ar.setNextName("notificationConsumerData");
    ar.startNode();
    ar.setNextName("firstRequestNotificationConsumers");
    ar.startNode();
    ar(cereal::make_nvp("assetId", m_asset_id));
    ar(cereal::make_nvp("assetName", m_asset_name));
    ar(cereal::make_nvp("originalEventSeverity", TagAndEnumManagement::convertToString(m_severity)));
    ar.finishNode();
    ar.finishNode();
}

std::string FirstRequestNotificationObject::toString() const
{
    std::stringstream ss;
    {
        cereal::JSONOutputArchive ar(ss);
        serialize(ar);
    }

    return ss.str();
}

std::ostream& operator<<(std::ostream& os, const FirstRequestNotificationObject& obj)
{
    return os << obj.toString();
}
