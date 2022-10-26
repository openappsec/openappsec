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

#ifndef __FIRST_REQUEST_NOTIFICATION_OBJECT_H__
#define __FIRST_REQUEST_NOTIFICATION_OBJECT_H__

#include <string>
#include <ostream>
#include "cereal/archives/json.hpp"
#include "report/report.h"

class FirstRequestNotificationObject
{
public:
    explicit FirstRequestNotificationObject(
        std::string asset_id,
        std::string asset_name,
        ReportIS::Severity severity
    );
    virtual ~FirstRequestNotificationObject();
    void serialize(cereal::JSONOutputArchive& ar) const;

    friend std::ostream& operator<<(std::ostream& os, const FirstRequestNotificationObject& obj);

private:
    std::string toString() const;

    std::string m_asset_id;
    std::string m_asset_name;
    ReportIS::Severity m_severity;
};
#endif
