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

#ifndef __SYNC_LEARNING_NOTIFICATION_OBJECT_H__
#define __SYNC_LEARNING_NOTIFICATION_OBJECT_H__

#include <string>
#include <ostream>
#include "cereal/archives/json.hpp"
#include "report/report.h"
#include "rest.h"

class SyncLearningNotificationObject
{
public:
    explicit SyncLearningNotificationObject(
        const std::string& asset_id,
        const std::string& type,
        const std::string& window_id
    );
    ~SyncLearningNotificationObject();
    void serialize(cereal::JSONOutputArchive& ar) const;

    friend std::ostream& operator<<(std::ostream& os, const SyncLearningNotificationObject& obj);

private:
    std::string toString() const;

    std::string m_asset_id;
    std::string m_type;
    std::string m_window_id;
};

class SyncLearningObject : public ClientRest
{
public:
    SyncLearningObject(
        const std::string& _asset_id,
        const std::string& _type,
        const std::string& _window_id
    ) : assetId(_asset_id), type(_type), windowId(_window_id) {}

private:
    C2S_PARAM(std::string, assetId);
    C2S_PARAM(std::string, type);
    C2S_PARAM(std::string, windowId);
};

#endif
