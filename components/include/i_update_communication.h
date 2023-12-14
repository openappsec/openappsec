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

#ifndef __I_UPDATE_COMMUNICATION_H__
#define __I_UPDATE_COMMUNICATION_H__

#include "maybe_res.h"
#include "orchestrator/rest_api/get_resource_file.h"
#include "orchestrator/rest_api/orchestration_check_update.h"

using OrchManifest  = Maybe<std::string>;
using OrchPolicy    = Maybe<std::string>;
using OrchSettings  = Maybe<std::string>;
using OrchData      = Maybe<std::string>;

class I_UpdateCommunication
{
public:
    virtual void init() = 0;
    virtual Maybe<void> sendPolicyVersion(
        const std::string &policy_version,
        const std::string &policy_versions
    ) const = 0;
    virtual Maybe<void> authenticateAgent() = 0;
    virtual Maybe<void> getUpdate(CheckUpdateRequest &request) = 0;
    virtual Maybe<std::string> downloadAttributeFile(const GetResourceFile &resourse_file) = 0;
    virtual void setAddressExtenesion(const std::string &extension) = 0;
};

#endif // __I_UPDATE_COMMUNICATION_H__
