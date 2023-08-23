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

#ifndef __LOCAL_COMMUNICATION_H__
#define __LOCAL_COMMUNICATION_H__

#include "i_update_communication.h"
#include "i_orchestration_tools.h"
#include "maybe_res.h"

class LocalCommunication
        :
    public I_UpdateCommunication,
    Singleton::Consume<I_OrchestrationTools>
{
public:
    static void preload();

    void init();

    Maybe<void> authenticateAgent() override;
    Maybe<void> getUpdate(CheckUpdateRequest &request) override;

    Maybe<std::string> downloadAttributeFile(const GetResourceFile &resourse_file) override;
    void setAddressExtenesion(const std::string &extension) override;
    Maybe<void> sendPolicyVersion(
        const std::string &policy_version,
        const std::string &policy_versions
    ) const override;

private:
    std::string getChecksum(const std::string &file_path);
    std::string filesystem_prefix = "";
};

#endif // __LOCAL_COMMUNICATION_H__
