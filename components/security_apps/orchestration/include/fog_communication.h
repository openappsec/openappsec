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

#ifndef __FOG_COMMUNICATION_H__
#define __FOG_COMMUNICATION_H__

#include <chrono>
#include <functional>
#include <tuple>
#include <vector>
#include "cereal/archives/json.hpp"

#include "i_update_communication.h"
#include "fog_authenticator.h"
#include "i_orchestration_tools.h"
#include "i_agent_details.h"
#include "i_orchestration_status.h"
#include "i_messaging.h"
#include "i_mainloop.h"
#include "i_encryptor.h"
#include "i_details_resolver.h"
#include "i_rest_api.h"
#include "i_time_get.h"
#include "i_encryptor.h"
#include "maybe_res.h"
#include "declarative_policy_utils.h"

class FogCommunication : public FogAuthenticator
{
public:
    void init() override;
    Maybe<void> getUpdate(CheckUpdateRequest &request) override;
    Maybe<std::string> downloadAttributeFile(const GetResourceFile &resourse_file) override;
    Maybe<void> sendPolicyVersion(
        const std::string &policy_version,
        const std::string &policy_versions
    ) const override;

private:
    I_DeclarativePolicy *i_declarative_policy = nullptr;
};

#endif // __FOG_COMMUNICATION_H__
