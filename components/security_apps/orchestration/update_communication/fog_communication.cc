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

#include "fog_communication.h"
#include "rest.h"
#include "config.h"
#include "log_generator.h"
#include "agent_details.h"
#include "version.h"
#include "sasal.h"

#include <algorithm>
#include <map>
#include <vector>

SASAL_START // Orchestration - Communication

using namespace std;
using namespace cereal;
using HTTPMethod = I_Messaging::Method;

USE_DEBUG_FLAG(D_ORCHESTRATOR);

Maybe<void>
FogCommunication::getUpdate(CheckUpdateRequest &request)
{
    if (!access_token.ok()) return genError("Acccess Token not available.");

    auto unpacked_access_token = access_token.unpack().getToken();
    static const string check_update_str = "/api/v2/agents/resources";
    auto request_status = Singleton::Consume<I_Messaging>::by<FogCommunication>()->sendObject(
        request,
        HTTPMethod::POST,
        fog_address_ex + check_update_str,
        buildOAuth2Header(unpacked_access_token)
    );

    if (!request_status) {
        dbgDebug(D_ORCHESTRATOR) << "Failed to get response after check update request.";
        return genError("Failed to request updates");
    }
    dbgDebug(D_ORCHESTRATOR) << "Got response after check update request.";
    return Maybe<void>();
}

Maybe<string>
FogCommunication::downloadAttributeFile(const GetResourceFile &resourse_file)
{
    if (!access_token.ok()) return genError("Acccess Token not available.");

    auto unpacked_access_token = access_token.unpack().getToken();

    static const string file_attribute_str = "/api/v2/agents/resources/";
    Maybe<string> attribute_file = Singleton::Consume<I_Messaging>::by<FogCommunication>()->downloadFile(
        resourse_file,
        resourse_file.getRequestMethod(),
        fog_address_ex + file_attribute_str + resourse_file.getFileName(),
        buildOAuth2Header(unpacked_access_token) // Header
    );

    return attribute_file;
}

Maybe<void>
FogCommunication::sendPolicyVersion(const string &policy_version) const
{
    PolicyVersionPatchRequest request(policy_version);
    auto fog_messaging = Singleton::Consume<I_Messaging>::by<FogCommunication>();
    if (fog_messaging->sendNoReplyObject(request, HTTPMethod::PATCH, fog_address_ex + "/agents")) {
        dbgInfo(D_ORCHESTRATOR)
            << "Patch request was sent successfully to the fog."
            << " Policy version: "
            << policy_version;
        return Maybe<void>();
    }
    return genError("Failed to patch policy version");
}

SASAL_END
