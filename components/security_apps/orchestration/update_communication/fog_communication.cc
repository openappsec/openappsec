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

#include <algorithm>
#include <map>
#include <vector>

using namespace std;
using namespace cereal;

USE_DEBUG_FLAG(D_ORCHESTRATOR);

void
FogCommunication::init()
{
    FogAuthenticator::init();
    i_declarative_policy = Singleton::Consume<I_DeclarativePolicy>::from<DeclarativePolicyUtils>();
}

Maybe<void>
FogCommunication::getUpdate(CheckUpdateRequest &request)
{
    dbgTrace(D_ORCHESTRATOR) << "Getting updates - fog Communication";
    if (!access_token.ok()) return genError("Acccess Token not available.");

    auto unpacked_access_token = access_token.unpack().getToken();
    static const string check_update_str = "/api/v2/agents/resources";
    auto response = Singleton::Consume<I_Messaging>::by<FogCommunication>()->sendSyncMessage(
        HTTPMethod::POST,
        check_update_str,
        request
    );

    if (!response.ok()) {
        const auto &fog_err = response.getErr();
        dbgDebug(D_ORCHESTRATOR) << "Check update request fail. Error: " << fog_err.getBody();
        return genError(fog_err.getBody());
    }

    string policy_mgmt_mode = getSettingWithDefault<string>("management", "profileManagedMode");
    dbgTrace(D_ORCHESTRATOR) << "Profile managed mode: " << policy_mgmt_mode;
    if (policy_mgmt_mode == "declarative") {
        Maybe<string> maybe_new_manifest = request.getManifest();
        string manifest_checksum = maybe_new_manifest.ok() ? maybe_new_manifest.unpack() : "";

        Maybe<string> maybe_new_settings = request.getSettings();
        string settings_checksum = maybe_new_settings.ok() ? maybe_new_settings.unpack() : "";

        Maybe<string> maybe_new_data = request.getData();
        string data_checksum = maybe_new_data.ok() ? maybe_new_data.unpack() : "";

        if (i_declarative_policy->shouldApplyPolicy()) {
            string policy_response = i_declarative_policy->getUpdate(request);
            if (!policy_response.empty()) {
                dbgTrace(D_ORCHESTRATOR) << "Apply policy - declarative mode";
                auto agent_details = Singleton::Consume<I_AgentDetails>::by<DeclarativePolicyUtils>();
                auto maybe_fog_address = agent_details->getFogDomain();
                string fog_address = maybe_fog_address.ok() ? maybe_fog_address.unpack() : "";

                i_declarative_policy->sendUpdatesToFog(
                    unpacked_access_token,
                    agent_details->getTenantId(),
                    agent_details->getProfileId(),
                    fog_address
                );
            }
            request = CheckUpdateRequest(manifest_checksum, policy_response, settings_checksum, data_checksum, "", "");
        } else {
            request = CheckUpdateRequest(manifest_checksum, "", settings_checksum, data_checksum, "", "");
        }
    }

    dbgDebug(D_ORCHESTRATOR) << "Got response after check update request.";
    return Maybe<void>();
}

Maybe<string>
FogCommunication::downloadAttributeFile(const GetResourceFile &resourse_file, const string &file_path)
{
    if (!access_token.ok()) return genError("Acccess Token not available.");

    string policy_mgmt_mode = getSettingWithDefault<string>("management", "profileManagedMode");
    if (policy_mgmt_mode == "declarative" && resourse_file.getFileName() =="policy") {
        dbgDebug(D_ORCHESTRATOR) << "Download policy on declarative mode - returning the local policy";
        string policy = i_declarative_policy->getCurrPolicy();
        auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<FogCommunication>();
        if (orchestration_tools->writeFile(policy, file_path)) return policy;
        return genError("Failed to write policy to file: " + file_path);
    }
    static const string file_attribute_str = "/api/v2/agents/resources/";

    auto attribute_file = Singleton::Consume<I_Messaging>::by<FogCommunication>()->downloadFile(
        resourse_file.getRequestMethod(),
        file_attribute_str + resourse_file.getFileName(),
        file_path
    );
    if (!attribute_file.ok()) {
        const auto &fog_err = attribute_file.getErr();
        return genError(fog_err.getBody());
    }
    return file_path;
}

Maybe<void>
FogCommunication::sendPolicyVersion(const string &policy_version, const string &policy_versions) const
{
    dbgTrace(D_ORCHESTRATOR)
        << "Sending patch request to the fog. Policy version: "
        << policy_version
        << " , Policy versions: "
        << policy_versions;
    PolicyVersionPatchRequest request(policy_version, policy_versions);
    auto request_status = Singleton::Consume<I_Messaging>::by<FogCommunication>()->sendSyncMessageWithoutResponse(
        HTTPMethod::PATCH,
        "/agents",
        request
    );
    if (request_status) {
        dbgTrace(D_ORCHESTRATOR)
            << "Patch request was sent successfully to the fog."
            << " Policy versions: "
            << policy_versions
            << " Policy version: "
            << policy_version;
        return Maybe<void>();
    }
    return genError("Failed to patch policy version");
}
