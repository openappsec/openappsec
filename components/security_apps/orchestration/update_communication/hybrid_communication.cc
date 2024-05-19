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

#include "hybrid_communication.h"
#include "update_policy_notification.h"
#include "rest.h"
#include "config.h"
#include "log_generator.h"
#include "agent_details.h"
#include "version.h"

#include <algorithm>
#include <map>
#include <vector>

using namespace std;

USE_DEBUG_FLAG(D_ORCHESTRATOR);

static const string agent_resource_api = "/api/v2/agents/resources";

void
HybridCommunication::init()
{
    dbgTrace(D_ORCHESTRATOR) << "Initializing the Hybrid Communication Component";

    FogAuthenticator::init();
    i_declarative_policy = Singleton::Consume<I_DeclarativePolicy>::from<DeclarativePolicyUtils>();

    auto env_tuning_host = getenv("TUNING_HOST");
    tuning_host = env_tuning_host != nullptr ? env_tuning_host : "appsec-tuning-svc";

    if (getConfigurationFlag("otp") != "") {
        otp = getConfigurationFlag("otp");
    } else {
        otp = "cp-3fb5c718-5e39-47e6-8d5e-99b4bc5660b74b4b7fc8-5312-451d-a763-aaf7872703c0";
    }
}

Maybe<void>
HybridCommunication::getUpdate(CheckUpdateRequest &request)
{
    string manifest_checksum = "";
    dbgTrace(D_ORCHESTRATOR) << "Getting updates in Hybrid Communication";
    if (access_token.ok()) {
        auto request_status = Singleton::Consume<I_Messaging>::by<HybridCommunication>()->sendSyncMessage(
            HTTPMethod::POST,
            agent_resource_api,
            request
        );


        if (!request_status.ok()) {
            auto fog_err = request_status.getErr();
            dbgDebug(D_ORCHESTRATOR) << "Check update request fail. Error: " << fog_err.getBody();
            return genError(fog_err.getBody());
        }

        Maybe<string> maybe_new_manifest = request.getManifest();
        manifest_checksum = maybe_new_manifest.ok() ? maybe_new_manifest.unpack() : "";
    } else {
        dbgWarning(D_ORCHESTRATOR) << "Acccess Token not available.";
    }

    if (!i_declarative_policy->shouldApplyPolicy()) {
        request = CheckUpdateRequest(manifest_checksum, "", "", "", "", "");
        return Maybe<void>();
    }

    dbgTrace(D_ORCHESTRATOR) << "Getting policy update in Hybrid Communication";

    string policy_response = i_declarative_policy->getUpdate(request);

    doLocalFogOperations(policy_response);

    request = CheckUpdateRequest(manifest_checksum, policy_response, "", "", "", "");

    return Maybe<void>();
}

Maybe<string>
HybridCommunication::downloadAttributeFile(const GetResourceFile &resourse_file, const string &file_path)
{
    dbgTrace(D_ORCHESTRATOR)
        << "Downloading attribute file on hybrid mode, file name: "
        << resourse_file.getFileName();

    if (resourse_file.getFileName() =="policy") {
        string downloaded_file = i_declarative_policy->getCurrPolicy();
        auto *orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<HybridCommunication>();
        if (orchestration_tools->writeFile(downloaded_file, file_path)) return downloaded_file;
        return genError("Failed to write the attribute file in hybrid mode. File: " + downloaded_file);
    }
    if (resourse_file.getFileName() == "manifest") {
        if (!access_token.ok()) return genError("Acccess Token not available.");

        auto attribute_file = Singleton::Consume<I_Messaging>::by<HybridCommunication>()->downloadFile(
            resourse_file.getRequestMethod(),
            agent_resource_api + '/' + resourse_file.getFileName(),
            file_path
        );
        if (!attribute_file.ok()) {
            auto fog_err = attribute_file.getErr();
            return genError(fog_err.getBody());
        }
        return file_path;
    }
    dbgTrace(D_ORCHESTRATOR) << "Unnecessary attribute files downloading on hybrid mode";
    return string("");
}

Maybe<void>
HybridCommunication::sendPolicyVersion(const string &policy_version, const string &) const
{
    dbgFlow(D_ORCHESTRATOR);
    policy_version.empty();
    return Maybe<void>();
}

void
HybridCommunication::doLocalFogOperations(const string &policy) const
{
    if (policy.empty()) return;
    if (Singleton::Consume<I_EnvDetails>::by<HybridCommunication>()->getEnvType() != EnvType::K8S) return;

    dbgDebug(D_ORCHESTRATOR) << "Policy has changes, sending notification to tuning host";

    MessageMetadata update_policy_crd_md(tuning_host, 80);
    const auto &tenant_id = Singleton::Consume<I_AgentDetails>::by<HybridCommunication>()->getTenantId();
    update_policy_crd_md.insertHeader("X-Tenant-Id", tenant_id);

    UpdatePolicyCrdObject policy_change_object(policy);
    auto i_messaging = Singleton::Consume<I_Messaging>::by<HybridCommunication>();
    bool tuning_req_status = i_messaging->sendSyncMessageWithoutResponse(
        HTTPMethod::POST,
        "/api/update-policy-crd",
        policy_change_object,
        MessageCategory::GENERIC,
        update_policy_crd_md
    );

    if (!tuning_req_status) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to send tuning notification";
    } else {
        dbgDebug(D_ORCHESTRATOR) << "Successfully sent tuning policy update notification";
    }

}
