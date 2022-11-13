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
using HTTPMethod = I_Messaging::Method;

USE_DEBUG_FLAG(D_ORCHESTRATOR);

void
HybridCommunication::init()
{
    FogAuthenticator::init();
    dbgTrace(D_ORCHESTRATOR) << "Initializing the Hybrid Communication Component";
    if (getConfigurationFlag("otp") != "") {
        otp = getConfigurationFlag("otp");
    } else {
        otp = "cp-3fb5c718-5e39-47e6-8d5e-99b4bc5660b74b4b7fc8-5312-451d-a763-aaf7872703c0";
    }
}

string
HybridCommunication::getChecksum(const string &policy_version)
{
    string clean_plicy_version = policy_version;
    if (!clean_plicy_version.empty() && clean_plicy_version[clean_plicy_version.size() - 1] == '\n') {
        clean_plicy_version.erase(clean_plicy_version.size() - 1);
    }

    curr_policy = Singleton::Consume<I_LocalPolicyMgmtGen>::by<HybridCommunication>()->parsePolicy(clean_plicy_version);

    I_OrchestrationTools *orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<FogAuthenticator>();
    Maybe<string> file_checksum = orchestration_tools->calculateChecksum(
        I_OrchestrationTools::SELECTED_CHECKSUM_TYPE,
        Singleton::Consume<I_LocalPolicyMgmtGen>::by<HybridCommunication>()->getPolicyPath()
    );

    if (!file_checksum.ok()) {
        dbgWarning(D_ORCHESTRATOR) << "Failed the policy checksum calculation";
        return "";
    }
    return file_checksum.unpack();
}

Maybe<string>
HybridCommunication::getNewVersion()
{
    I_OrchestrationTools *orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<FogAuthenticator>();
    auto env = Singleton::Consume<I_LocalPolicyMgmtGen>::by<HybridCommunication>()->getEnvType();
    if (env == I_LocalPolicyMgmtGen::LocalPolicyEnv::K8S) {
        return orchestration_tools->readFile("/etc/cp/conf/k8s-policy-check.trigger");
    }

    string policy_path = getConfigurationFlagWithDefault(
        getFilesystemPathConfig() + "/conf/local_policy.yaml",
        "local_mgmt_policy"
    );

    Maybe<string> file_checksum = orchestration_tools->calculateChecksum(
        I_OrchestrationTools::SELECTED_CHECKSUM_TYPE,
        policy_path
    );

    if (!file_checksum.ok()) {
        dbgWarning(D_ORCHESTRATOR) << "Policy checksum was not calculated: " << file_checksum.getErr();
        return genError(file_checksum.getErr());
    }

    return file_checksum.unpack();
}

Maybe<void>
HybridCommunication::getUpdate(CheckUpdateRequest &request)
{
    string manifest_checksum = "";
    dbgTrace(D_ORCHESTRATOR) << "Getting updates in Hybrid Communication";
    if (access_token.ok()) {
        static const string check_update_str = "/api/v2/agents/resources";
        auto request_status = Singleton::Consume<I_Messaging>::by<HybridCommunication>()->sendObject(
            request,
            HTTPMethod::POST,
            fog_address_ex + check_update_str,
            buildOAuth2Header((*access_token).getToken())
        );

        if (!request_status) {
            dbgWarning(D_ORCHESTRATOR) << "Failed to get response after check update request.";
            return genError("Failed to request updates");
        }

        Maybe<string> maybe_new_manifest = request.getManifest();
        manifest_checksum = maybe_new_manifest.ok() ? maybe_new_manifest.unpack() : "";
    } else {
        dbgWarning(D_ORCHESTRATOR) << "Acccess Token not available.";
    }

    dbgTrace(D_ORCHESTRATOR) << "Getting policy update in Hybrid Communication";

    auto maybe_new_version = getNewVersion();
    if (!maybe_new_version.ok() || maybe_new_version == curr_version) {
        request = CheckUpdateRequest(manifest_checksum, "", "", "", "", "");
        dbgDebug(D_ORCHESTRATOR) << "No new version is currently available";
        return Maybe<void>();
    }

    auto policy_checksum = request.getPolicy();

    auto offline_policy_checksum = getChecksum(maybe_new_version.unpack());

    string policy_response = "";

    if (!policy_checksum.ok() || offline_policy_checksum != policy_checksum.unpack()) {
        policy_response = offline_policy_checksum;
    }

    dbgDebug(D_ORCHESTRATOR)
        << "Local update response: "
        << " policy: "
        << (policy_response.empty() ? "has no change," : "has new update," );

    request = CheckUpdateRequest(manifest_checksum, policy_response, "", "", "", "");
    curr_version = *maybe_new_version;

    return Maybe<void>();
}

Maybe<string>
HybridCommunication::downloadAttributeFile(const GetResourceFile &resourse_file)
{
    dbgTrace(D_ORCHESTRATOR)
        << "Downloading attribute file on hybrid mode, file name: "
        << resourse_file.getFileName();

    if (resourse_file.getFileName() == "policy") {
        return curr_policy;
    }


    if (resourse_file.getFileName() == "manifest") {
        if (!access_token.ok()) return genError("Acccess Token not available.");

        auto unpacked_access_token = access_token.unpack().getToken();

        static const string file_attribute_str = "/api/v2/agents/resources/";
        Maybe<string> attribute_file = Singleton::Consume<I_Messaging>::by<HybridCommunication>()->downloadFile(
            resourse_file,
            resourse_file.getRequestMethod(),
            fog_address_ex + file_attribute_str + resourse_file.getFileName(),
            buildOAuth2Header((*access_token).getToken()) // Header
        );
        return attribute_file;
    }

    dbgTrace(D_ORCHESTRATOR) << "Unnecessary attribute files downloading on hybrid mode";
    return string("");
}

Maybe<void>
HybridCommunication::sendPolicyVersion(const string &policy_version) const
{
    dbgFlow(D_ORCHESTRATOR);
    policy_version.empty();
    return Maybe<void>();
}

SASAL_END
