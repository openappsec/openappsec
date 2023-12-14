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
using HTTPMethod = I_Messaging::Method;

USE_DEBUG_FLAG(D_ORCHESTRATOR);

#define TUNING_HOST_ENV_NAME "TUNING_HOST"
static const string defaultTuningHost = "appsec-tuning-svc";

void
HybridCommunication::init()
{
    FogAuthenticator::init();
    i_declarative_policy = Singleton::Consume<I_DeclarativePolicy>::from<DeclarativePolicyUtils>();
    dbgTrace(D_ORCHESTRATOR) << "Initializing the Hybrid Communication Component";
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

    if (!i_declarative_policy->shouldApplyPolicy()) {
        request = CheckUpdateRequest(manifest_checksum, "", "", "", "", "");
        return Maybe<void>();
    }

    dbgTrace(D_ORCHESTRATOR) << "Getting policy update in Hybrid Communication";

    string policy_response = i_declarative_policy->getUpdate(request);

    auto env = Singleton::Consume<I_EnvDetails>::by<HybridCommunication>()->getEnvType();
    if (env == EnvType::K8S && !policy_response.empty()) {
        dbgDebug(D_ORCHESTRATOR) << "Policy has changes, sending notification to tuning host";
        I_AgentDetails *agentDetails = Singleton::Consume<I_AgentDetails>::by<HybridCommunication>();
        I_Messaging *messaging = Singleton::Consume<I_Messaging>::by<HybridCommunication>();

        UpdatePolicyCrdObject policy_change_object(policy_response);

        Flags<MessageConnConfig> conn_flags;
        conn_flags.setFlag(MessageConnConfig::EXTERNAL);

        string tenant_header = "X-Tenant-Id: " + agentDetails->getTenantId();

        auto get_tuning_host = []()
            {
                static string tuning_host;
                if (tuning_host != "") return tuning_host;

                char* tuning_host_env = getenv(TUNING_HOST_ENV_NAME);
                if (tuning_host_env != NULL) {
                    tuning_host = string(tuning_host_env);
                    return tuning_host;
                }
                dbgWarning(D_ORCHESTRATOR) << "tuning host is not set. using default";
                tuning_host = defaultTuningHost;

                return tuning_host;
            };

        bool ok = messaging->sendNoReplyObject(
            policy_change_object,
            I_Messaging::Method::POST,
            get_tuning_host(),
            80,
            conn_flags,
            "/api/update-policy-crd",
            tenant_header
        );
        dbgDebug(D_ORCHESTRATOR) << "sent tuning policy update notification ok: " << ok;
        if (!ok) {
            dbgWarning(D_ORCHESTRATOR) << "failed to send  tuning notification";
        }
    }

    request = CheckUpdateRequest(manifest_checksum, policy_response, "", "", "", "");

    return Maybe<void>();
}

Maybe<string>
HybridCommunication::downloadAttributeFile(const GetResourceFile &resourse_file)
{
    dbgTrace(D_ORCHESTRATOR)
        << "Downloading attribute file on hybrid mode, file name: "
        << resourse_file.getFileName();

    if (resourse_file.getFileName() =="policy") {
        return i_declarative_policy->getCurrPolicy();
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
HybridCommunication::sendPolicyVersion(const string &policy_version, const string &) const
{
    dbgFlow(D_ORCHESTRATOR);
    policy_version.empty();
    return Maybe<void>();
}
