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

#ifndef __GET_STATUS_RES_H__
#define __GET_STATUS_RES_H__

#include "i_messaging.h"
#include "i_mainloop.h"
#include "i_shell_cmd.h"
#include "i_encryptor.h"
#include "i_orchestration_status.h"
#include "i_rest_api.h"
#include "i_orchestration_tools.h"
#include "i_downloader.h"
#include "i_service_controller.h"
#include "i_manifest_controller.h"
#include "i_update_communication.h"
#include "i_details_resolver.h"
#include "i_shell_cmd.h"
#include "i_agent_details.h"
#include "i_environment.h"
#include "i_tenant_manager.h"
#include "i_package_handler.h"
#include "component.h"

class getStatusRest : public ServerRest
{
public:
    void
    doCall() override
    {
        auto i_orch_status = Singleton::Consume<I_OrchestrationStatus>::by<OrchestrationComp>();

        policies = "";
        settings = "";
        for (auto &policy: i_orch_status->getServicePolicies()) {
            policies = policies.get() + "\n    " + policy.first + ": " + policy.second;
        }
        for (auto &setting: i_orch_status->getServiceSettings()) {
            settings = settings.get() + "\n    " + setting.first + ": " + setting.second;
        }

        last_update_attempt = i_orch_status->getLastUpdateAttempt();
        last_update = i_orch_status->getUpdateTime();
        last_update_status = i_orch_status->getUpdateStatus();
        policy_version = i_orch_status->getPolicyVersion();
        last_policy_update = i_orch_status->getLastPolicyUpdate();
        last_manifest_update = i_orch_status->getLastManifestUpdate();
        last_settings_update = i_orch_status->getLastSettingsUpdate();
        registration_status = i_orch_status->getRegistrationStatus();
        manifest_status = i_orch_status->getManifestStatus();
        upgrade_mode = i_orch_status->getUpgradeMode();
        fog_address = i_orch_status->getFogAddress();
        agent_id = i_orch_status->getAgentId();
        profile_id = i_orch_status->getProfileId();
        tenant_id = i_orch_status->getTenantId();
        registration_details = i_orch_status->getRegistrationDetails();
    }

private:
    S2C_LABEL_PARAM(std::string, last_update_attempt, "Last update attempt");
    S2C_LABEL_PARAM(std::string, last_update, "Last update");
    S2C_LABEL_PARAM(std::string, last_update_status, "Last update status");
    S2C_LABEL_PARAM(std::string, policy_version, "Policy version");
    S2C_LABEL_PARAM(std::string, last_policy_update, "Last policy update");
    S2C_LABEL_PARAM(std::string, last_manifest_update, "Last manifest update");
    S2C_LABEL_PARAM(std::string, last_settings_update, "Last settings update");
    S2C_LABEL_PARAM(std::string, registration_status, "Registration status");
    S2C_LABEL_PARAM(std::string, manifest_status, "Manifest status");
    S2C_LABEL_PARAM(std::string, upgrade_mode, "Upgrade mode");
    S2C_LABEL_PARAM(std::string, fog_address, "Fog address");
    S2C_LABEL_PARAM(std::string, agent_id, "Agent ID");
    S2C_LABEL_PARAM(std::string, profile_id, "Profile ID");
    S2C_LABEL_PARAM(std::string, tenant_id, "Tenant ID");
    S2C_LABEL_PARAM(std::string, registration_details, "Registration details");
    S2C_LABEL_PARAM(std::string, policies, "Service policy");
    S2C_LABEL_PARAM(std::string, settings, "Service settings");
};

#endif // __GET_STATUS_RES_H__
