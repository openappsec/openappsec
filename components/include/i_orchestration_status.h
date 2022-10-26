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

#ifndef __I_ORCHESTRATION_STATUS_H__
#define __I_ORCHESTRATION_STATUS_H__

#include <string>
#include <chrono>
#include <cereal/archives/json.hpp>

#include "enum_array.h"

enum class OrchestrationStatusResult { SUCCESS, FAILED };
enum class OrchestrationStatusFieldType { REGISTRATION, MANIFEST, LAST_UPDATE, COUNT };
enum class OrchestrationStatusConfigType { MANIFEST, POLICY, SETTINGS, DATA, COUNT };

class I_OrchestrationStatus
{
public:
    virtual void writeStatusToFile() = 0;

    virtual const std::string & getLastUpdateAttempt() const = 0;
    virtual const std::string & getUpdateStatus() const = 0;
    virtual const std::string & getUpdateTime() const = 0;
    virtual const std::string & getLastManifestUpdate() const = 0;
    virtual const std::string & getPolicyVersion() const = 0;
    virtual const std::string & getLastPolicyUpdate() const = 0;
    virtual const std::string & getLastSettingsUpdate() const = 0;
    virtual const std::string & getUpgradeMode() const = 0;
    virtual const std::string & getFogAddress() const = 0;
    virtual const std::string & getRegistrationStatus() const = 0;
    virtual const std::string & getAgentId() const = 0;
    virtual const std::string & getProfileId() const = 0;
    virtual const std::string & getTenantId() const = 0;
    virtual const std::string & getManifestStatus() const = 0;
    virtual const std::string & getManifestError() const = 0;
    virtual const std::map<std::string, std::string> & getServicePolicies() const = 0;
    virtual const std::map<std::string, std::string> & getServiceSettings() const = 0;
    virtual const std::string getRegistrationDetails() const = 0;
    virtual void recoverFields() = 0;
    virtual void setIsConfigurationUpdated(EnumArray<OrchestrationStatusConfigType, bool> config_types) = 0;
    virtual void setFogAddress(const std::string &_fog_address) = 0;
    virtual void setLastUpdateAttempt() = 0;
    virtual void setPolicyVersion(const std::string &_policy_version) = 0;
    virtual void setRegistrationStatus(const std::string &_reg_status) = 0;
    virtual void setUpgradeMode(const std::string &_upgrade_mode) = 0;
    virtual void setAgentType(const std::string &_agent_type) = 0;
    virtual void setAgentDetails(
        const std::string &_agent_id,
        const std::string &_profile_id,
        const std::string &_tenant_id
    ) = 0;

    virtual void
    setFieldStatus(
        const OrchestrationStatusFieldType &field_type_status,
        const OrchestrationStatusResult &status,
        const std::string &failure_reason = ""
    ) = 0;

    virtual void
    setRegistrationDetails(
        const std::string &name,
        const std::string &type,
        const std::string &platform,
        const std::string &arch
    ) = 0;

    virtual void
    setServiceConfiguration(
        const std::string &service_name,
        const std::string &path,
        const OrchestrationStatusConfigType &configuration_file_type
    ) = 0;
};

#endif // __I_ORCHESTRATION_STATUS_H__
