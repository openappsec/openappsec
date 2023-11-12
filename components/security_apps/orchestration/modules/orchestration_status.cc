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

#include "orchestration_status.h"

#include <string>
#include <chrono>
#include <algorithm>

#include "debug.h"
#include "config.h"

using namespace cereal;
using namespace std;
using namespace chrono;

USE_DEBUG_FLAG(D_ORCHESTRATOR);

class RegistrationDetails
{
public:
    RegistrationDetails() = default;
    RegistrationDetails(const RegistrationDetails &) = default;
    RegistrationDetails(RegistrationDetails &&) = default;
    RegistrationDetails(
        string name,
        string type,
        string platform,
        string architecture)
            :
        name(name),
        type(type),
        platform(platform),
        architecture(architecture)
    {}

    void
    serialize(cereal::JSONOutputArchive &archive)
    {
        if (type == "InfinityNextGateway") {
            type = "AppSecGateway";
        }
        archive(
            cereal::make_nvp("Name",            name),
            cereal::make_nvp("Type",            type),
            cereal::make_nvp("Platform",        platform),
            cereal::make_nvp("Architecture",    architecture)
        );
    }

    void
    serialize(cereal::JSONInputArchive &archive)
    {
        archive(
            cereal::make_nvp("Name",            name),
            cereal::make_nvp("Type",            type),
            cereal::make_nvp("Platform",        platform),
            cereal::make_nvp("Architecture",    architecture)
        );
        if (type == "InfinityNextGateway") {
            type = "AppSecGateway";
        }
    }

    RegistrationDetails & operator=(const RegistrationDetails &) = default;
    RegistrationDetails & operator=(RegistrationDetails &&) = default;
    void setAgentType(const string &_type) { type = _type; }

    string
    toString() const
    {
        return
            "\n    Name: " + name +
            "\n    Type: " + type +
            "\n    Platform: " + platform +
            "\n    Architecture: " + architecture;
    }

private:
    string name;
    string type;
    string platform;
    string architecture;
};

class Status
{
public:
    Status() = default;
    Status(const Status &) = default;
    Status(Status &&) = default;

    Status & operator=(Status &&from) = default;
    Status & operator=(const Status &from)
    {
        last_update_status = from.last_update_status;
        last_update_time = from.last_update_time;
        last_update_attempt = from.last_update_attempt;
        last_manifest_update = from.last_manifest_update;
        policy_version = from.policy_version;
        last_policy_update = from.last_policy_update;
        last_settings_update = from.last_settings_update;
        upgrade_mode = from.upgrade_mode;
        fog_address = from.fog_address;
        registration_status = from.registration_status;
        manifest_status = from.manifest_status;
        agent_id = from.agent_id;
        profile_id = from.profile_id;
        tenant_id = from.tenant_id;
        registration_details = from.registration_details;
        service_policies = from.service_policies;
        service_settings = from.service_settings;
        return *this;
    }

    const string & getLastUpdateAttempt() const                      { return last_update_attempt; }
    const string & getUpdateStatus() const                           { return last_update_status; }
    const string & getUpdateTime() const                             { return last_update_time; }
    const string & getLastManifestUpdate() const                     { return last_manifest_update; }
    const string & getPolicyVersion() const                          { return policy_version; }
    const string & getLastPolicyUpdate() const                       { return last_policy_update; }
    const string & getLastSettingsUpdate() const                     { return last_settings_update; }
    const string & getUpgradeMode() const                            { return upgrade_mode; }
    const string & getFogAddress() const                             { return fog_address; }
    const string & getRegistrationStatus() const                     { return registration_status; }
    const string & getAgentId() const                                { return agent_id; }
    const string & getProfileId() const                              { return profile_id; }
    const string & getTenantId() const                               { return tenant_id; }
    const string & getManifestStatus() const                         { return manifest_status; }
    const string & getManifestError() const                          { return manifest_error; }
    const RegistrationDetails & getRegistrationDetails() const       { return registration_details; }
    const map<string, string> & getServicePolicies() const { return service_policies; }
    const map<string, string> & getServiceSettings() const { return service_settings; }

    void
    insertServicePolicy(const string &key, const string &value)
    {
        service_policies.insert(make_pair(key, value));
    }

    void
    eraseServicePolicy(const string &key)
    {
        service_policies.erase(key);
    }

    void
    insertServiceSetting(const string &key, const string &value)
    {
        service_settings.insert(make_pair(key, value));
    }

    void
    eraseServiceSetting(const string &key)
    {
        service_settings.erase(key);
    }

    void
    setIsConfigurationUpdated(
        EnumArray<OrchestrationStatusConfigType, bool> config_types,
        const string &current_time
    )
    {
        if (config_types[OrchestrationStatusConfigType::MANIFEST]) last_manifest_update = current_time;
        if (config_types[OrchestrationStatusConfigType::POLICY]) last_policy_update = current_time;
        if (config_types[OrchestrationStatusConfigType::SETTINGS]) last_settings_update = current_time;
    }

    void
    setPolicyVersion(const string &_policy_version)
    {
        policy_version = _policy_version;
    }

    void
    setRegistrationStatus(const string &_reg_status)
    {
        registration_status = _reg_status;
    }

    void
    setUpgradeMode(const string &_upgrade_mode)
    {
        upgrade_mode = _upgrade_mode;
    }

    void
    setAgentType(const string &_agent_type)
    {
        registration_details.setAgentType(_agent_type);
    }

    void
    setAgentDetails(
        const string &_agent_id,
        const string &_profile_id,
        const string &_tenant_id)
    {
        agent_id = _agent_id;
        profile_id = _profile_id;
        tenant_id = _tenant_id;
    }

    void
    setLastUpdateAttempt(const string &_last_update_attempt)
    {
        last_update_attempt = _last_update_attempt;
    }

    void
    setFogAddress(const string &_fog_address)
    {
        fog_address = _fog_address;
    }

    void
    setRegistrationDetails(
        const string &name,
        const string &type,
        const string &platform,
        const string &arch)
    {
        registration_details = RegistrationDetails(name, type, platform, arch);
    }

    void
    setManifestStatus(const string &_manifest_status)
    {
        manifest_status = _manifest_status;
    }

    void
    setManifestError(const string &error)
    {
        manifest_error = error;
    }

    void
    setLastUpdateTime(const string &_last_update_time)
    {
        last_update_time = _last_update_time;
    }

    void
    setLastUpdateStatus(const string &_last_update_status)
    {
        last_update_status = _last_update_status;
    }

    void
    initValues()
    {
        last_update_attempt = "None";
        last_update_time = "None";
        last_update_status = "None";
        last_manifest_update = "None";
        last_policy_update = "None";
        last_settings_update = "None";
        fog_address = "None";
        agent_id = "None";
        profile_id = "None";
        tenant_id = "None";
        registration_status = "None";
        manifest_status = getenv("CLOUDGUARD_APPSEC_STANDALONE") ? "Succeeded" : "None";
        upgrade_mode = "None";
    }

    void
    recoverFields()
    {
        auto success_status = "Succeeded";
        if (fog_address == "None" && registration_status.find(success_status) != string::npos) {
            auto agent_details = Singleton::Consume<I_AgentDetails>::by<OrchestrationStatus>();
            dbgWarning(D_ORCHESTRATOR) << "Repairing status fields";
            agent_id = agent_details->getAgentId();
            profile_id = agent_details->getProfileId();
            tenant_id = agent_details->getTenantId();
            auto maybe_fog_domain = agent_details->getFogDomain();
            if (maybe_fog_domain.ok()) {
                fog_address = maybe_fog_domain.unpack();
            } else {
                fog_address = "None";
            }
        }
    }

    void
    serialize(cereal::JSONOutputArchive &archive)
    {
        recoverFields();
        archive(cereal::make_nvp("Last update attempt", last_update_attempt));
        archive(cereal::make_nvp("Last update status", last_update_status));
        archive(cereal::make_nvp("Last update", last_update_time));
        archive(cereal::make_nvp("Last manifest update", last_manifest_update));
        archive(cereal::make_nvp("Policy version", policy_version));
        archive(cereal::make_nvp("Last policy update", last_policy_update));
        archive(cereal::make_nvp("Last settings update", last_settings_update));
        archive(cereal::make_nvp("Upgrade mode", upgrade_mode));
        archive(cereal::make_nvp("Fog address", fog_address));
        archive(cereal::make_nvp("Registration status", registration_status));
        archive(cereal::make_nvp("Registration details", registration_details));
        archive(cereal::make_nvp("Agent ID", agent_id));
        archive(cereal::make_nvp("Profile ID", profile_id));
        archive(cereal::make_nvp("Tenant ID", tenant_id));
        archive(cereal::make_nvp("Manifest status", manifest_status));
        archive(cereal::make_nvp("Service policy", service_policies));
        archive(cereal::make_nvp("Service settings", service_settings));
    }

    void
    serialize(cereal::JSONInputArchive &archive)
    {
        archive(cereal::make_nvp("Last update attempt",     last_update_attempt));
        archive(cereal::make_nvp("Last update status",      last_update_status));
        archive(cereal::make_nvp("Last update",             last_update_time));
        archive(cereal::make_nvp("Last manifest update",    last_manifest_update));
        try {
            archive(cereal::make_nvp("Policy version",          policy_version));
        } catch (...) {
            archive.setNextName(nullptr);
        }

        archive(cereal::make_nvp("Last policy update",      last_policy_update));
        archive(cereal::make_nvp("Last settings update",    last_settings_update));

        // Optional param (upgrade - new parameter)
        bool is_upgrade_mode = false;
        try {
            archive(cereal::make_nvp("Upgrade mode", upgrade_mode));
            is_upgrade_mode = true;
        } catch (...) {
            archive.setNextName(nullptr);
        }

        if (!is_upgrade_mode) {
            try {
                archive(cereal::make_nvp("Update mode", upgrade_mode));
            } catch (...) {
                archive.setNextName(nullptr);
            }
        }

        archive(cereal::make_nvp("Fog address",             fog_address));
        archive(cereal::make_nvp("Registration status",     registration_status));
        archive(cereal::make_nvp("Registration details",    registration_details));
        archive(cereal::make_nvp("Agent ID",                agent_id));
        archive(cereal::make_nvp("Profile ID",              profile_id));
        archive(cereal::make_nvp("Tenant ID",               tenant_id));
        archive(cereal::make_nvp("Manifest status",         manifest_status));
        archive(cereal::make_nvp("Service policy",          service_policies));
        archive(cereal::make_nvp("Service settings",        service_settings));
    }

private:
    string last_update_time;
    string last_update_status;
    string last_update_attempt;
    string last_manifest_update;
    string policy_version;
    string last_policy_update;
    string last_settings_update;
    string upgrade_mode;
    string fog_address;
    string registration_status;
    string manifest_status;
    string manifest_error;
    string agent_id;
    string profile_id;
    string tenant_id;
    RegistrationDetails registration_details;
    map<string, string> service_policies;
    map<string, string> service_settings;
};

class OrchestrationStatus::Impl : Singleton::Provide<I_OrchestrationStatus>::From<OrchestrationStatus>
{
public:
    void
    writeStatusToFile() override
    {
        auto orchestration_status_path = getConfigurationWithDefault<string>(
            filesystem_prefix + "/conf/orchestration_status.json",
            "orchestration",
            "Orchestration status path"
        );
        auto write_result =
            orchestration_tools->objectToJsonFile<Status>(status, orchestration_status_path);
        if (!write_result) {
            dbgWarning(D_ORCHESTRATOR) << "Failed to write Orchestration status. File: " << orchestration_status_path;
        }
        dbgTrace(D_ORCHESTRATOR) << "Orchestration status file has been updated. File: " << orchestration_status_path;
    }

    void
    recoverFields() override
    {
        status.recoverFields();
    }

    void
    setServiceConfiguration(
        const string &service_name,
        const string &path,
        const OrchestrationStatusConfigType &configuration_file_type
    )
    {
        if (shouldPolicyStatusBeIgnored(service_name, path)) return;

        switch (configuration_file_type) {
            case OrchestrationStatusConfigType::POLICY:
                status.insertServicePolicy(service_name, path);
                return;
            case OrchestrationStatusConfigType::SETTINGS:
                status.insertServiceSetting(service_name, path);
                return;
            case OrchestrationStatusConfigType::MANIFEST:
                dbgAssert(false) << "Manifest is not a service configuration file type";
                break;
            case OrchestrationStatusConfigType::DATA:
                return;
            case OrchestrationStatusConfigType::COUNT:
                break;
        }
        dbgAssert(false) << "Unknown configuration file type";
    }

    void
    init()
    {
        time = Singleton::Consume<I_TimeGet>::by<OrchestrationStatus>();
        orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<OrchestrationStatus>();
        filesystem_prefix = getFilesystemPathConfig();
        initValues();
        loadFromFile();

        dbgTrace(D_ORCHESTRATOR)
            << "Initializing Orchestration status, file system path prefix: "
            << filesystem_prefix;

        map<string, string> service_policies_copy = status.getServicePolicies();
        for (const auto &policy: service_policies_copy) {
            setServiceConfiguration(policy.first, policy.second, OrchestrationStatusConfigType::POLICY);
        }

        auto mainloop = Singleton::Consume<I_MainLoop>::by<OrchestrationStatus>();
        mainloop->addRecurringRoutine(
            I_MainLoop::RoutineType::Timer,
            seconds(5),
            [this] ()
            {
                dbgTrace(D_ORCHESTRATOR) << "Write Orchestration status file <co-routine>";
                writeStatusToFile();
            },
            "Write Orchestration status file"
        );
    }

private:
    void initValues();
    bool shouldPolicyStatusBeIgnored(const string &service_name, const string &path);

    void
    loadFromFile()
    {
        auto orchestration_status_path = getConfigurationWithDefault<string>(
            filesystem_prefix + "/conf/orchestration_status.json",
            "orchestration",
            "Orchestration status path"
        );
        Maybe<Status> maybe_status_file =
            orchestration_tools->jsonFileToObject<Status>(orchestration_status_path);
        if (!maybe_status_file.ok()) {
            dbgTrace(D_ORCHESTRATOR)
                << "Failed to load Orchestration status, start with clear status."
                << " Error: " << maybe_status_file.getErr();
            return;
        }

        status = maybe_status_file.unpack();

        dbgInfo(D_ORCHESTRATOR) << "Orchestration status loaded from file." << " File: " << orchestration_status_path;
    }

    const string & getLastUpdateAttempt() const override              { return status.getLastUpdateAttempt(); }
    const string & getUpdateStatus() const override                   { return status.getUpdateStatus(); }
    const string & getUpdateTime() const override                     { return status.getUpdateTime(); }
    const string & getLastManifestUpdate() const override             { return status.getLastManifestUpdate(); }
    const string & getPolicyVersion() const override                  { return status.getPolicyVersion(); }
    const string & getLastPolicyUpdate() const override               { return status.getLastPolicyUpdate(); }
    const string & getLastSettingsUpdate() const override             { return status.getLastSettingsUpdate(); }
    const string & getUpgradeMode() const override                    { return status.getUpgradeMode(); }
    const string & getFogAddress() const override                     { return status.getFogAddress(); }
    const string & getRegistrationStatus() const override             { return status.getRegistrationStatus(); }
    const string & getAgentId() const override                        { return status.getAgentId(); }
    const string & getProfileId() const override                      { return status.getProfileId(); }
    const string & getTenantId() const override                       { return status.getTenantId(); }
    const string & getManifestStatus() const override                 { return status.getManifestStatus(); }
    const string & getManifestError() const override                  { return status.getManifestError(); }
    const string getRegistrationDetails() const override { return status.getRegistrationDetails().toString(); }
    const map<string, string> & getServicePolicies() const override   { return status.getServicePolicies(); }
    const map<string, string> & getServiceSettings() const override   { return status.getServiceSettings(); }

    void
    setIsConfigurationUpdated(EnumArray<OrchestrationStatusConfigType, bool> config_types) override
    {
        status.setIsConfigurationUpdated(config_types, time->getLocalTimeStr());
    }

    void
    setPolicyVersion(const string &_policy_version) override
    {
        status.setPolicyVersion(_policy_version);
    }

    void
    setRegistrationStatus(const string &_reg_status) override
    {
        status.setRegistrationStatus(_reg_status);
    }

    void
    setUpgradeMode(const string &_upgrade_mode) override
    {
        status.setUpgradeMode(_upgrade_mode);
    }

    void
    setAgentType(const string &_agent_type) override
    {
        status.setAgentType(_agent_type);
    }

    void
    setAgentDetails(
        const string &_agent_id,
        const string &_profile_id,
        const string &_tenant_id) override
    {
        status.setAgentDetails(_agent_id, _profile_id, _tenant_id);
    }

    void
    setLastUpdateAttempt() override
    {
        status.setLastUpdateAttempt(time->getLocalTimeStr());
    }

    void
    setFogAddress(const string &_fog_address) override
    {
        status.setFogAddress(_fog_address);
    }

    void
    setFieldStatus(
        const OrchestrationStatusFieldType &field_type_status,
        const OrchestrationStatusResult &status_result,
        const string &failure_reason) override
    {
        string field_value = status_string_map.at(status_result) + " " + failure_reason;
        switch (field_type_status) {
            case OrchestrationStatusFieldType::REGISTRATION:
                status.setRegistrationStatus(field_value);
                return;
            case OrchestrationStatusFieldType::MANIFEST:
                status.setManifestStatus(field_value);
                status.setManifestError(failure_reason);
                return;
            case OrchestrationStatusFieldType::LAST_UPDATE:
                if (status_result == OrchestrationStatusResult::SUCCESS) {
                    status.setLastUpdateTime(time->getLocalTimeStr());
                }
                if (status.getUpdateStatus() != field_value) {
                    writeStatusToFile();
                }
                status.setLastUpdateStatus(field_value);
                return;
            case OrchestrationStatusFieldType::COUNT:
                break;
        }
    }

    void
    setRegistrationDetails(
        const string &name,
        const string &type,
        const string &platform,
        const string &arch) override
    {
        status.setRegistrationDetails(name, type, platform, arch);
    }

    OrchestrationStatus::Impl & operator=(OrchestrationStatus::Impl &&from) = default;
    OrchestrationStatus::Impl & operator=(const OrchestrationStatus::Impl &from) = default;

    const map<OrchestrationStatusResult, string> status_string_map = {
        { OrchestrationStatusResult::SUCCESS,     "Succeeded" },
        { OrchestrationStatusResult::FAILED,      "Failed. Reason:" }
    };

    Status status;
    I_TimeGet *time;
    I_OrchestrationTools *orchestration_tools;
    string filesystem_prefix;

};

void
OrchestrationStatus::Impl::initValues()
{
    status.initValues();
}

bool
OrchestrationStatus::Impl::shouldPolicyStatusBeIgnored(
    const string &service_name,
    const string &path)
{
    vector<string> default_status_ingored_policies = {
        "rules",
        "zones",
        "triggers",
        "parameters",
        "orchestration",
        "webUserResponse",
        "kubernetescalico",
        "activeContextConfig"
    };

    auto status_ingored_policies = getSettingWithDefault<vector<string>>(
        default_status_ingored_policies,
        "orchestration",
        "Orchestration status ignored policies"
    );

    auto config_content = orchestration_tools->readFile(path);

    if (!config_content.ok() || config_content.unpack().empty()) {
        dbgDebug(D_ORCHESTRATOR) << "Can not read the policy for " << service_name;
        return true;
    }

    auto find_exist_iterator = status.getServicePolicies().find(service_name);
    auto find_ignored_iterator = find(status_ingored_policies.begin(), status_ingored_policies.end(), service_name);

    if (config_content.unpack() == "{}") {
        dbgDebug(D_ORCHESTRATOR) << "Skipping status print for an empty policy file. Policy name: " << service_name;
        if (find_exist_iterator != status.getServicePolicies().end()) {
            status.eraseServicePolicy(service_name);
        }
        return true;
    } else if (find_ignored_iterator != status_ingored_policies.end()) {
        dbgDebug(D_ORCHESTRATOR)
            << "Skipping status print for the policy from a list of ignored policies. Policy name: "
            << service_name;
        if (find_exist_iterator != status.getServicePolicies().end()) {
            status.eraseServicePolicy(service_name);
        }
        return true;
    }
    return false;
}

void
OrchestrationStatus::init() { pimpl->init(); }

OrchestrationStatus::OrchestrationStatus() : Component("OrchestrationStatus"), pimpl(make_unique<Impl>()) {}

OrchestrationStatus::~OrchestrationStatus() {}
