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

#include "orchestration_comp.h"

#include <cereal/archives/json.hpp>
#include <unordered_map>
#include <fstream>
#include <map>

#include "common.h"
#include "singleton.h"
#include "config.h"
#include "version.h"
#include "log_generator.h"
#include "downloader.h"
#include "package_handler.h"
#include "orchestration_policy.h"
#include "service_controller.h"
#include "manifest_controller.h"
#include "url_parser.h"
#include "i_messaging.h"
#include "agent_details_report.h"
#include "maybe_res.h"
#include "customized_cereal_map.h"
#include "orchestrator/data.h"
#include "health_check_status/health_check_status.h"
#include "get_status_rest.h"
#include "hybrid_mode_telemetry.h"
#include "telemetry.h"
#include "tenant_profile_pair.h"
#include "env_details.h"
#include "hybrid_communication.h"
#include "agent_core_utilities.h"

using namespace std;
using namespace chrono;
using namespace ReportIS;

USE_DEBUG_FLAG(D_ORCHESTRATOR);

#if defined(gaia) || defined(smb)
static string fw_last_update_time = "";
#endif // gaia || smb

class HealthCheckStatusListener : public Listener<HealthCheckStatusEvent>
{
public:
    void upon(const HealthCheckStatusEvent &) override {}

    HealthCheckStatusReply
    respond(const HealthCheckStatusEvent &) override
    {
        return HealthCheckStatusReply(comp_name, status, extended_status);
    }

    string getListenerName() const override { return "HealthCheckStatusListener"; }

    void
    setStatus(
        HealthCheckStatus _status,
        OrchestrationStatusFieldType _status_field_type,
        const string &_status_description = "Success")
    {
        string status_field_type_str = convertOrchestrationStatusFieldTypeToStr(_status_field_type);
        extended_status[status_field_type_str] = _status_description;
        field_types_status[status_field_type_str] = _status;

        switch(_status) {
            case HealthCheckStatus::UNHEALTHY: {
                status = HealthCheckStatus::UNHEALTHY;
                return;
            }
            case HealthCheckStatus::DEGRADED: {
                for (const auto &type_status : field_types_status) {
                    if ((type_status.first != status_field_type_str)
                            && (type_status.second == HealthCheckStatus::UNHEALTHY))
                    {
                        return;
                    }
                }
                status = HealthCheckStatus::DEGRADED;
                return;
            }
            case HealthCheckStatus::HEALTHY: {
                for (const auto &type_status : field_types_status) {
                    if ((type_status.first != status_field_type_str)
                            && (type_status.second == HealthCheckStatus::UNHEALTHY
                                || type_status.second == HealthCheckStatus::DEGRADED)
                        )
                    {
                        return;
                    }
                    status = HealthCheckStatus::HEALTHY;
                }
                return;
            }
            case HealthCheckStatus::IGNORED: {
                return;
            }
        }
    }

private:
    string
    convertOrchestrationStatusFieldTypeToStr(OrchestrationStatusFieldType type)
    {
        switch (type) {
            case OrchestrationStatusFieldType::REGISTRATION : return "Registration";
            case OrchestrationStatusFieldType::MANIFEST : return "Manifest";
            case OrchestrationStatusFieldType::LAST_UPDATE : return "Last Update";
            case OrchestrationStatusFieldType::COUNT : return "Count";
        }

        dbgError(D_ORCHESTRATOR) << "Trying to convert unknown orchestration status field to string.";
        return "";
    }

    string comp_name = "Orchestration";
    HealthCheckStatus status = HealthCheckStatus::IGNORED;
    map<string, string> extended_status;
    map<string, HealthCheckStatus> field_types_status;
};

class SetAgentUninstall
        :
    public ServerRest,
    Singleton::Consume<I_AgentDetails>
{
public:
    void
    doCall() override
    {
        dbgTrace(D_ORCHESTRATOR) << "Send 'agent uninstall process started' log to fog";
        setConfiguration(false, "Logging", "Enable bulk of logs");
        string profile_id = Singleton::Consume<I_AgentDetails>::by<SetAgentUninstall>()->getProfileId();
        LogGen log (
            "Agent started uninstall process",
            Audience::INTERNAL,
            Severity::INFO,
            Priority::URGENT,
            LogField("profileId", profile_id),
            LogField("issuingEngine", "agentUninstallProvider"),
            Tags::ORCHESTRATOR
        );
        notify_uninstall_to_fog = true;
    }

private:
    S2C_PARAM(bool, notify_uninstall_to_fog);
};

class OrchestrationComp::Impl
{
public:
    explicit Impl() : curr_agent_data_report(false) {}

    void
    init()
    {
        filesystem_prefix = getFilesystemPathConfig();
        dbgTrace(D_ORCHESTRATOR)
            << "Initializing Orchestration component, file system path prefix: "
            << filesystem_prefix;
        Singleton::Consume<I_AgentDetails>::by<OrchestrationComp>()->readAgentDetails();
        setAgentDetails();
        doEncrypt();
        health_check_status_listener.registerListener();

        curr_agent_data_report.disableReportSending();
        auto rest = Singleton::Consume<I_RestApi>::by<OrchestrationComp>();
        rest->addRestCall<getStatusRest>(RestAction::SHOW, "orchestration-status");
        rest->addRestCall<AddProxyRest>(RestAction::ADD, "proxy");
        rest->addRestCall<SetAgentUninstall>(RestAction::SET, "agent-uninstall");
        // Main loop of the Orchestration.
        Singleton::Consume<I_MainLoop>::by<OrchestrationComp>()->addOneTimeRoutine(
            I_MainLoop::RoutineType::RealTime,
            [this] () { run(); },
            "Orchestration runner",
            true
        );

        auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<OrchestrationComp>();
        orchestration_tools->getClusterId();

        hybrid_mode_metric.init(
            "Watchdog Metrics",
            ReportIS::AudienceTeam::AGENT_CORE,
            ReportIS::IssuingEngine::AGENT_CORE,
            chrono::minutes(10),
            true,
            ReportIS::Audience::INTERNAL
        );
        hybrid_mode_metric.registerListener();
        orchestration_tools->loadTenantsFromDir(
            getConfigurationWithDefault<string>(getFilesystemPathConfig() + "/conf/", "orchestration", "Conf dir")
        );
    }

    void
    fini()
    {
        Singleton::Consume<I_OrchestrationStatus>::by<OrchestrationComp>()->writeStatusToFile();
        curr_agent_data_report.disableReportSending();
    }

private:
    Maybe<void>
    start()
    {
        auto update_communication = Singleton::Consume<I_UpdateCommunication>::by<OrchestrationComp>();
        auto agent_mode = getOrchestrationMode();
        auto policy_mgmt_mode = getSettingWithDefault<string>("management", "profileManagedMode");
        bool declarative = agent_mode == OrchestrationMode::HYBRID || policy_mgmt_mode == "declarative";

        bool enforce_policy_flag = false;
        Maybe<OrchestrationPolicy> maybe_policy = genError("Empty policy");
        string policy_version = "";
        auto orchestration_policy_file = getPolicyConfigPath("orchestration", Config::ConfigFileType::Policy);

        auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<OrchestrationComp>();
        if (orchestration_tools->doesFileExist(orchestration_policy_file)) {
            maybe_policy = loadOrchestrationPolicy();
            if (!maybe_policy.ok()) {
                dbgWarning(D_ORCHESTRATOR) << "Failed to load Orchestration policy. Error: " << maybe_policy.getErr();
                enforce_policy_flag = true;
            }
            dbgDebug(D_ORCHESTRATOR) << "Orchestration is restarting";

            auto policy_file_path = getConfigurationWithDefault<string>(
                filesystem_prefix + "/conf/policy.json",
                "orchestration",
                "Policy file path"
            );
            auto settings_file_path = getConfigurationWithDefault<string>(
                filesystem_prefix + "/conf/settings.json",
                "orchestration",
                "Settings file path"
            );

            auto service_controller = Singleton::Consume<I_ServiceController>::by<OrchestrationComp>();
            auto is_update_config = service_controller->updateServiceConfiguration(
                policy_file_path,
                settings_file_path
            );
            if (!is_update_config.ok()) {
                dbgWarning(D_ORCHESTRATOR)
                    << "Failed to load the policy and settings, Error: "
                    << is_update_config.getErr();
            }

            policy_version = service_controller->getPolicyVersion();
            if (!policy_version.empty()) {
                Singleton::Consume<I_OrchestrationStatus>::by<OrchestrationComp>()->setPolicyVersion(policy_version);
            }
        } else {
            dbgDebug(D_ORCHESTRATOR) << "Orchestration is running for the first time";
            enforce_policy_flag = true;
        }

        if (enforce_policy_flag) {
            // Trying to create the Orchestration policy from the general policy file
            maybe_policy = enforceOrchestrationPolicy();
            if (!maybe_policy.ok()) {
                return genError(maybe_policy.getErr());
            }
            reloadConfiguration();
        }

        char *fog_address_env = getenv("FOG_ADDRESS");
        string fog_address = fog_address_env ? string(fog_address_env) : maybe_policy.unpack().getFogAddress();

        if (updateFogAddress(fog_address)) {
            policy = maybe_policy.unpack();
        } else {
            return genError("Failed to set fog address from policy");
        }

        auto authentication_res = update_communication->authenticateAgent();
        if (authentication_res.ok() && !policy_version.empty()) {
            auto service_controller = Singleton::Consume<I_ServiceController>::by<OrchestrationComp>();
            const string &policy_versions = service_controller->getPolicyVersions();
            auto path_policy_version = update_communication->sendPolicyVersion(policy_version, policy_versions);
            if (!path_policy_version.ok()) {
                dbgWarning(D_ORCHESTRATOR) << path_policy_version.getErr();
            }
        }

	if (declarative) Singleton::Consume<I_DeclarativePolicy>::from<DeclarativePolicyUtils>()->turnOnApplyPolicyFlag();
        return authentication_res;
    }

    Maybe<OrchestrationPolicy>
    loadOrchestrationPolicy()
    {
        auto maybe_policy = loadDefaultOrchestrationPolicy();
        if (!maybe_policy.ok()) {
            dbgWarning(D_ORCHESTRATOR) << "Failed to load Orchestration Policy. Trying to load from backup.";
            maybe_policy = loadOrchestrationPolicyFromBackup();
        }
        return maybe_policy;
    }

    Maybe<OrchestrationPolicy>
    loadDefaultOrchestrationPolicy()
    {
        auto orchestration_policy_file = getPolicyConfigPath("orchestration", Config::ConfigFileType::Policy);

        auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<OrchestrationComp>();
        auto maybe_policy = orchestration_tools->jsonFileToObject<OrchestrationPolicy>(orchestration_policy_file);
        if (maybe_policy.ok()) {
            return maybe_policy;
        }

        return genError("Failed to load default Orchestration policy. Error: " + maybe_policy.getErr());
    }

    Maybe<OrchestrationPolicy>
    loadOrchestrationPolicyFromBackup()
    {
        auto orchestration_policy_file = getPolicyConfigPath("orchestration", Config::ConfigFileType::Policy);

        auto backup_ext = getConfigurationWithDefault<string>(".bk", "orchestration", "Backup file extension");
        auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<OrchestrationComp>();
        auto maybe_policy = orchestration_tools->jsonFileToObject<OrchestrationPolicy>(
            orchestration_policy_file + backup_ext
        );

        if (maybe_policy.ok()) {
            if (!recoverBackupOrchestrationPolicy()) {
                dbgWarning(D_ORCHESTRATOR)
                    << "Succeed to load policy from backup, "
                    << "but failed to write it to Orchestration default policy file.";
            }

            return maybe_policy;
        }

        return genError("Failed to load Orchestration policy from backup.");
    }

    Maybe<OrchestrationPolicy>
    enforceOrchestrationPolicy()
    {
        Maybe<OrchestrationPolicy> maybe_policy(genError("Failed to enforce Orchestration policy"));
        auto policy_file_path = getConfigurationWithDefault<string>(
            filesystem_prefix + "/conf/policy.json",
            "orchestration",
            "Policy file path"
        );
        auto orchestration_policy_file = getPolicyConfigPath("orchestration", Config::ConfigFileType::Policy);

        auto settings_file_path = getConfigurationWithDefault<string>(
            filesystem_prefix + "/conf/settings.json",
            "orchestration",
            "Settings file path"
        );

        dbgInfo(D_ORCHESTRATOR)
            << "Enforcing new configuration. Policy file: "
            << policy_file_path
            << ", Settings file: "
            << settings_file_path;

        auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<OrchestrationComp>();
        auto service_controller = Singleton::Consume<I_ServiceController>::by<OrchestrationComp>();
        auto is_update_config = service_controller->updateServiceConfiguration(policy_file_path, settings_file_path);
        if (is_update_config.ok()) {
            maybe_policy = orchestration_tools->jsonFileToObject<OrchestrationPolicy>(orchestration_policy_file);
        } else {
            dbgWarning(D_ORCHESTRATOR) << is_update_config.getErr();
        }

        if (!maybe_policy.ok()) {
            dbgDebug(D_ORCHESTRATOR) << "Enforcing policy file from backup";
            string backup_ext = getConfigurationWithDefault<string>(
                ".bk",
                "orchestration",
                "Backup file extension"
            );

            dbgInfo(D_ORCHESTRATOR) << "Recovering the policy file from backup.";
            if (!orchestration_tools->copyFile(policy_file_path + backup_ext, policy_file_path)) {
                return genError("Failed to copy orchestration policy from backup policy.json file.");
            }
            // Try to use the backup policy.json file and re-write the services's policies.
            is_update_config = service_controller->updateServiceConfiguration(policy_file_path, settings_file_path);
            if (is_update_config.ok()) {
                maybe_policy = orchestration_tools->jsonFileToObject<OrchestrationPolicy>(orchestration_policy_file);
            } else {
                dbgWarning(D_ORCHESTRATOR) << is_update_config.getErr();
            }
        }

        if (maybe_policy.ok()) {
            return maybe_policy;
        }

        dbgDebug(D_ORCHESTRATOR) << "Failed to load Orchestration policy. Error: " << maybe_policy.getErr();
        return genError("Failed to load Orchestration policy from the main policy.");
    }

    bool
    recoverBackupOrchestrationPolicy()
    {
        auto conf_path = getPolicyConfigPath("orchestration", Config::ConfigFileType::Policy);

        string backup_ext = getConfigurationWithDefault<string>(".bk", "orchestration", "Backup file extension");
        string backup_orchestration_conf_file = conf_path + backup_ext;

        auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<OrchestrationComp>();
        return orchestration_tools->copyFile(backup_orchestration_conf_file, conf_path);
    }

    Maybe<void>
    handleManifestUpdate(const OrchManifest &orch_manifest)
    {
        if (!orch_manifest.ok()) return Maybe<void>();

        // Handling manifest update.
        dbgInfo(D_ORCHESTRATOR) << "There is a new manifest file.";
        GetResourceFile resource_file(GetResourceFile::ResourceFileType::MANIFEST);
        Maybe<string> new_manifest_file =
            Singleton::Consume<I_Downloader>::by<OrchestrationComp>()->downloadFileFromFog(
                orch_manifest.unpack(),
                I_OrchestrationTools::SELECTED_CHECKSUM_TYPE,
                resource_file
            );

        auto orch_status = Singleton::Consume<I_OrchestrationStatus>::by<OrchestrationComp>();
        auto service_controller = Singleton::Consume<I_ServiceController>::by<OrchestrationComp>();
        auto agent_details = Singleton::Consume<I_AgentDetails>::by<OrchestrationComp>();
        static int service_to_port_size = service_controller->getServiceToPortMap().size();
        auto hostname = Singleton::Consume<I_DetailsResolver>::by<ManifestHandler>()->getHostname();
        string err_hostname = (hostname.ok() ? "on host '" + *hostname : "'" + agent_details->getAgentId()) + "'";
        if (!new_manifest_file.ok()) {
            string install_error;
            if (!service_to_port_size) {
                install_error =
                    "Critical Error: Agent/Gateway was not fully deployed " +
                    err_hostname +
                    " and is not enforcing a security policy. Retry installation or contact Check Point support.";
            } else {
                install_error =
                    "Warning: Agent/Gateway " +
                    err_hostname +
                    " software update failed. Agent is running previous software. Contact Check Point support.";
            }
            dbgTrace(D_ORCHESTRATOR)
                << "Manifest failed to be updated. Error: "
                << new_manifest_file.getErr()
                << " Presenting the next message to the user: "
                << install_error;
            orch_status->setFieldStatus(
                OrchestrationStatusFieldType::MANIFEST,
                OrchestrationStatusResult::FAILED,
                install_error
            );

            health_check_status_listener.setStatus(
                HealthCheckStatus::UNHEALTHY,
                OrchestrationStatusFieldType::MANIFEST,
                install_error
            );

            return genError(install_error);
        }

        auto manifest_controller = Singleton::Consume<I_ManifestController>::by<OrchestrationComp>();
        if (!manifest_controller->updateManifest(new_manifest_file.unpack())) {
            string install_error =
                "Warning: Agent/Gateway " +
                err_hostname +
                " software update failed. Agent is running previous software. Contact Check Point support.";
            string current_error = orch_status->getManifestError();
            if (current_error.find("Gateway was not fully deployed") == string::npos) {
                orch_status->setFieldStatus(
                    OrchestrationStatusFieldType::MANIFEST,
                    OrchestrationStatusResult::FAILED,
                    install_error
                );
            } else {
                install_error = current_error;
            }
            dbgTrace(D_ORCHESTRATOR)
                << "Manifest failed to be updated. Presenting the next message to the user: "
                << install_error;

            health_check_status_listener.setStatus(
                HealthCheckStatus::UNHEALTHY,
                OrchestrationStatusFieldType::MANIFEST,
                install_error
            );

            return genError(install_error);
        }

        orch_status->setFieldStatus(
                OrchestrationStatusFieldType::MANIFEST,
                OrchestrationStatusResult::SUCCESS
        );
        health_check_status_listener.setStatus(
            HealthCheckStatus::HEALTHY,
            OrchestrationStatusFieldType::MANIFEST
        );

        ifstream restart_watchdog_orch(filesystem_prefix + "/orchestration/restart_watchdog");
        if (restart_watchdog_orch.good()) {
            ofstream restart_watchdog("/tmp/restart_watchdog", ofstream::out);
            restart_watchdog.close();
            remove((filesystem_prefix + "/orchestration/restart_watchdog").c_str());
            restart_watchdog_orch.close();
        }

        string manifest_success_notification_message(
            "Agent/Gateway " +
            err_hostname +
            " software update succeeded. Agent is running latest software."
        );
        LogGen manifest_success_notification(
            manifest_success_notification_message,
            ReportIS::Level::ACTION,
            ReportIS::Audience::SECURITY,
            ReportIS::Severity::INFO,
            ReportIS::Priority::LOW,
            ReportIS::Tags::ORCHESTRATOR
        );
        manifest_success_notification.addToOrigin(LogField("eventTopic", "Agent Profiles"));
        manifest_success_notification << LogField("notificationId", "4165c3b1-e9bc-44c3-888b-863e204c1bfb");

        return Maybe<void>();
    }

    bool
    updateServiceConfigurationFromBackup()
    {
        auto policy_file_path = getConfigurationWithDefault<string>(
            filesystem_prefix + "/conf/policy.json",
            "orchestration",
            "Policy file path"
        );

        auto orchestration_policy_file = getPolicyConfigPath("orchestration", Config::ConfigFileType::Policy);

        auto settings_file_path = getConfigurationWithDefault<string>(
            filesystem_prefix + "/conf/settings.json",
            "orchestration",
            "Settings file path"
        );

        dbgInfo(D_ORCHESTRATOR)
            << "Enforcing new configuration. Policy file: "
            << policy_file_path
            << ", Settings file: "
            << settings_file_path;

        string backup_ext = getConfigurationWithDefault<string>(
            ".bk",
            "orchestration",
            "Backup file extension"
        );

        auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<OrchestrationComp>();
        auto service_controller = Singleton::Consume<I_ServiceController>::by<OrchestrationComp>();

        // Try to use the backup policy.json file and re-write the services's policies.
        dbgInfo(D_ORCHESTRATOR) << "Updating services with the new policy.";
        auto is_update_config = service_controller->updateServiceConfiguration(
            policy_file_path + backup_ext,
            settings_file_path
        );
        if (!is_update_config.ok()) {
            dbgWarning (D_ORCHESTRATOR) << "Failed to load Orchestration policy. Error: " << is_update_config.getErr();
            return false;
        }
        dbgInfo(D_ORCHESTRATOR) << "Recovering the policy file from backup.";
        if (!orchestration_tools->copyFile(policy_file_path + backup_ext, policy_file_path)) {
            dbgWarning (D_ORCHESTRATOR)
                << "Failed to recover policy file from backup. File: "
                << policy_file_path + backup_ext;
            return false;
        }
        return true;
    }

    string
    updatePolicyAndFogAddress(const OrchestrationPolicy &orchestration_policy)
    {
        if (!updateFogAddress(orchestration_policy.getFogAddress())) {
            dbgWarning(D_ORCHESTRATOR) << "Failed to update the new Fog address.";
            if (!updateFogAddress(policy.getFogAddress())) {
                dbgWarning(D_ORCHESTRATOR) << "Failed to restore the old Fog address.";
            }
            return "";
        }

        policy = orchestration_policy;

        auto service_controller = Singleton::Consume<I_ServiceController>::by<OrchestrationComp>();
        string new_policy_version = service_controller->getPolicyVersion();
        if (!new_policy_version.empty()) {
            Singleton::Consume<I_OrchestrationStatus>::by<OrchestrationComp>()->setPolicyVersion(new_policy_version);
        }
        auto update_communication = Singleton::Consume<I_UpdateCommunication>::by<OrchestrationComp>();
        const string &policy_versions = service_controller->getPolicyVersions();
        auto path_policy_version = update_communication->sendPolicyVersion(new_policy_version, policy_versions);
        if (!path_policy_version.ok()) {
            dbgWarning(D_ORCHESTRATOR) << path_policy_version.getErr();
        }

        return new_policy_version;
    }

    Maybe<void>
    handlePolicyUpdate(const OrchPolicy &new_policy, const string &settings_path, const vector<string> &data_updates)
    {
        if (!new_policy.ok()) return Maybe<void>();
        // Handling policy update.
        dbgInfo(D_ORCHESTRATOR) << "There is a new policy file.";
        GetResourceFile resource_file(GetResourceFile::ResourceFileType::POLICY);
        Maybe<string> new_policy_file =
        Singleton::Consume<I_Downloader>::by<OrchestrationComp>()->downloadFileFromFog(
            new_policy.unpack(),
            I_OrchestrationTools::SELECTED_CHECKSUM_TYPE,
            resource_file
        );
        if (!new_policy_file.ok()) {
            return genError("Failed to download the new policy file. Error: " + new_policy_file.getErr());
        }

        auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<OrchestrationComp>();
        auto conf_path = filesystem_prefix + "/conf/policy.json";
        string last_ext = getConfigurationWithDefault<string>(
            ".last",
            "orchestration",
            "last fog policy file extension"
        );
        if (!orchestration_tools->copyFile(new_policy_file.unpack(), conf_path + last_ext)) {
            dbgWarning(D_ORCHESTRATOR) << "Failed to copy a new policy file to " << conf_path + last_ext;
        }

        // Calculate the changes between the existing policy to the new one.
        auto service_controller = Singleton::Consume<I_ServiceController>::by<OrchestrationComp>();
        string old_policy_version = service_controller->getPolicyVersion();
        auto res = service_controller->updateServiceConfiguration(
            new_policy_file.unpack(),
            settings_path,
            data_updates
        );

        if (!res.ok()) {
            string updated_policy_version = service_controller->getUpdatePolicyVersion();
            string error_str =
                "Failed to update services' policy configuration files. Previous version: " +
                old_policy_version +
                ". New version: " +
                updated_policy_version +
                ". Error: " +
                res.getErr();

            auto policy_file = getConfigurationWithDefault<string>(
                filesystem_prefix + "/conf/policy.json",
                "orchestration",
                "Policy file path"
            );
            auto setting_file = getConfigurationWithDefault<string>(
                filesystem_prefix + "/conf/settings.json",
                "orchestration",
                "Settings file path"
            );

            set<string> changed_policy_files = service_controller->moveChangedPolicies();
            for (const string &changed_policy_file : changed_policy_files) {
                orchestration_tools->writeFile("{}\n", changed_policy_file);
            }

            service_controller->updateServiceConfiguration(policy_file, setting_file, data_updates);
            LogGen(
                error_str,
                Audience::SECURITY,
                Severity::CRITICAL,
                Priority::HIGH,
                Tags::ORCHESTRATOR
            )
                << LogField("policyVersion", updated_policy_version)
                << LogField("previousPolicyVersion", old_policy_version);

            return genError(error_str);
        }
        service_controller->moveChangedPolicies();

        // Reload the orchestration policy, in case of the policy updated
        auto orchestration_policy = loadDefaultOrchestrationPolicy();
        if (!orchestration_policy.ok()) {
            return genError("Failed to load new Orchestration policy file.");
        }

        string new_policy_version = updatePolicyAndFogAddress(orchestration_policy.unpack());
        if (new_policy_version.empty()) {
            return genError("Failed to load Orchestration new policy file.");
        }
        if (getProfileAgentSettingWithDefault<bool>(false, "agent.config.orchestration.reportAgentDetail")) {
            service_controller->clearFailedServices();
            reportAgentDetailsMetaData();
            if(service_controller->doesFailedServicesExist()) {
                dbgWarning(D_ORCHESTRATOR) << "Failed to enforce Orchestration policy.";
                updateServiceConfigurationFromBackup();
                // Reload the orchestration policy, in case of the policy updated
                orchestration_policy = loadDefaultOrchestrationPolicy();
                if (!orchestration_policy.ok()) {
                    return genError("Failed to load new Orchestration policy file.");
                }

                new_policy_version = updatePolicyAndFogAddress(orchestration_policy.unpack());
                if (new_policy_version.empty()) {
                    return genError("Failed to load Orchestration new policy file.");
                }
            }
        }

        dbgTrace(D_ORCHESTRATOR)
            << "Update policy"
            << " from version: " + old_policy_version
            << " to version: " + new_policy_version;
        LogGen(
            "Agent's policy has been updated",
            Audience::SECURITY,
            Severity::INFO,
            Priority::LOW,
            Tags::ORCHESTRATOR,
            Notification::POLICY_UPDATE
        ) << LogField("policyVersion", new_policy_version) << LogField("fromVersion", old_policy_version);

        Singleton::Consume<I_MainLoop>::by<OrchestrationComp>()->addOneTimeRoutine(
            I_MainLoop::RoutineType::Offline,
            [this, new_policy_version] ()
            {
                chrono::microseconds curr_time = Singleton::Consume<I_TimeGet>::by<OrchestrationComp>()->getWalltime();
                AudienceTeam audience_team = AudienceTeam::NONE;
                auto i_env = Singleton::Consume<I_Environment>::by<OrchestrationComp>();
                auto team = i_env->get<AudienceTeam>("Audience Team");
                if (team.ok()) audience_team = *team;

                Report policy_update_message(
                    "Agent's policy has been updated",
                    curr_time,
                    Type::EVENT,
                    Level::LOG,
                    LogLevel::INFO,
                    Audience::INTERNAL,
                    audience_team,
                    Severity::INFO,
                    Priority::LOW,
                    chrono::seconds(0),
                    LogField("agentId", Singleton::Consume<I_AgentDetails>::by<OrchestrationComp>()->getAgentId()),
                    Tags::ORCHESTRATOR
                );
                policy_update_message.addToOrigin(LogField("policyVersion", new_policy_version));

                LogRest policy_update_message_client_rest(policy_update_message);

                Singleton::Consume<I_Messaging>::by<OrchestrationComp>()->sendObjectWithPersistence(
                    policy_update_message_client_rest,
                    I_Messaging::Method::POST,
                    "/api/v1/agents/events",
                    "",
                    true,
                    MessageTypeTag::REPORT
                );
            },
            "Send policy update report"
        );

        dbgInfo(D_ORCHESTRATOR) << "Policy update report was successfully sent to fog";

        return Maybe<void>();
    }

    Maybe<void>
    handleDataUpdate(const OrchData &orch_data, vector<string> &data_updates)
    {
        if (!orch_data.ok()) return Maybe<void>();

        auto service_name = Singleton::Consume<I_Environment>::by<OrchestrationComp>()->get<string>("Service Name");
        if (service_name.ok() && *service_name == "WLP Standalone") {
            dbgInfo(D_ORCHESTRATOR) << "Skipping download of Data file update";
            return Maybe<void>();
        }

        dbgInfo(D_ORCHESTRATOR) << "There is a new data file.";
        const string data_file_dir = filesystem_prefix + "/conf/data";

        auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<OrchestrationComp>();
        if (!orchestration_tools->doesDirectoryExist(data_file_dir)) {
            orchestration_tools->createDirectory(data_file_dir);
        }
        const auto data_file_path = getConfigurationWithDefault<string>(
            filesystem_prefix + "/conf/data.json",
            "orchestration",
            "Data file path"
        );
        GetResourceFile resource_file(GetResourceFile::ResourceFileType::DATA);
        Maybe<string> new_data_files = Singleton::Consume<I_Downloader>::by<OrchestrationComp>()->downloadFileFromFog(
            orch_data.unpack(),
            I_OrchestrationTools::SELECTED_CHECKSUM_TYPE,
            resource_file
        );

        if (!new_data_files.ok()) {
            return genError("Failed to download new data file, Error: " + new_data_files.getErr());
        }
        auto new_data_file_input = orchestration_tools->readFile(new_data_files.unpack());
        if (!new_data_file_input.ok()) {
            return genError("Failed to read new data file, Error: " + new_data_file_input.getErr());
        }

        map<string, Data> parsed_data;
        dbgDebug(D_ORCHESTRATOR) << "Parsing data from " << new_data_files.unpack();
        try {
            stringstream is(new_data_file_input.unpack());
            cereal::JSONInputArchive archive_in(is);
            cereal::load(archive_in, parsed_data);
        } catch (exception &e) {
            dbgDebug(D_ORCHESTRATOR)
                << "Failed to load data from JSON file. Error:  "
                << e.what()
                << ". Content: "
                << new_data_files.unpack();
            return genError(e.what());
        }

        for (const auto &data_file : parsed_data) {
            const string data_file_save_path = getPolicyConfigPath(data_file.first, Config::ConfigFileType::Data);
            Maybe<string> new_data_file =
            Singleton::Consume<I_Downloader>::by<OrchestrationComp>()->downloadFileFromURL(
                data_file.second.getDownloadPath(),
                data_file.second.getChecksum(),
                I_OrchestrationTools::SELECTED_CHECKSUM_TYPE,
                "data_" + data_file.first
            );

            if (!new_data_file.ok()) {
                dbgWarning(D_ORCHESTRATOR) << "Failed to download the " << data_file.first << " data file.";
                return new_data_file.passErr();
            }
            auto data_new_checksum = getChecksum(new_data_file.unpack());
            if (data_new_checksum != data_file.second.getChecksum()) {
                stringstream current_error;
                current_error << "No match for the checksums of the expected and the downloaded data file:"
                    << " Expected checksum: "
                    << data_file.second.getChecksum()
                    << ". Downloaded checksum: "
                    << data_new_checksum;

                dbgWarning(D_ORCHESTRATOR) << current_error.str();
                return genError(current_error.str());
            }
            if (!orchestration_tools->copyFile(new_data_file.unpack(), data_file_save_path)) {
                dbgWarning(D_ORCHESTRATOR) << "Failed to copy a new data file to " << data_file_save_path;
            }

            data_updates.push_back(data_file.first);
        }
        if (!orchestration_tools->copyFile(new_data_files.unpack(), data_file_path)) {
            dbgWarning(D_ORCHESTRATOR) << "Failed to copy a new agents' data file to " << data_file_path;
        }

        return Maybe<void>();
    }

    Maybe<void>
    handleSettingsUpdate(const OrchSettings &orch_settings, string &settings_file_path)
    {
        if (!orch_settings.ok()) return Maybe<void>();

        dbgInfo(D_ORCHESTRATOR) << "There is a new settings file.";
        GetResourceFile resource_file(GetResourceFile::ResourceFileType::SETTINGS);
        Maybe<string> new_settings_file =
        Singleton::Consume<I_Downloader>::by<OrchestrationComp>()->downloadFileFromFog(
            orch_settings.unpack(),
            I_OrchestrationTools::SELECTED_CHECKSUM_TYPE,
            resource_file
        );

        if (!new_settings_file.ok()) {
            dbgWarning(D_ORCHESTRATOR)
                << "Failed to download the new settings file. Error: "
                << new_settings_file.getErr();
            return genError("Failed to download the new settings file. Error: " + new_settings_file.getErr());
        }

        auto res = updateSettingsFile(*new_settings_file);
        if (res.ok()) {
            settings_file_path = *res;
            reloadConfiguration();
            return Maybe<void>();
        }

        return res.passErr();
    }

    Maybe<void>
    checkUpdate()
    {
        auto span_scope =
            Singleton::Consume<I_Environment>::by<OrchestrationComp>()->startNewSpanScope(Span::ContextType::NEW);
        auto manifest_checksum = getChecksum(
            getConfigurationWithDefault<string>(
                filesystem_prefix + "/conf/manifest.json",
                "orchestration",
                "Manifest file path"
            )
        );
        auto settings_checksum = getChecksum(
            getConfigurationWithDefault<string>(
                filesystem_prefix + "/conf/settings.json",
                "orchestration",
                "Settings file path"
            )
        );
        auto policy_checksum = getChecksum(
            getConfigurationWithDefault<string>(
                filesystem_prefix + "/conf/policy.json",
                "orchestration",
                "Policy file path"
            )
        );
        auto data_checksum = getChecksum(
            getConfigurationWithDefault<string>(
                filesystem_prefix + "/conf/data.json",
                "orchestration",
                "Data file path"
            )
        );

        auto policy_version = Singleton::Consume<I_ServiceController>::by<OrchestrationComp>()->getPolicyVersion();

        dbgDebug(D_ORCHESTRATOR) << "Sending check update request";

        CheckUpdateRequest request(
            manifest_checksum,
            policy_checksum,
            settings_checksum,
            data_checksum,
            I_OrchestrationTools::SELECTED_CHECKSUM_TYPE_STR,
            policy_version
        );

        auto agent_mode = Singleton::Consume<I_AgentDetails>::by<OrchestrationComp>()->getOrchestrationMode();
        auto policy_mgmt_mode = getSettingWithDefault<string>("management", "profileManagedMode");
        if (agent_mode == OrchestrationMode::HYBRID || policy_mgmt_mode == "declarative") {
            auto upgrade_mode = getSettingWithDefault<string>("manual", "upgradeMode");
            if (upgrade_mode != "scheduled") {
                request.setUpgradeFields(upgrade_mode);
            } else {
                request.setUpgradeFields(
                    upgrade_mode,
                    getSettingWithDefault<string>("0:00", "upgradeTime"),
                    getSettingWithDefault<uint>(4, "upgradeDurationHours"),
                    getSettingWithDefault<vector<string>>({}, "upgradeDay")
                );
            }
        }

        auto greedy_update = getProfileAgentSettingWithDefault<bool>(false, "orchestration.multitenancy.greedymode");
        greedy_update = getConfigurationWithDefault<bool>(greedy_update, "orchestration", "Multitenancy Greedy mode");

        auto tenant_manager = Singleton::Consume<I_TenantManager>::by<OrchestrationComp>();
        for (auto const &active_tenant: tenant_manager->fetchActiveTenants()) {
            for (auto const &profile_id: tenant_manager->fetchProfileIds(active_tenant)) {
                auto virtual_policy_data = getPolicyTenantData(active_tenant, profile_id);
                request.addTenantPolicy(virtual_policy_data);
                request.addTenantSettings(
                    getSettingsTenantData(
                        active_tenant,
                        profile_id,
                        virtual_policy_data.getVersion()
                    )
                );
            }
        }

        if (greedy_update) {
            request.setGreedyMode();
        }

        auto update_communication = Singleton::Consume<I_UpdateCommunication>::by<OrchestrationComp>();
        auto response = update_communication->getUpdate(request);

        auto orch_status = Singleton::Consume<I_OrchestrationStatus>::by<OrchestrationComp>();
        orch_status->setLastUpdateAttempt();
        auto upgrade_mode = getSetting<string>("upgradeMode");
        auto agent_type = getSetting<string>("agentType");
        if (upgrade_mode.ok()) {
            orch_status->setUpgradeMode(upgrade_mode.unpack());
        }
        if (agent_type.ok()) {
            orch_status->setAgentType(agent_type.unpack());
        }

        HybridModeMetricEvent().notify();

        if (!response.ok()) {
            orch_status->setFieldStatus(
                OrchestrationStatusFieldType::LAST_UPDATE,
                OrchestrationStatusResult::FAILED,
                response.getErr()
            );

            return genError(response.getErr());
        }

        return handleUpdate(request);
    }

    Maybe<string>
    convertOrchestrationConfigTypeToString(OrchestrationStatusConfigType type)
    {
        switch (type) {
            case OrchestrationStatusConfigType::DATA: return string("Data");
            case OrchestrationStatusConfigType::SETTINGS: return string("Settings");
            case OrchestrationStatusConfigType::MANIFEST: return string("Manifest");
            case OrchestrationStatusConfigType::POLICY: return string("Policy");
            default: {
                return genError(
                    "Cannot convert OrchestrationStatusConfigType to string. Type: " +
                    to_string(static_cast<int>(type))
                );
            }
        }
    }

    Maybe<void>
    handleUpdate(const CheckUpdateRequest &response)
    {
        auto span_scope =
        Singleton::Consume<I_Environment>::by<OrchestrationComp>()->startNewSpanScope(Span::ContextType::CHILD_OF);
        auto agent_details = Singleton::Consume<I_AgentDetails>::by<OrchestrationComp>();
        dbgDebug(D_ORCHESTRATOR) << "Starting to handle check update response";

        OrchManifest orch_manifest  = response.getManifest();
        OrchPolicy orch_policy      = response.getPolicy();
        OrchSettings orch_settings  = response.getSettings();
        OrchData orch_data          = response.getData();

        auto orch_status = Singleton::Consume<I_OrchestrationStatus>::by<OrchestrationComp>();
        orch_status->setFieldStatus(
            OrchestrationStatusFieldType::LAST_UPDATE,
            OrchestrationStatusResult::SUCCESS
        );
        orch_status->setIsConfigurationUpdated(
            EnumArray<OrchestrationStatusConfigType, bool>(
                orch_manifest.ok(), orch_policy.ok(), orch_settings.ok(), orch_data.ok()
            )
        );

        EnumArray<OrchestrationStatusConfigType, Maybe<void>> update_results;

        string settings_path = "";
        update_results[OrchestrationStatusConfigType::SETTINGS] = handleSettingsUpdate(orch_settings, settings_path);

        vector<string> data_updates;
        update_results[OrchestrationStatusConfigType::DATA] = handleDataUpdate(orch_data, data_updates);

        auto orch_mode = agent_details->getOrchestrationMode();
        if ((!orch_manifest.ok() || orch_mode == OrchestrationMode::HYBRID) && orch_policy.ok()) {
            update_results[OrchestrationStatusConfigType::POLICY] = handlePolicyUpdate(
                orch_policy,
                settings_path,
                data_updates
            );
        }
        if (!orch_policy.ok() && (!data_updates.empty() || !settings_path.empty())) {
            auto service_controller = Singleton::Consume<I_ServiceController>::by<OrchestrationComp>();
            auto res = service_controller->updateServiceConfiguration(
                "",
                settings_path,
                data_updates
            );

            if (!res.ok()) {
                dbgWarning(D_ORCHESTRATOR) << res.getErr();
            }
        }

        update_results[OrchestrationStatusConfigType::MANIFEST] = handleManifestUpdate(orch_manifest);
        if (!update_results[OrchestrationStatusConfigType::MANIFEST].ok()) {
            string current_error = orch_status->getManifestError();
            string recommended_fix;
            string msg;
            bool is_deploy_error = current_error.find("Critical") != string::npos;
            auto hostname = Singleton::Consume<I_DetailsResolver>::by<ManifestHandler>()->getHostname();
            string err_hostname = (hostname.ok() ? "on host '" + *hostname : "'" + agent_details->getAgentId()) + "'";
            if (is_deploy_error) {
                msg =
                    "Agent/Gateway was not fully deployed " +
                    err_hostname +
                    " and is not enforcing a security policy.";
                recommended_fix = "Retry installation or contact Check Point support.";
            } else if (current_error.find("Warning") != string::npos) {
                msg =
                    "Agent/Gateway " +
                    err_hostname +
                    " software update failed. Agent is running previous software.";
                recommended_fix = "Contact Check Point support.";
            }
            if (!msg.empty() && !recommended_fix.empty()) {
                LogGen manifest_error_notification(
                    msg,
                    ReportIS::Level::ACTION,
                    ReportIS::Audience::SECURITY,
                    is_deploy_error ? ReportIS::Severity::CRITICAL : ReportIS::Severity::HIGH,
                    ReportIS::Priority::URGENT,
                    ReportIS::Tags::ORCHESTRATOR
                );
                manifest_error_notification.addToOrigin(LogField("eventTopic", "Agent Profiles"));
                manifest_error_notification << LogField("eventRemediation", recommended_fix);
                if (is_deploy_error) {
                    manifest_error_notification << LogField("notificationId", "4165c3b1-e9bc-44c3-888b-863e204c1bfb");
                }
            }
        }

        handleVirtualFiles(response.getVirtualSettings(), response.getVirtualPolicy(), data_updates);

        string maybe_errors;
        for (OrchestrationStatusConfigType update_type : makeRange<OrchestrationStatusConfigType>()) {
            if (update_results[update_type].ok()) continue;
            auto type_str = convertOrchestrationConfigTypeToString(update_type);
            if (!type_str.ok()) {
                continue;
            }
            if (maybe_errors != "") maybe_errors += ", ";
            maybe_errors += (*type_str + " error: " + update_results[update_type].getErr());
        }

        if (maybe_errors != "") return genError(maybe_errors);
        return Maybe<void>();
    }

    void
    handleVirtualFiles(
        const Maybe<vector<CheckUpdateRequest::Tenants>> &updated_settings_tenants,
        const Maybe<vector<CheckUpdateRequest::Tenants>> &updated_policy_tenants,
        const vector<string> &new_data_files)
    {
        dbgFlow(D_ORCHESTRATOR) << "Handling virtual files";
        if (!updated_policy_tenants.ok()) return;

        // Sorting files by tenant id;
        unordered_map<TenantProfilePair, vector<string>> sorted_files;

        // Download virtual policy
        bool is_empty = true;
        GetResourceFile resource_v_policy_file(GetResourceFile::ResourceFileType::VIRTUAL_POLICY);
        I_Downloader *downloader = Singleton::Consume<I_Downloader>::by<OrchestrationComp>();
        auto tenant_manager = Singleton::Consume<I_TenantManager>::by<OrchestrationComp>();
        map<string, set<string>> profiles_to_be_deleted =
            tenant_manager->fetchAndUpdateActiveTenantsAndProfiles(false);
        for (const auto &tenant: *updated_policy_tenants) {
            profiles_to_be_deleted[tenant.getTenantID()].erase(tenant.getProfileID());
            if (!tenant.getVersion().empty()) {
                is_empty = false;

                string profile_to_use = tenant.getProfileID().empty() ?
                    downloader->getProfileFromMap(tenant.getTenantID()) :
                    tenant.getProfileID();

                dbgTrace(D_ORCHESTRATOR)
                    << "Adding a tenant to the multi-tenant list. Tenant: "
                    << tenant.getTenantID()
                    << " Profile: "
                    << profile_to_use;

                tenant_manager->addActiveTenantAndProfile(tenant.getTenantID(), profile_to_use);
                resource_v_policy_file.addTenant(
                    tenant.getTenantID(),
                    profile_to_use,
                    tenant.getVersion(),
                    tenant.getChecksum()
                );
            }
        }

        if (!is_empty) {
            auto new_virtual_policy_files =
                downloader->downloadVirtualFileFromFog(
                    resource_v_policy_file,
                    I_OrchestrationTools::SELECTED_CHECKSUM_TYPE
                );
            if (new_virtual_policy_files.ok()) {
                for (const auto &tenant_file: *new_virtual_policy_files) {
                    auto tenant_profile = TenantProfilePair(tenant_file.first.first, tenant_file.first.second);
                    sorted_files[tenant_profile].push_back(tenant_file.second);
                }
            }
        }

        if (updated_settings_tenants.ok()) {
            // Download virtual settings
            is_empty = true;
            GetResourceFile resource_v_settings_file(GetResourceFile::ResourceFileType::VIRTUAL_SETTINGS);
            for (const auto &tenant: *updated_settings_tenants) {
                if (!tenant.getVersion().empty()) {
                    is_empty = false;

                    string profile_to_use = tenant.getProfileID().empty() ?
                        downloader->getProfileFromMap(tenant.getTenantID()) :
                        tenant.getProfileID();

                    dbgTrace(D_ORCHESTRATOR)
                        << "Handling virtual settings: Tenant ID: "
                        << tenant.getTenantID()
                        << ", Profile ID: "
                        << profile_to_use
                        << ", version: "
                        << tenant.getVersion()
                        << ", checksum: "
                        << tenant.getChecksum();

                    resource_v_settings_file.addTenant(
                        tenant.getTenantID(),
                        profile_to_use,
                        tenant.getVersion(),
                        tenant.getChecksum()
                    );
                }
            }

            if (!is_empty) {
                auto new_virtual_settings_files =
                    Singleton::Consume<I_Downloader>::by<OrchestrationComp>()->downloadVirtualFileFromFog(
                        resource_v_settings_file,
                        I_OrchestrationTools::SELECTED_CHECKSUM_TYPE
                    );
                if (new_virtual_settings_files.ok()) {
                    for (const auto &tenant_file: *new_virtual_settings_files) {
                        auto tenant_profile = TenantProfilePair(tenant_file.first.first, tenant_file.first.second);
                        dbgTrace(D_ORCHESTRATOR)
                            << "Downloaded a file from the FOG: Tenant ID: "
                            << tenant_profile.getTenantId()
                            << ", Profile ID: "
                            << tenant_profile.getProfileId();
                        sorted_files[tenant_profile].push_back(tenant_file.second);
                    }
                }
            }
        }
        auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<OrchestrationComp>();
        auto conf_dir = getConfigurationWithDefault<string>(
            getFilesystemPathConfig() + "/conf/",
            "orchestration",
            "Conf dir"
        );
        for (const auto &tenant_profile_set : profiles_to_be_deleted) {
            auto tenant_id = tenant_profile_set.first;
            for (const auto &profile_id: tenant_profile_set.second) {
                dbgTrace(D_ORCHESTRATOR)
                    << "Delete configuration files for inactive profile: "
                    << "Tenant ID: "
                    << tenant_id
                    << ", Profile ID: "
                    << profile_id;
                tenant_manager->deactivateTenant(tenant_id, profile_id);
                orchestration_tools->deleteVirtualTenantProfileFiles(
                    tenant_id,
                    profile_id,
                    conf_dir
                );
            }
        }

        clearOldTenants();

        for (auto it = sorted_files.begin(); it != sorted_files.end(); it++) {
            const auto &downloaded_files = *it;
            auto files = downloaded_files.second;
            string policy_file = files[0];
            string setting_file = "";
            if (files.size() > 1) {
                setting_file = files[1];
                auto handled_settings = updateSettingsFile(
                    setting_file,
                    downloaded_files.first.getTenantId(),
                    downloaded_files.first.getProfileId()
                );
                if (handled_settings.ok()) setting_file = *handled_settings;
            }

            bool last_iteration = false;
            if (next(it) == sorted_files.end()) last_iteration = true;

            Singleton::Consume<I_ServiceController>::by<OrchestrationComp>()->updateServiceConfiguration(
                policy_file,
                setting_file,
                new_data_files,
                downloaded_files.first.getTenantId(),
                downloaded_files.first.getProfileId(),
                last_iteration
            );
        }
    }

    Maybe<string>
    updateSettingsFile(const string &new_settings_file, const string &tenant_id = "",  const string &profile_id = "")
    {
        // Handling settings update.
        auto conf_dir = getConfigurationWithDefault<string>(
            filesystem_prefix + "/conf/",
            "orchestration",
            "Conf dir"
        ) + (tenant_id != "" ? "tenant_" + tenant_id  + "_profile_" + profile_id + "_"  : "");

        auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<OrchestrationComp>();
        string settings_file_path = conf_dir + "settings.json";
        dbgTrace(D_ORCHESTRATOR) << "The settings directory is " << settings_file_path;
        if (!orchestration_tools->copyFile(new_settings_file, settings_file_path)) {
            dbgWarning(D_ORCHESTRATOR) << "Failed to update the settings.";
            return genError("Failed to update the settings");
        }

        return settings_file_path;
    }

    CheckUpdateRequest::Tenants
    getPolicyTenantData(const string &tenant_id, const string &profile_id)
    {
        string dir = getConfigurationWithDefault<string>(
            filesystem_prefix + "/conf",
            "orchestration",
            "Configuration directory"
        );

        string policy_file = dir + "/tenant_" + tenant_id + "_profile_" + profile_id + "/policy.json";

        string policy_file_checksum = getChecksum(policy_file);
        string policy_file_version= getVersion(policy_file);

        return CheckUpdateRequest::Tenants(tenant_id, profile_id, policy_file_checksum, policy_file_version);
    }

    CheckUpdateRequest::Tenants
    getSettingsTenantData(const string &tenant_id, const string &profile_id, const string &policy_version)
    {
        string dir = getConfigurationWithDefault<string>(
            filesystem_prefix + "/conf",
            "orchestration",
            "Configuration directory"
        );

        string settings_file = dir + "/tenant_" + tenant_id + "_profile_" + profile_id + "_settings.json";
        string settings_file_checksum = getChecksum(settings_file);

        return CheckUpdateRequest::Tenants(tenant_id, profile_id, settings_file_checksum, policy_version);
    }

    string
    getChecksum(const string &file_path)
    {
        auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<OrchestrationComp>();
        Maybe<string> file_checksum = orchestration_tools->calculateChecksum(
            I_OrchestrationTools::SELECTED_CHECKSUM_TYPE,
            file_path
        );

        if (!file_checksum.ok()) return "";
        return file_checksum.unpack();
    }

    string
    getVersion(const string &file_path)
    {
        string version;
        auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<OrchestrationComp>();
        Maybe<string> file_data = orchestration_tools->readFile(file_path);

        if (file_data.ok()) {
            try {
                stringstream in;
                in.str(*file_data);
                cereal::JSONInputArchive ar(in);
                ar(cereal::make_nvp("version", version));
            } catch (...) {}
        }
        // Must be removed.
        if (version.empty()) return "1";

        return version;
    }

    void
    encryptOldFile(const string &old_path, const string &new_path)
    {
        auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<OrchestrationComp>();
        auto file_data = orchestration_tools->readFile(old_path);
        if (file_data.ok()) {
            auto encryptor = Singleton::Consume<I_Encryptor>::by<OrchestrationComp>();
            auto decoded_data   = encryptor->base64Decode(file_data.unpack());
            if (!orchestration_tools->writeFile(decoded_data, new_path)) {
                dbgWarning(D_ORCHESTRATOR) << "Failed to encrypt files";
            } else {
                // Removing clear data files after encrypting
                orchestration_tools->removeFile(old_path);
            }
        }
    }

    void
    encryptToFile(const string &data, const string &file)
    {
        auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<OrchestrationComp>();
        if (!orchestration_tools->writeFile(data, file)) {
            dbgWarning(D_ORCHESTRATOR) << "Failed to encrypt files";
        }
    }

    void
    reportAgentDetailsMetaData()
    {
        I_DetailsResolver *i_details_resolver = Singleton::Consume<I_DetailsResolver>::by<OrchestrationComp>();
        i_details_resolver->getResolvedDetails();

        AgentDataReport agent_data_report;
        agent_data_report << AgentReportFieldWithLabel("agent_version", i_details_resolver->getAgentVersion());

        auto platform = i_details_resolver->getPlatform();
        if (platform.ok()) agent_data_report.setPlatform(*platform);

        auto arch =  i_details_resolver->getArch();
        if (arch.ok()) agent_data_report.setArchitecture(*arch);

        for (const pair<string, string> details : i_details_resolver->getResolvedDetails()) {
            agent_data_report << details;
        }

        agent_data_report.setAgentVersion(i_details_resolver->getAgentVersion());

        auto nginx_data = i_details_resolver->parseNginxMetadata();
        if (nginx_data.ok()) {
            string nginx_version;
            string config_opt;
            string cc_opt;
            tie(config_opt, cc_opt, nginx_version) = nginx_data.unpack();
            agent_data_report
                << make_pair("nginxVersion",     nginx_version)
                << make_pair("configureOpt",     config_opt)
                << make_pair("extraCompilerOpt", cc_opt);
        } else {
            dbgDebug(D_ORCHESTRATOR) << nginx_data.getErr();
        }

        if (i_details_resolver->isReverseProxy()) {
            agent_data_report << AgentReportFieldWithLabel("reverse_proxy", "true");
        }

        if (i_details_resolver->isKernelVersion3OrHigher()) {
            agent_data_report << AgentReportFieldWithLabel("isKernelVersion3OrHigher", "true");
        }

        if (i_details_resolver->isGwNotVsx()) {
            agent_data_report << AgentReportFieldWithLabel("isGwNotVsx", "true");
        }

        if (i_details_resolver->isVersionEqualOrAboveR8110()) {
            agent_data_report << AgentReportFieldWithLabel("isVersionEqualOrAboveR8110", "true");
        }

        auto i_agent_details = Singleton::Consume<I_AgentDetails>::by<OrchestrationComp>();
        if (
            i_agent_details->getOrchestrationMode() == OrchestrationMode::HYBRID ||
            getSettingWithDefault<string>("management", "profileManagedMode") == "declarative"
        ) {
            agent_data_report << AgentReportFieldWithLabel("managedMode", "declarative");
        } else {
            agent_data_report << AgentReportFieldWithLabel("managedMode", "management");
        }

#if defined(gaia) || defined(smb)
        if (i_details_resolver->compareCheckpointVersion(8100, greater_equal<int>())) {
            agent_data_report << AgentReportFieldWithLabel("isCheckpointVersionGER81", "true");
        }
        if (i_details_resolver->compareCheckpointVersion(8200, greater_equal<int>())) {
            agent_data_report << AgentReportFieldWithLabel("isCheckpointVersionGER82", "true");
        }
#endif // gaia || smb

        if (agent_data_report == curr_agent_data_report) {
            agent_data_report.disableReportSending();
        } else {
            curr_agent_data_report = agent_data_report;
            curr_agent_data_report.disableReportSending();
        }
    }

    void
    doEncrypt()
    {
        static const string data1 = "This is fake";
        static const string data2 = "0000 is fake";
        static const string data3 = "This is 3333";

        auto data_path = getConfigurationWithDefault<string>(
            filesystem_prefix + "/data/",
            "encryptor",
            "Data files directory"
        );
        encryptOldFile(
            getConfigurationWithDefault<string>(
                filesystem_prefix + "/conf/user-cred.json",
                "message",
                "User Credentials Path"
            ),
            data_path + user_cred_file_name
        );

        encryptToFile(data1, data_path + data1_file_name);
        encryptToFile(data2, data_path + data4_file_name);
        encryptToFile(data3, data_path + data6_file_name);
    }

    void
    run()
    {
        int sleep_interval = policy.getErrorSleepInterval();
        Maybe<void> start_state(genError("Not running yet."));
        while (!(start_state = start()).ok()) {
            dbgDebug(D_ORCHESTRATOR) << "Orchestration not started yet. Status: " << start_state.getErr();
            health_check_status_listener.setStatus(
                HealthCheckStatus::UNHEALTHY,
                OrchestrationStatusFieldType::REGISTRATION,
                start_state.getErr()
            );
            sleep_interval = getConfigurationWithDefault<int>(
                20,
                "orchestration",
                "Default sleep interval"
            );
            Singleton::Consume<I_MainLoop>::by<OrchestrationComp>()->yield(seconds(sleep_interval));
        }

        Singleton::Consume<I_MainLoop>::by<OrchestrationComp>()->yield(chrono::seconds(1));

        health_check_status_listener.setStatus(
            HealthCheckStatus::HEALTHY,
            OrchestrationStatusFieldType::REGISTRATION
        );

        LogGen(
            "Check Point Orchestration nano service successfully started",
            Audience::SECURITY,
            Severity::INFO,
            Priority::LOW,
            Tags::ORCHESTRATOR)
            << LogField("agentType", "Orchestration")
            << LogField("agentVersion", Version::get());

        Singleton::Consume<I_MainLoop>::by<OrchestrationComp>()->addOneTimeRoutine(
            I_MainLoop::RoutineType::Offline,
            sendRegistrationData,
            "Send registration data"
        );

        reportAgentDetailsMetaData();

        if (!Singleton::Consume<I_ManifestController>::by<OrchestrationComp>()->loadAfterSelfUpdate()) {
            // Should restore from backup
            dbgWarning(D_ORCHESTRATOR) << "Failed to load Orchestration after self-update";
            health_check_status_listener.setStatus(
                HealthCheckStatus::UNHEALTHY,
                OrchestrationStatusFieldType::LAST_UPDATE,
                "Failed to load Orchestration after self-update"
            );
        } else {
            health_check_status_listener.setStatus(
                HealthCheckStatus::HEALTHY,
                OrchestrationStatusFieldType::MANIFEST
            );
        }

        bool is_new_success = false;
        while (true) {
            static int failure_count = 0;
            Singleton::Consume<I_Environment>::by<OrchestrationComp>()->startNewTrace(false);
            if (shouldReportAgentDetailsMetadata()) {
                reportAgentDetailsMetaData();
            }
            auto check_update_result = checkUpdate();
            if (!check_update_result.ok()) {
                failure_count++;
                is_new_success = false;
                sleep_interval = policy.getErrorSleepInterval();
                int failure_multiplier = 1;
                if (failure_count >= 10) {
                    failure_count = 10;
                    failure_multiplier = 10;
                } else if (failure_count >= 3) {
                    failure_multiplier = 2;
                }
                sleep_interval *= failure_multiplier;
                dbgWarning(D_ORCHESTRATOR)
                    << "Failed during check update from Fog. Error: "
                    << check_update_result.getErr()
                    << ", new check will be every: "
                    << sleep_interval << " seconds";

                health_check_status_listener.setStatus(
                    HealthCheckStatus::UNHEALTHY,
                    OrchestrationStatusFieldType::LAST_UPDATE,
                    "Failed during check update from Fog. Error: " + check_update_result.getErr()
                );
            } else {
                failure_count = 0;
                dbgDebug(D_ORCHESTRATOR) << "Check update process completed successfully";
                health_check_status_listener.setStatus(
                    HealthCheckStatus::HEALTHY,
                    OrchestrationStatusFieldType::LAST_UPDATE
                );
                sleep_interval = policy.getSleepInterval();
                if (!is_new_success) {
                    dbgInfo(D_ORCHESTRATOR)
                        << "Check update process completed successfully, new check will be every: "
                        << sleep_interval << " seconds";
                    is_new_success = true;
                }
            }

            dbgDebug(D_ORCHESTRATOR) << "Next check for update will be in: " << sleep_interval << " seconds";
            Singleton::Consume<I_Environment>::by<OrchestrationComp>()->finishTrace();
            Singleton::Consume<I_MainLoop>::by<OrchestrationComp>()->yield(seconds(sleep_interval));
        }
    }

    static void
    sendRegistrationData()
    {
        dbgInfo(D_ORCHESTRATOR) << "Sending registration data";

        set<Tags> tags{ Tags::ORCHESTRATOR };

        auto deployment_type = Singleton::Consume<I_EnvDetails>::by<HybridCommunication>()->getEnvType();
        switch (deployment_type) {
            case EnvType::LINUX: {
                tags.insert(Tags::DEPLOYMENT_EMBEDDED);
                break;
            }
            case EnvType::K8S: {
                tags.insert(Tags::DEPLOYMENT_K8S);
                break;
            }
            case EnvType::COUNT: {
                dbgWarning(D_ORCHESTRATOR) << "Could not identify deployment type";
                break;
            }
        }

        string server_name = getAttribute("registered-server", "registered_server");
        auto server = TagAndEnumManagement::convertStringToTag(server_name);
        if (server.ok()) tags.insert(*server);

        if (getAttribute("no-setting", "CROWDSEC_ENABLED") == "true") tags.insert(Tags::CROWDSEC);
        if (getAttribute("no-setting", "PLAYGROUND") == "true") tags.insert(Tags::PLAYGROUND);
        if (getAttribute("no-setting", "nginxproxymanager") == "true") tags.insert(Tags::NGINX_PROXY_MANAGER);

        Report registration_report(
            "Local Agent Data",
            Singleton::Consume<I_TimeGet>::by<OrchestrationComp>()->getWalltime(),
            Type::EVENT,
            Level::LOG,
            LogLevel::INFO,
            Audience::INTERNAL,
            AudienceTeam::NONE,
            Severity::INFO,
            Priority::LOW,
            chrono::seconds(0),
            LogField("agentId", Singleton::Consume<I_AgentDetails>::by<OrchestrationComp>()->getAgentId()),
            tags
        );

        auto email = getAttribute("email-address", "user_email");
        if (email != "") registration_report << LogField("userDefinedId", email);

        LogRest registration_report_rest(registration_report);
        Singleton::Consume<I_Messaging>::by<OrchestrationComp>()->sendObjectWithPersistence(
            registration_report_rest,
            I_Messaging::Method::POST,
            "/api/v1/agents/events",
            "",
            true,
            MessageTypeTag::REPORT
        );
    }

    static string
    getAttribute(const string &setting, const string &env)
    {
        auto res = getSetting<string>(setting);
        if (res.ok() && *res != "") return res.unpack();
        auto env_res = getenv(env.c_str());
        if (env_res != nullptr) return env_res;
        return "";
    }

    // LCOV_EXCL_START Reason: future changes will be done
    void
    restoreToBackup()
    {
        dbgWarning(D_ORCHESTRATOR) << "Reverting to the latest Orchestration service backup installation package.";

        // Copy the backup installation package to the running installation package.
        auto packages_dir = getConfigurationWithDefault<string>(
            filesystem_prefix + "/packages",
            "orchestration",
            "Packages directory"
        );
        auto service_name = getConfigurationWithDefault<string>("orchestration", "orchestration", "Service name");
        auto orchestration_dir = packages_dir + "/" + service_name;
        auto current_installation_file = orchestration_dir + "/" + service_name;
        auto backup_ext = getConfigurationWithDefault<string>(".bk", "orchestration", "Backup file extension");
        auto backup_installation_file = current_installation_file + backup_ext;
        auto temp_ext = getConfigurationWithDefault<string>("_temp", "orchestration", "Temp file extension");

        auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<OrchestrationComp>();
        dbgAssert(orchestration_tools->doesFileExist(backup_installation_file))
            << "There is no backup installation package";

        dbgAssert(orchestration_tools->copyFile(backup_installation_file, current_installation_file))
            << "Failed to copy backup installation package";

        // Copy the backup manifest file to the default manifest file path.
        auto manifest_file_path = getConfigurationWithDefault<string>(
            filesystem_prefix + "/conf/manifest.json",
            "orchestration",
            "Manifest file path"
        );

        if (!orchestration_tools->copyFile(manifest_file_path + backup_ext, manifest_file_path + temp_ext)) {
            dbgWarning(D_ORCHESTRATOR) << "Failed to restore manifest backup file.";
        }

        auto package_handler = Singleton::Consume<I_PackageHandler>::by<OrchestrationComp>();
        // Install the backup orchestration service installation package.
        dbgAssert(package_handler->preInstallPackage(service_name, current_installation_file))
            << "Failed to restore from backup, pre install test failed";
        dbgAssert(package_handler->installPackage(service_name, current_installation_file, true))
            << "Failed to restore from backup, installation failed";
    }
    // LCOV_EXCL_STOP

    bool
    shouldReconnectToFog(
        const string &fog,
        const uint16_t port,
        const bool is_secure)
    {
        auto agent_details = Singleton::Consume<I_AgentDetails>::by<OrchestrationComp>();
        return
            agent_details->getSSLFlag() != is_secure ||
            !agent_details->getFogPort().ok() || agent_details->getFogPort().unpack() != port ||
            !agent_details->getFogDomain().ok() || agent_details->getFogDomain().unpack() != fog;
    }

    bool
    updateFogAddress(const string &fog_addr)
    {
        auto orch_status = Singleton::Consume<I_OrchestrationStatus>::by<OrchestrationComp>();
        auto agent_details = Singleton::Consume<I_AgentDetails>::by<OrchestrationComp>();
        auto orchestration_mode = getOrchestrationMode();
        agent_details->setOrchestrationMode(orchestration_mode);
        if (orchestration_mode == OrchestrationMode::OFFLINE) {
            orch_status->setUpgradeMode("Offline upgrades");
            orch_status->setRegistrationStatus("Offline mode");
            orch_status->setFogAddress("");
            if (agent_details->writeAgentDetails()) {
                dbgDebug(D_ORCHESTRATOR) << "Agent details was successfully saved";
            } else {
                dbgWarning(D_COMMUNICATION) << "Failed to save agent details to a file";
            }
            return true;
        }

        if (fog_addr.empty()) return false; // Fog address could not be empty on online update mode

        auto fog_params = parseURLParams(fog_addr);
        if (!fog_params.ok()) {
            dbgWarning(D_ORCHESTRATOR) << "Failed to update Fog address, Error: " << fog_params.getErr();
            return false;
        }
        string fog_domain;
        string fog_query;
        uint16_t fog_port = 0;
        bool encrypted_fog_connection;
        tie(fog_domain, fog_query, fog_port, encrypted_fog_connection) = fog_params.unpack();

        auto message = Singleton::Consume<I_Messaging>::by<OrchestrationComp>();

        if (!shouldReconnectToFog(
            fog_domain,
            fog_port,
            encrypted_fog_connection
        )) {
            dbgDebug(D_ORCHESTRATOR) << "Skipping reconnection to the Fog - Fog details did not change";
            return true;
        }

        if (message->setActiveFog(fog_domain, fog_port, encrypted_fog_connection, MessageTypeTag::GENERIC)) {
            agent_details->setFogPort(fog_port);
            agent_details->setFogDomain(fog_domain);
            agent_details->setSSLFlag(encrypted_fog_connection);

            if (agent_details->writeAgentDetails()) {
                dbgDebug(D_ORCHESTRATOR) << "Agent details was successfully saved";
            } else {
                dbgWarning(D_COMMUNICATION) << "Failed to save agent details to a file";
            }

            auto update_communication = Singleton::Consume<I_UpdateCommunication>::by<OrchestrationComp>();
            update_communication->setAddressExtenesion(fog_query);
            orch_status->setFogAddress(fog_addr);
            return true;
        }

        dbgWarning(D_ORCHESTRATOR) << "Failed to connect to the Fog, Address: " << fog_addr;
        return false;
    }

    // Returns Base URL, Query, Port, SSL
    Maybe<tuple<string, string, uint16_t, bool>>
    parseURLParams(const string &url)
    {
        URLParser url_parser(url);
        auto fog_base_url = url_parser.getBaseURL();

        if (!fog_base_url.ok()) return genError("Failed to parse address. Address: " + url);

        auto fog_port = url_parser.getPort();
        uint16_t port;
        try {
            port = stoi(fog_port);
        } catch (const exception& err) {
            return genError("Failed to parse port. Port: " + fog_port + ", Error:" + err.what());
        }

        return make_tuple(
            fog_base_url.unpack(),
            url_parser.getQuery(),
            port,
            url_parser.isOverSSL()
        );
    }

    OrchestrationMode
    getOrchestrationMode()
    {
        string orchestration_mode = getConfigurationFlag("orchestration-mode");
        if (
            orchestration_mode == "online_mode" ||
            orchestration_mode == "hybrid_mode" ||
            orchestration_mode == "offline_mode"
        ) {
            dbgTrace(D_ORCHESTRATOR) << "Orchestraion mode: " << orchestration_mode;
            if (orchestration_mode == "online_mode") {
                return OrchestrationMode::ONLINE;
            } else if (orchestration_mode == "hybrid_mode") {
                return OrchestrationMode::HYBRID;
            } else {
                return OrchestrationMode::OFFLINE;
            }
        } else if (orchestration_mode == ""){
            dbgInfo(D_ORCHESTRATOR) <<
                "Orchestraion mode was not found in configuration file, continue in online mode";
        } else {
            dbgError(D_ORCHESTRATOR)
                << "Unexpected orchestration mode found in configuration file: "
                << orchestration_mode;
        }
        return OrchestrationMode::ONLINE;
    }

    void
    setAgentDetails()
    {
        static const string openssl_dir_cmd = "openssl version -d | cut -d\" \" -f2 | cut -d\"\\\"\" -f2";
        auto i_shell_cmd = Singleton::Consume<I_ShellCmd>::by<OrchestrationComp>();
        auto result = i_shell_cmd->getExecOutput(openssl_dir_cmd);
        if (result.ok()) {
            string val_openssl_dir = result.unpack();
            if (val_openssl_dir.empty()) return;
            if (val_openssl_dir.back() == '\n') val_openssl_dir.pop_back();
            dbgTrace(D_ORCHESTRATOR)
                << "Adding OpenSSL default directory to agent details. Directory: "
                << val_openssl_dir;

            auto agent_details = Singleton::Consume<I_AgentDetails>::by<OrchestrationComp>();
            agent_details->setOpenSSLDir(val_openssl_dir + "/certs");
            agent_details->setOrchestrationMode(getOrchestrationMode());
            agent_details->writeAgentDetails();
        } else {
            dbgWarning(D_ORCHESTRATOR)
                << "Failed to load OpenSSL default certificate authority. Error: "
                << result.getErr();
        }
    }

    bool
    shouldReportAgentDetailsMetadata()
    {
        bool should_report_agent_details_metadata = true;
#if defined(gaia) || defined(smb)
        auto i_shell_cmd = Singleton::Consume<I_ShellCmd>::by<OrchestrationComp>();
        auto result = i_shell_cmd->getExecOutput("stat -c %Y $FWDIR/state/local/FW1");
        if (!result.ok()) return should_report_agent_details_metadata;
        string current_update_time = result.unpack();
        fw_last_update_time = fw_last_update_time.empty() ? current_update_time : fw_last_update_time;
        try {
                bool is_fw_dir_changed = stoi(current_update_time) > stoi(fw_last_update_time);
                if (!is_fw_dir_changed) {
                    should_report_agent_details_metadata = false;
                } else {
                    fw_last_update_time = current_update_time;
                }
        } catch (const exception& err) {
            dbgWarning(D_ORCHESTRATOR)
                << "Failed to check if access policy was recently updated , Error:"
                <<  err.what();
        }
#endif // gaia || smb
        return should_report_agent_details_metadata;
    }

    class AddProxyRest : public ServerRest
    {
    public:
        void
        doCall() override
        {
            auto agent_details = Singleton::Consume<I_AgentDetails>::by<OrchestrationComp>();
            agent_details->setProxy(proxy.get());
            agent_details->writeAgentDetails();
        }

    private:
        C2S_PARAM(string, proxy);
    };

    const uint16_t default_fog_dport = 443;
    OrchestrationPolicy policy;
    HealthCheckStatusListener health_check_status_listener;
    HybridModeMetric hybrid_mode_metric;
    EnvDetails env_details;

    string filesystem_prefix = "";
    AgentDataReport curr_agent_data_report;
};

OrchestrationComp::OrchestrationComp()
        :
    Component("OrchestrationComp"),
    pimpl(make_unique<Impl>())
{
}

OrchestrationComp::~OrchestrationComp() {}

void
OrchestrationComp::init()
{
    pimpl->init();
}

void
OrchestrationComp::fini()
{
    pimpl->fini();
}

void
OrchestrationComp::preload()
{
    Singleton::Consume<I_Environment>::by<OrchestrationComp>()->registerValue<bool>("Is Orchestrator", true);

    registerExpectedConfiguration<string>("orchestration", "Backup file extension");
    registerExpectedConfiguration<string>("orchestration", "Multitenancy Greedy mode");
    registerExpectedConfiguration<string>("orchestration", "Service name");
    registerExpectedConfiguration<string>("orchestration", "Packages directory");
    registerExpectedConfiguration<string>("orchestration", "Manifest file path");
    registerExpectedConfiguration<string>("orchestration", "Settings file path");
    registerExpectedConfiguration<string>("orchestration", "Data file path");
    registerExpectedConfiguration<string>("orchestration", "Policy file path");
    registerExpectedConfiguration<string>("orchestration", "Configuration path");
    registerExpectedConfiguration<string>("orchestration", "Configuration directory");
    registerExpectedConfiguration<string>("orchestration", "Default Check Point directory");
    registerExpectedConfiguration<string>("orchestration", "Configuration file extension");
    registerExpectedConfiguration<string>("orchestration", "Policy file extension");
    registerExpectedConfiguration<string>("orchestration", "Temp file extension");
    registerExpectedConfiguration<string>("orchestration", "Services ports file");
    registerExpectedConfiguration<string>("orchestration", "Orchestration status path");
    registerExpectedConfiguration<string>("orchestration", "Ignore packages list file path");
    registerExpectedConfiguration<string>("orchestration", "Supported practices file path");
    registerExpectedConfiguration<string>("orchestration", "Nginx metadata temp file");
    registerExpectedConfiguration<int>("orchestration", "Default sleep interval");
    registerExpectedConfiguration<int>("orchestration", "Reconfiguration timeout seconds");
    registerExpectedConfiguration<int>("orchestration", "Download pending time frame seconds");
    registerExpectedSetting<vector<string>>("orchestration", "Orchestration status ignored policies");
    registerExpectedSetting<string>("agentType");
    registerExpectedSetting<string>("upgradeMode");
    registerExpectedSetting<string>("upgradeTime");
    registerExpectedSetting<uint>("upgradeDurationHours");
    registerExpectedSetting<vector<string>>("upgradeDay");
    registerExpectedSetting<string>("email-address");
    registerExpectedSetting<string>("registered-server");
    registerExpectedConfigFile("orchestration", Config::ConfigFileType::Policy);
    registerExpectedConfigFile("registration-data", Config::ConfigFileType::Policy);
}
