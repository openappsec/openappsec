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

#include "service_controller.h"

#include <cereal/types/unordered_set.hpp>
#include <algorithm>
#include <sstream>
#include <unistd.h>

#include "config.h"
#include "debug.h"
#include "rest.h"
#include "connkey.h"
#include "i_messaging.h"
#include "common.h"
#include "log_generator.h"
#include "i_orchestration_tools.h"
#include "customized_cereal_map.h"
#include "declarative_policy_utils.h"

using namespace std;
using namespace ReportIS;

USE_DEBUG_FLAG(D_ORCHESTRATOR);

class SendConfigurations : public ClientRest
{
public:
    SendConfigurations(int _id, const string &ver) : id(_id), policy_version(ver) {}

    BOTH_PARAM(int, id);
    S2C_PARAM(bool, error);
    S2C_PARAM(bool, finished);
    S2C_OPTIONAL_PARAM(string, error_message);
    C2S_PARAM(string, policy_version);
};

class ServiceReconfStatusMonitor : Singleton::Consume<I_ServiceController>, public ServerRest
{
public:
    void
    doCall() override
    {
        auto service_controller = Singleton::Consume<I_ServiceController>::by<ServiceReconfStatusMonitor>();
        if (!finished.get()) {
            service_controller->updateReconfStatus(id.get(), service_name.get(), ReconfStatus::IN_PROGRESS);
            dbgTrace(D_ORCHESTRATOR)
                << "Request for service reconfiguration is still in progress. ID: "
                << id.get()
                << ", Service Name: "
                << service_name.get();
            return;
        }
        if (error.get()) {
            service_controller->updateReconfStatus(id.get(), service_name.get(), ReconfStatus::FAILED);
            dbgError(D_ORCHESTRATOR)
                << "Request for service reconfiguration failed to complete. ID: "
                << id.get()
                << ", Service Name: "
                << service_name.get()
                << "."
                << (error_message.isActive() ? " Error: " + error_message.get() : "");
            return;
        }
        service_controller->updateReconfStatus(id.get(), service_name.get(), ReconfStatus::SUCCEEDED);
        dbgInfo(D_ORCHESTRATOR)
            << "Request for service reconfiguration successfully accomplished. Reconf ID: "
            << id.get()
            << ", Service Name: "
            << service_name.get();
        return;
    }

private:
    C2S_PARAM(int, id);
    C2S_PARAM(string, service_name);
    C2S_PARAM(bool, error);
    C2S_PARAM(bool, finished);
    C2S_OPTIONAL_PARAM(string, error_message);
};

bool
ServiceDetails::isServiceActive() const
{
    stringstream watchdog_status_cmd;
    watchdog_status_cmd
        << getFilesystemPathConfig()
        << "/watchdog/cp-nano-watchdog --status --verbose --service "
        << service_name;

    if (!service_id.empty() && service_id != service_name) {
        string uuid = "";
        if (service_id.find("_") != string::npos) {
            string fid = service_id.substr(0, service_id.find("_"));
            uuid = service_id.substr(service_id.find("_") + 1, service_id.size());
            watchdog_status_cmd << " --family " << fid << " --id " << uuid;
        } else {
            uuid = service_id;
            watchdog_status_cmd << " --id " << uuid;
        }
    }

    dbgDebug(D_ORCHESTRATOR)
        << "Executing service status check via watchdog api. Service name: "
        << service_name
        << ", Watchdog command: "
        << watchdog_status_cmd.str();

    I_ShellCmd *shell_cmd = Singleton::Consume<I_ShellCmd>::by<ServiceController>();
    Maybe<string> service_status = shell_cmd->getExecOutput(watchdog_status_cmd.str());

    int max_retry_attempts = getConfigurationWithDefault<int>(
        5,
        "orchestration",
        "service controller attempts before timeout"
    );

    uint default_ms_tmout = 200;
    uint ms_tmout = default_ms_tmout;

    for (int current_attempt = 0; current_attempt < max_retry_attempts; ++current_attempt) {
        if (service_status.ok() || service_status.getErr().find("Reached timeout") == string::npos) break;

        dbgWarning(D_ORCHESTRATOR)
            << "Retrying to execute service status check via watchdog API after getting timeout. Service name: "
            << service_name
            << ", Watchdog command: "
            << watchdog_status_cmd.str()
            << ", retry number: "
            << (current_attempt + 1);

        ms_tmout = default_ms_tmout*(current_attempt + 2);
        service_status = shell_cmd->getExecOutput(watchdog_status_cmd.str(), ms_tmout);
    }

    if (!service_status.ok()) {
        dbgWarning(D_ORCHESTRATOR)
            << "Changing service status to inactive after failure to its status from watchdog. Service name: "
            << service_name
            << ", Watchdog output: "
            << service_status.getErr();
        return false;
    }

    dbgDebug(D_ORCHESTRATOR)
        << "Successfully retrieved service status from watchdog. Service name: "
        << service_name
        << ", Watchdog output: "
        << *service_status;

    string status = service_status.unpack();
    for_each(status.begin(), status.end(), [](char &c) { c = ::tolower(c); });

    bool is_registered = status.find("not-registered") == string::npos && status.find("registered") != string::npos;
    bool is_running = status.find("not-running") == string::npos && status.find("running") != string::npos;

    dbgInfo(D_ORCHESTRATOR)
        << "Successfully set service status. Service name: "
        << service_name
        << ", Status: "
        << ((is_registered && is_running) ? "active" : "inactive");

    return is_registered && is_running;
}

template <typename Archive>
void
ServiceDetails::serialize(Archive &ar)
{
    ar(cereal::make_nvp("Service name", service_name));
    ar(cereal::make_nvp("Service ID", service_id));
    ar(cereal::make_nvp("Service port", service_port));
    ar(cereal::make_nvp("Relevant configs", relevant_configs));
}

ReconfStatus
ServiceDetails::sendNewConfigurations(int configuration_id, const string &policy_version)
{
    if(!isServiceActive()) {
        dbgDebug(D_ORCHESTRATOR) << "Service " << service_name << " is inactive";
        return ReconfStatus::INACTIVE;
    }

    SendConfigurations new_config(configuration_id, policy_version);

    I_Messaging *messaging = Singleton::Consume<I_Messaging>::by<ServiceController>();
    Flags<MessageConnConfig> conn_flags;
    conn_flags.setFlag(MessageConnConfig::ONE_TIME_CONN);
    bool res = messaging->sendObject(
        new_config,
        I_Messaging::Method::POST,
        "127.0.0.1",
        service_port,
        conn_flags,
        "/set-new-configuration"
    );

    if (!res) {
        dbgDebug(D_ORCHESTRATOR) << "Service " << service_name << " didn't respond to new configuration request";
        return ReconfStatus::FAILED;
    }

    auto service_details = Singleton::Consume<I_ServiceController>::by<ServiceDetails>();

    if (new_config.finished.get()) {
        if (!new_config.error.get()) {
            service_details->startReconfStatus(new_config.id.get(), ReconfStatus::SUCCEEDED, service_name, service_id);
            dbgDebug(D_ORCHESTRATOR) << "Loading service configuration succeeded for service " << service_name;
            return ReconfStatus::SUCCEEDED;
        } else {
            string log_name = "Agent could not update policy to version " +
                service_details->getUpdatePolicyVersion() +
                ". " +
                (new_config.error_message.isActive() ? "Additional details: " + new_config.error_message.get() : "");
            LogGen(
                log_name,
                Audience::SECURITY,
                Severity::CRITICAL,
                Priority::HIGH,
                Tags::ORCHESTRATOR
            )
                << LogField("ServiceName", service_name)
                << LogField("policyVersion", service_details->getPolicyVersion());

            service_details->startReconfStatus(new_config.id.get(), ReconfStatus::FAILED, service_name, service_id);
            dbgDebug(D_ORCHESTRATOR)
                << "Loading service configuration failed for service "
                << service_name
                << " with error: "
                << (new_config.error_message.isActive() ? new_config.error_message.get() : "");
            return ReconfStatus::FAILED;
        }
    }
    dbgDebug(D_ORCHESTRATOR) << "Loading service configuration is in progress for service: " << service_name;
    service_details->startReconfStatus(new_config.id.get(), ReconfStatus::IN_PROGRESS, service_name, service_id);
    return ReconfStatus::IN_PROGRESS;
}

void
SetNanoServiceConfig::doCall()
{
    dbgFlow(D_ORCHESTRATOR)
        << "Received registration request from service. Service name: "
        << service_name.get()
        << ", service listening port: "
        << service_listening_port.get();

    I_ServiceController *i_service_controller = Singleton::Consume<I_ServiceController>::from<ServiceController>();
    i_service_controller->registerServiceConfig(
        service_name,
        service_listening_port,
        expected_configurations,
        service_id.isActive() ? service_id.get() : service_name.get()
    );

    status = true;
}

class ServiceController::Impl
        :
    Singleton::Provide<I_ServiceController>::From<ServiceController>,
    Singleton::Consume<I_OrchestrationTools>
{
public:
    void init();

    Maybe<void>
    updateServiceConfiguration(
        const string &new_policy_path,
        const string &new_settings_path,
        const vector<string> &new_data_files,
        const string &child_tenant_id,
        const string &child_profile_id,
        const bool last_iteration
    ) override;

    bool isServiceInstalled(const string &service_name) override;

    void registerServiceConfig(
        const string &service_name,
        PortNumber listening_port,
        const vector<string> &relevant_configurations,
        const string &service_id
    ) override;

    void refreshPendingServices() override;
    const string & getPolicyVersion() const override;
    const string & getUpdatePolicyVersion() const override;
    const string & getPolicyVersions() const override;
    void updateReconfStatus(int id, const string &service_name, ReconfStatus status) override;
    void startReconfStatus(
        int id,
        ReconfStatus status,
        const string &service_name,
        const string &service_id
    ) override;

    bool doesFailedServicesExist() override;

    void clearFailedServices() override;

    set<string> && moveChangedPolicies() override;

private:
    void cleanUpVirtualFiles();

    Maybe<void> sendSignalForServices(
        const set<string> &nano_services_to_update,
        const string &policy_version_to_update);

    Maybe<void> updateServiceConfigurationFile(
        const string &configuration_name,
        const string &configuration_file_path,
        const string &new_configuration_path);

    ReconfStatus getUpdatedReconfStatus();
    Maybe<ServiceDetails> getServiceDetails(const string &service_name);
    map<string, PortNumber> getServiceToPortMap();

    template<class Archive>
    void serializeRegisterServices(Archive &ar) { ar(pending_services); }

    void loadRegisteredServicesFromFile();
    void writeRegisteredServicesToFile();

    bool backupConfigurationFile(const string &configuration_file_path);
    bool createDirectoryForChildTenant(const string &child_tenant_id, const string &child_profile_id) const;

    int configuration_id = 0;
    map<string, ServiceDetails> registered_services;
    map<string, ServiceDetails> pending_services;
    string policy_versions;
    string policy_version;
    string update_policy_version;
    string settings_path;
    map<int, ReconfStatus> services_reconf_status;
    map<int, ReconfStatus> failed_services;
    map<int, string> services_reconf_names;
    map<int, string> services_reconf_ids;
    string filesystem_prefix;
    bool is_multi_tenant_env = false;
    set<string> changed_policy_files;

    I_OrchestrationTools *orchestration_tools = nullptr;
    I_MainLoop *mainloop = nullptr;
};

class GetServicesPorts : public ServerRest
{
public:
    void
    doCall()
    {
        stringstream output;
        auto ports_map = Singleton::Consume<I_ServiceController>::from<ServiceController>()->getServiceToPortMap();
        for (auto const& entry: ports_map) {
            string service = entry.first;
            replace(service.begin(), service.end(), ' ', '-');
            output << service << ":";
            output << entry.second << ",";
        }
        ports_list = output.str();
    }

    S2C_PARAM(string, ports_list);
};

Maybe<ServiceDetails>
ServiceController::Impl::getServiceDetails(const string &service_id)
{
    auto iter = registered_services.find(service_id);
    if (iter != registered_services.end()) return iter->second;

    return genError("did not find service details for the provided service name. service id: " + service_id);
}

ReconfStatus
ServiceController::Impl::getUpdatedReconfStatus()
{
    ReconfStatus res = ReconfStatus::SUCCEEDED;

    for(auto &service_and_reconf_status : services_reconf_status) {
        string service_id = services_reconf_ids[service_and_reconf_status.first];
        auto maybe_service = getServiceDetails(service_id);

        if (!maybe_service.ok()) {
            dbgWarning(D_ORCHESTRATOR) << "Unable to get service details. Error: " << maybe_service.getErr();
            continue;
        }

        if (!maybe_service.unpack().isServiceActive()) {
            dbgInfo(D_ORCHESTRATOR)
                << "Service is not active, removing from registered services list. Service: "
                << services_reconf_names[service_and_reconf_status.first]
                << "ID: "
                << service_id;
            registered_services.erase(service_id);
            service_and_reconf_status.second = ReconfStatus::INACTIVE;
            writeRegisteredServicesToFile();

            continue;
        }

        if (res < service_and_reconf_status.second)  res = service_and_reconf_status.second;
    }

    return res;
}

// LCOV_EXCL_START Reason: future fix will be done
void
ServiceController::Impl::clearFailedServices()
{
    failed_services.clear();
}

bool
ServiceController::Impl::doesFailedServicesExist()
{
    return (failed_services.size() > 0);
}
// LCOV_EXCL_STOP

set<string> &&
ServiceController::Impl::moveChangedPolicies()
{
    return move(changed_policy_files);
}

void
ServiceController::Impl::init()
{
    auto rest = Singleton::Consume<I_RestApi>::by<ServiceController>();
    rest->addRestCall<SetNanoServiceConfig>(RestAction::SET, "nano-service-config");
    rest->addRestCall<GetServicesPorts>(RestAction::SHOW, "all-service-ports");
    rest->addRestCall<ServiceReconfStatusMonitor>(RestAction::SET, "reconf-status");

    orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<ServiceController>();
    mainloop = Singleton::Consume<I_MainLoop>::by<ServiceController>();

    Singleton::Consume<I_MainLoop>::by<ServiceController>()->addRecurringRoutine(
        I_MainLoop::RoutineType::System,
        chrono::seconds(
            getConfigurationWithDefault<int>(
                86400,
                "orchestration",
                "Cleanup virtual tenant seconds interval"
            )
        ),
        [this] () { cleanUpVirtualFiles(); },
        "Cleanup virtual tenants"
    );

    filesystem_prefix = getFilesystemPathConfig();

    loadRegisteredServicesFromFile();

    auto agent_type = getSetting<string>("agentType");
    if (agent_type.ok() && (*agent_type == "CloudNative" || *agent_type == "VirtualNSaaS")) {
        is_multi_tenant_env = true;
    }
}

void
ServiceController::Impl::loadRegisteredServicesFromFile()
{
    auto registered_services_file = getConfigurationWithDefault<string>(
        filesystem_prefix + "/conf/orchestrations_registered_services.json",
        "orchestration",
        "Orchestration registered services"
    );
    auto maybe_registered_services_str = Singleton::Consume<I_OrchestrationTools>::by<ServiceController::Impl>()->
        readFile(registered_services_file);
    if (!maybe_registered_services_str.ok()) {
        dbgTrace(D_ORCHESTRATOR)
            << "could not read file. File: "
            << registered_services_file
            << " Error: " << maybe_registered_services_str.getErr();
        return;
    }

    stringstream ss(maybe_registered_services_str.unpack());
    cereal::JSONInputArchive ar(ss);
    ar(cereal::make_nvp("Registered Services", pending_services));

    dbgInfo(D_ORCHESTRATOR)
        << "Orchestration pending services loaded from file."
        << " File: "
        << registered_services_file
        << ". Registered Services:";

    for (const auto &id_service_pair : pending_services) {
        const auto &service = id_service_pair.second;
        dbgInfo(D_ORCHESTRATOR)
            << "Service name: "
            << service.getServiceName()
            << ", Service ID: "
            << service.getServiceID()
            << ", Service port: "
            << service.getPort();
    }
}

void
ServiceController::Impl::writeRegisteredServicesToFile()
{
    dbgFlow(D_ORCHESTRATOR);
    auto registered_services_file = getConfigurationWithDefault<string>(
        filesystem_prefix + "/conf/orchestrations_registered_services.json",
        "orchestration",
        "Orchestration registered services"
    );

    ofstream ss(registered_services_file);
    cereal::JSONOutputArchive ar(ss);
    ar(cereal::make_nvp("Registered Services", registered_services));

    dbgInfo(D_ORCHESTRATOR)
        << "Orchestration registered services file has been updated. File: "
        << registered_services_file
        << ". Registered Services:";

    for (const auto &id_service_pair : registered_services) {
        const auto &service = id_service_pair.second;
        dbgInfo(D_ORCHESTRATOR)
            << "Service name: "
            << service.getServiceName()
            << ", Service ID: "
            << service.getServiceID()
            << ", Service port: "
            << service.getPort();
    }
}

void
ServiceController::Impl::cleanUpVirtualFiles()
{
    const string file_list_cmd =
        "ls " +
        getConfigurationWithDefault<string>(
            filesystem_prefix + "/conf",
            "orchestration",
            "Configuration directory"
        ) +
        " | grep 'tenant_*' | cut -d '_' -f 2";

    auto shell_cmd = Singleton:: Consume<I_ShellCmd>::by<ServiceController>();
    auto tenant_manager = Singleton::Consume<I_TenantManager>::by<ServiceController>();

    auto result = shell_cmd->getExecOutput(file_list_cmd);
    if (!result.ok()) return;

    set<string> tenants_on_agent;

    istringstream parsig(*result);
        while (!parsig.eof()) {
        string tenant_id;
        getline(parsig, tenant_id);
        if (!tenant_id.empty()) tenants_on_agent.insert(tenant_id);
    }

    for (const auto &active_tenant: tenant_manager->fetchActiveTenants()) {
        tenants_on_agent.erase(active_tenant);
    }

    for (const auto &none_active_tenant: tenants_on_agent) {
        // remove files;
        string settings_file = filesystem_prefix + "/conf/"+  none_active_tenant + "_settings.json";
        string tenant_dir = filesystem_prefix + "/conf/tenant_"+  none_active_tenant;

        Singleton::Consume<I_OrchestrationTools>::by<ServiceController>()->removeFile(settings_file);
        rmdir(tenant_dir.c_str());
    }
}

map<string, PortNumber>
ServiceController::Impl::getServiceToPortMap()
{
    map<string, PortNumber> ports_map;
    for (auto const& entry: registered_services) {
        const string &service = entry.first;
        PortNumber port = entry.second.getPort();
        ports_map[service] = port;
    }

    for (auto const& entry: pending_services) {
        const string &service = entry.first;
        PortNumber port = entry.second.getPort();
        ports_map[service] = port;
    }

    return ports_map;
}

void
ServiceController::Impl::registerServiceConfig(
    const string &service_name,
    PortNumber listening_port,
    const vector<string> &relevant_configurations,
    const string &service_id)
{
    ServiceDetails service_config(
        service_name,
        listening_port,
        relevant_configurations,
        service_id
    );

    pending_services.erase(service_config.getServiceID());
    pending_services.insert({service_config.getServiceID(), service_config});
}

bool
ServiceController::Impl::isServiceInstalled(const string &service_name)
{
    return
        registered_services.find(service_name) != registered_services.end() ||
        pending_services.find(service_name) != pending_services.end();
}

void
ServiceController::Impl::refreshPendingServices()
{
    dbgFlow(D_ORCHESTRATOR);
    if (pending_services.empty()) return;
    for (const auto &service : pending_services) {
        registered_services.erase(service.first);
        registered_services.insert({service.first, service.second});
        dbgDebug(D_ORCHESTRATOR) << "Successfully registered service. Name: " << service.first;
    }
    pending_services.clear();

    writeRegisteredServicesToFile();
}

bool
ServiceController::Impl::backupConfigurationFile(const string &config_file_path)
{
    uint max_backup_attempts = 3;
    string backup_ext = getConfigurationWithDefault<string>(".bk", "orchestration", "Backup file extension");
    string backup_file = config_file_path + backup_ext;

    if (!orchestration_tools->doesFileExist(config_file_path)) {
        dbgTrace(D_ORCHESTRATOR) << "File does not exist. File: " << config_file_path;
        return true;
    }

    for (size_t i = 0; i < max_backup_attempts; i++) {
        if (orchestration_tools->copyFile(config_file_path, backup_file)) {
            return true;
        }
        mainloop->yield(false);
    }

    dbgWarning(D_ORCHESTRATOR) << "Failed to back up the file. File: " << config_file_path;
    return false;
}

bool
ServiceController::Impl::createDirectoryForChildTenant(
    const string &child_tenant_id,
    const string &child_profile_id) const
{
    if (child_tenant_id == "") return true;

    auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<ServiceController>();
    string dir = getConfigurationWithDefault<string>(
        filesystem_prefix + "/conf",
        "orchestration",
        "Configuration directory"
    );

    dir = dir + "/tenant_" + child_tenant_id + "_profile_" + child_profile_id;
    if (orchestration_tools->doesDirectoryExist(dir)) return true;

    if (!orchestration_tools->createDirectory(dir)) {
        dbgError(D_ORCHESTRATOR)
            << "Failed to create configuration directory for tenant "
            << child_tenant_id;
        return false;
    }
    dbgTrace(D_ORCHESTRATOR) << "Created new configuration directory for tenant " << child_tenant_id;
    return true;
}

Maybe<void>
ServiceController::Impl::updateServiceConfiguration(
    const string &new_policy_path,
    const string &new_settings_path,
    const vector<string> &new_data_files,
    const string &child_tenant_id,
    const string &child_profile_id,
    const bool last_iteration)
{
    string tenant_and_profile_ids = "";
    if (!child_tenant_id.empty()) {
        tenant_and_profile_ids = " Child tenant id: " + child_tenant_id + ", Child profile id: " + child_profile_id;
    }
    dbgFlow(D_ORCHESTRATOR)
        << "new_policy_path: "
        << new_policy_path
        << ",  new_settings_path: "
        << new_settings_path
        << ", new_data_files: "
        << makeSeparatedStr(new_data_files, ",")
        << "."
        << tenant_and_profile_ids;

    if (!new_settings_path.empty()) {
        settings_path = new_settings_path;
    }

    refreshPendingServices();

    set<string> nano_services_to_update;
    for (const auto &service : registered_services) {
        if (new_settings_path != "") {
            nano_services_to_update.insert(service.first);
            continue;
        }

        for (const string &data : new_data_files) {
            dbgTrace(D_ORCHESTRATOR) << "data: " << data;
            if (service.second.isConfigurationRelevant(data)) {
                dbgTrace(D_ORCHESTRATOR)
                    << "data has relevant configuration, will update the service: "
                    << service.first;
                nano_services_to_update.insert(service.first);
                break;
            }
        }
    }

    if (new_policy_path == "") {
        dbgDebug(D_ORCHESTRATOR) << "Policy file was not updated. Sending reload command regarding settings and data";
        auto signal_services = sendSignalForServices(nano_services_to_update, "");
        if (!signal_services.ok()) return signal_services.passErr();
        Singleton::Consume<I_DeclarativePolicy>::from<DeclarativePolicyUtils>()->turnOffApplyPolicyFlag();
        return Maybe<void>();
    }

    Maybe<string> loaded_policy_json = orchestration_tools->readFile(new_policy_path);
    if (!loaded_policy_json.ok()) {
        dbgWarning(D_ORCHESTRATOR)
            << "Failed to load new file: "
            << new_policy_path
            << ". Error: "
            << loaded_policy_json.getErr();

        return genError("Failed to load new file: " + new_policy_path + ". Error: " + loaded_policy_json.getErr());
    }

    auto all_security_policies = orchestration_tools->jsonObjectSplitter(
        loaded_policy_json.unpack(),
        child_tenant_id,
        child_profile_id
    );

    if (!all_security_policies.ok()) {
        dbgWarning(D_ORCHESTRATOR)
            << "Failed to parse json file: "
            << new_policy_path
            << ". Error: "
            << all_security_policies.getErr();

        return genError("Failed to parse json file: " +
            new_policy_path +
            ". Error: " +
            all_security_policies.getErr()
        );
    }

    bool was_policy_updated = true;
    const string version_param = "version";
    const string versions_param = "versions";
    string version_value;
    string send_signal_for_services_err;

    changed_policy_files.clear();
    for (auto &single_policy : all_security_policies.unpack()) {
        if (single_policy.first == version_param) {
            version_value = single_policy.second;
            version_value.erase(remove(version_value.begin(), version_value.end(), '\"'), version_value.end());
            update_policy_version = version_value;
            continue;
        }
        if (child_tenant_id.empty() && single_policy.first == versions_param) {
            //In a multi-tenant env, only the parent should handle the versions parameter
            policy_versions = single_policy.second;
            dbgWarning(D_ORCHESTRATOR) << "Found versions parameter in policy file:" << policy_versions;
        }

        dbgDebug(D_ORCHESTRATOR) << "Starting to update policy file. Policy type: " << single_policy.first;

        if (!createDirectoryForChildTenant(child_tenant_id, child_profile_id)) {
            dbgWarning(D_ORCHESTRATOR)
                << "Failed to create directory for child. Tenant id: " << child_tenant_id
                << ", Profile id: " << child_profile_id;
            return genError("Failed to create directory for child tenant");
        }

        string policy_file_path =
            getPolicyConfigPath(
                single_policy.first,
                Config::ConfigFileType::Policy,
                child_tenant_id,
                child_profile_id
            );

        auto update_config_result = updateServiceConfigurationFile(
            single_policy.first,
            policy_file_path,
            single_policy.second
        );

        if (!update_config_result.ok()) {
            send_signal_for_services_err =  "Failed to update policy file. Policy name: " +
                single_policy.first +
                ". Error: " +
                update_config_result.getErr();
            was_policy_updated = false;
            continue;
        }
        changed_policy_files.insert(policy_file_path);

        dbgInfo(D_ORCHESTRATOR) << "Successfully updated policy file. Policy name: " << single_policy.first;

        auto orc_status = Singleton::Consume<I_OrchestrationStatus>::by<ServiceController>();
        orc_status->setServiceConfiguration(
            single_policy.first,
            policy_file_path,
            OrchestrationStatusConfigType::POLICY
        );

        if (child_tenant_id != "") {
            auto instances = Singleton::Consume<I_TenantManager>::by<ServiceController>()->getInstances(
                child_tenant_id,
                child_profile_id
            );
            for (const auto &instance_id: instances) {
                auto relevant_service = registered_services.find(instance_id);
                if (relevant_service == registered_services.end()) {
                    dbgWarning(D_ORCHESTRATOR) << "Could not find registered service. Service Id: " << instance_id;
                    continue;
                }
                if (relevant_service->second.isConfigurationRelevant(single_policy.first)) {
                    nano_services_to_update.insert(instance_id);
                }
            }
        } else {
            for (const auto &service : registered_services) {
                if (service.second.isConfigurationRelevant(single_policy.first)) {
                    nano_services_to_update.insert(service.first);
                }
            }
        }
    }

    // In a multi-tenant env, we send the signal to the services only on the last iteration
    if (!is_multi_tenant_env || last_iteration) {
        auto is_send_signal_for_services = sendSignalForServices(nano_services_to_update, version_value);
        was_policy_updated &= is_send_signal_for_services.ok();
        if (!is_send_signal_for_services.ok()) send_signal_for_services_err = is_send_signal_for_services.getErr();
    }

    dbgTrace(D_ORCHESTRATOR) << "was policy updated: " << (was_policy_updated ? "true" : "false");

    if (was_policy_updated) {
        string base_path =
            filesystem_prefix + "/conf/" +
            (child_tenant_id != "" ? "tenant_" + child_tenant_id + "_profile_" + child_profile_id + "/" : "");

        string config_file_path = getConfigurationWithDefault<string>(
            base_path + "policy.json",
            "orchestration",
            "Policy file path"
        );

        if (new_policy_path.compare(config_file_path) == 0) {
            dbgDebug(D_ORCHESTRATOR) << "Enforcing the default policy file";
            policy_version = version_value;
            Singleton::Consume<I_DeclarativePolicy>::from<DeclarativePolicyUtils>()->turnOffApplyPolicyFlag();
            return Maybe<void>();
        }

        if (!backupConfigurationFile(config_file_path)) {
            dbgWarning(D_ORCHESTRATOR) << "Failed to backup the policy file.";
            return genError("Failed to backup the policy file.");
        }

        policy_version = version_value;

        // Save the new configuration file.
        if (!orchestration_tools->copyFile(new_policy_path, config_file_path)) {
            dbgWarning(D_ORCHESTRATOR) << "Failed to save the policy file.";
            return genError("Failed to save the policy file.");
        }
    }

    if (!was_policy_updated && !send_signal_for_services_err.empty()) return genError(send_signal_for_services_err);
    Singleton::Consume<I_DeclarativePolicy>::from<DeclarativePolicyUtils>()->turnOffApplyPolicyFlag();
    return Maybe<void>();
}

Maybe<void>
ServiceController::Impl::sendSignalForServices(
    const set<string> &nano_services_to_update,
    const string &policy_version_to_update)
{
    dbgFlow(D_ORCHESTRATOR);
    for (auto &service_id : nano_services_to_update) {
        auto nano_service = registered_services.find(service_id);
        if (nano_service == registered_services.end()) {
            dbgWarning(D_ORCHESTRATOR) << "Could not find registered service. Service Id: " << service_id;
            continue;
        }

        ++configuration_id;
        auto reconf_status = nano_service->second.sendNewConfigurations(configuration_id, policy_version_to_update);

        if (reconf_status == ReconfStatus::INACTIVE) {
            dbgWarning(D_ORCHESTRATOR) << "Erasing details regarding inactive service " << service_id;
            registered_services.erase(service_id);
            writeRegisteredServicesToFile();
        }

        if (reconf_status == ReconfStatus::FAILED) {
            dbgDebug(D_ORCHESTRATOR) << "The reconfiguration failed for serivce: " << service_id;
            services_reconf_status.clear();
            services_reconf_names.clear();
            return genError("The reconfiguration failed for serivce: " + service_id);
        }
    }

    int profile_tmo_conf = getProfileAgentSettingWithDefault<int>(
        600,
        "orchestration.configTimeoutSeconds"
    );
    int reconf_timeout = getConfigurationWithDefault<int>(
        profile_tmo_conf,
        "orchestration",
        "Reconfiguration timeout seconds"
    );
    auto timer = Singleton::Consume<I_TimeGet>::by<ServiceController>();
    auto current_timeout = timer->getMonotonicTime() + chrono::seconds(reconf_timeout);
    while(timer->getMonotonicTime() < current_timeout) {
        switch (getUpdatedReconfStatus()) {
            case ReconfStatus::SUCCEEDED: {
                dbgDebug(D_ORCHESTRATOR) << "The reconfiguration was successfully completed for all the services";
                services_reconf_status.clear();
                services_reconf_names.clear();
                return Maybe<void>();
            }
            case ReconfStatus::IN_PROGRESS: {
                dbgTrace(D_ORCHESTRATOR) << "Reconfiguration in progress...";
                Singleton::Consume<I_MainLoop>::by<ServiceController>()->yield(chrono::seconds(2));
                break;
            }
            case ReconfStatus::FAILED: {
                vector<string> failed_services_vec;
                for(auto &status : services_reconf_status) {
                    if (status.second == ReconfStatus::FAILED) {
                        failed_services_vec.push_back(services_reconf_names[status.first]);
                        dbgDebug(D_ORCHESTRATOR)
                            << "The reconfiguration failed for serivce "
                            << services_reconf_names[status.first];
                    }
                }
                services_reconf_status.clear();
                services_reconf_names.clear();

                string failed_services = makeSeparatedStr(failed_services_vec, ", ");

                return genError("The reconfiguration failed for serivces: " + failed_services);
            }
            case ReconfStatus::INACTIVE: {
                dbgError(D_ORCHESTRATOR) << "Reached inactive state in the middle of reconfiguration!";
                services_reconf_status.clear();
                services_reconf_names.clear();
                return genError("Reached inactive state in the middle of reconfiguration!");
            }
        }
    }

    dbgDebug(D_ORCHESTRATOR) << "The reconfiguration has reached a timeout";
    services_reconf_status.clear();
    services_reconf_names.clear();
    return genError("The reconfiguration has reached a timeout");
}

Maybe<void>
ServiceController::Impl::updateServiceConfigurationFile(
    const string &configuration_name,
    const string &configuration_file_path,
    const string &new_configuration_path)
{

    dbgFlow(D_ORCHESTRATOR) << "Updating configuration. Config Name: " << configuration_name;

    if (orchestration_tools->doesFileExist(configuration_file_path)) {
        Maybe<string> old_configuration = orchestration_tools->readFile(configuration_file_path);
        if (old_configuration.ok()) {
            bool service_changed = old_configuration.unpack().compare(new_configuration_path) != 0;
            if (service_changed == false) {
                dbgDebug(D_ORCHESTRATOR) << "There is no update for policy file: " << configuration_file_path;
                return Maybe<void>();
            }
            dbgDebug(D_ORCHESTRATOR)
                << "Starting to update " << configuration_file_path << " to " << new_configuration_path;
            string old_configuration_backup_path = configuration_file_path + getConfigurationWithDefault<string>(
                ".bk",
                "orchestration",
                "Backup file extension"
            );
            if (orchestration_tools->copyFile(configuration_file_path, old_configuration_backup_path)) {
                dbgDebug(D_ORCHESTRATOR) << "Backup of policy file has been created in: " << configuration_file_path;
            } else {
                dbgWarning(D_ORCHESTRATOR) << "Failed to backup policy file";
                return genError("Failed to backup policy file");
            }
        } else {
            dbgWarning(D_ORCHESTRATOR)
                << "Failed to read current policy file "
                << configuration_file_path
                << ". Error: "
                << old_configuration.getErr();

            return genError(
                "Failed to read current policy file " +
                configuration_file_path +
                ". Error: " +
                old_configuration.getErr()
            );
        }
    }

    if (orchestration_tools->writeFile(new_configuration_path, configuration_file_path)) {
        dbgDebug(D_ORCHESTRATOR) << "New policy file has been saved in: " << configuration_file_path;
    } else {
        dbgWarning(D_ORCHESTRATOR) << "Failed to save new policy file";
        return genError("Failed to save new policy file");
    }

    dbgInfo(D_ORCHESTRATOR) << "Successfully updated policy file: " << configuration_file_path;

    return Maybe<void>();
}

ServiceController::ServiceController() : Component("ServiceController"), pimpl(make_unique<Impl>()) {}

ServiceController::~ServiceController() {}

void
ServiceController::init()
{
    pimpl->init();
}

const string &
ServiceController::Impl::getPolicyVersion() const
{
    return policy_version;
}

const string &
ServiceController::Impl::getPolicyVersions() const
{
    return policy_versions;
}

const string &
ServiceController::Impl::getUpdatePolicyVersion() const
{
    return update_policy_version;
}

void
ServiceController::Impl::updateReconfStatus(int id, const string &service_name, ReconfStatus status)
{
    if (status == ReconfStatus::FAILED) {
        failed_services.emplace(id, status);
    }

    if (services_reconf_status.find(id) == services_reconf_status.end()) {
        dbgError(D_ORCHESTRATOR)
            << "Unable to find a mapping for reconfiguration ID:"
            << id
            << ". Service name: "
            << service_name;
        return;
    }
    dbgTrace(D_ORCHESTRATOR)
        << "Updating reconf status for reconfiguration ID "
        << id
        << ", Service name: "
        << service_name
        << ". Status: "
        << static_cast<int>(status);
    services_reconf_status[id] = status;
}

void
ServiceController::Impl::startReconfStatus(
    int id,
    ReconfStatus status,
    const string &service_name,
    const string &service_id)
{
    dbgTrace(D_ORCHESTRATOR)
        << "Starting reconf status. Configuration ID: "
        << id
        << ", service name: "
        << service_name
        << ", service ID: "
        << service_id
        << ", status: "
        << static_cast<int>(status);
    services_reconf_status.emplace(id, status);
    services_reconf_names.emplace(id, service_name);
    services_reconf_ids.emplace(id, service_id);
}
