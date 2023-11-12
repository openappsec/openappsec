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

#include "config.h"
#include "config_component.h"

#include <dirent.h>
#include <algorithm>
#include <fstream>
#include <boost/regex.hpp>
#include "agent_core_utilities.h"

#include "cereal/archives/json.hpp"

#include "debug.h"
#include "cereal/external/rapidjson/error/en.h"
#include "include/profile_settings.h"
#include "enum_range.h"
#include "rest.h"
#include "tenant_profile_pair.h"

using namespace std;
using namespace cereal;
using namespace Config;

USE_DEBUG_FLAG(D_CONFIG);

static const string not_found = "";

AgentProfileSettings AgentProfileSettings::default_profile_settings = AgentProfileSettings();

class registerExpectedConfigUpdates : public ClientRest
{
public:
    C2S_PARAM(string, service_name);
    C2S_OPTIONAL_PARAM(string, service_id);
    C2S_PARAM(int, service_listening_port);
    C2S_PARAM(vector<string>, expected_configurations);
    S2C_PARAM(bool, status);
};

class LoadNewConfigurationStatus : public ClientRest
{
public:
    LoadNewConfigurationStatus(uint _id, string _service_name, bool _error, bool end)
            :
        id(_id), service_name(_service_name), error(_error), finished(end) {}

    void setError(const string &error) { error_message = error; }

private:
    C2S_PARAM(int, id);
    C2S_PARAM(string, service_name);
    C2S_PARAM(bool, error);
    C2S_PARAM(bool, finished);
    C2S_OPTIONAL_PARAM(string, error_message);
};

class LoadNewConfiguration : public ServerRest
{
public:
    void
    doCall() override
    {
        static const map<I_Config::AsyncLoadConfigStatus, string> status_map {
            {I_Config::AsyncLoadConfigStatus::Success, "Success"},
            {I_Config::AsyncLoadConfigStatus::InProgress, "In Progress"},
            {I_Config::AsyncLoadConfigStatus::Error, "Error"}
        };

        auto i_config = Singleton::Consume<I_Config>::from<ConfigComponent>();
        I_Config::AsyncLoadConfigStatus load_config_staus = i_config->reloadConfiguration(policy_version, true, id);

        finished = load_config_staus != I_Config::AsyncLoadConfigStatus::InProgress;
        error = load_config_staus == I_Config::AsyncLoadConfigStatus::Error;

        if (error) {
            error_message = "Reload already in progress - can't start another one";
            dbgWarning(D_CONFIG) << "Configuration reload status: " << status_map.at(load_config_staus);
        } else {
            dbgDebug(D_CONFIG) << "Configuration reload status: " << status_map.at(load_config_staus);
        }
    }

private:
    BOTH_PARAM(int, id);
    S2C_PARAM(bool, error);
    S2C_PARAM(bool, finished);
    S2C_OPTIONAL_PARAM(string, error_message);
    C2S_PARAM(string, policy_version);
};

class ConfigComponent::Impl : public Singleton::Provide<I_Config>::From<ConfigComponent>
{
    using PerContextValue = vector<pair<shared_ptr<EnvironmentEvaluator<bool>>, TypeWrapper>>;

public:
    void preload();
    void init();

    const TypeWrapper & getConfiguration(const vector<string> &paths) const override;
    PerContextValue getAllConfiguration(const std::vector<std::string> &paths) const;
    const TypeWrapper & getResource(const vector<string> &paths) const override;
    const TypeWrapper & getSetting(const vector<string> &paths) const override;
    string getProfileAgentSetting(const string &setting_name) const override;
    vector<string> getProfileAgentSettings(const string &regex) const override;

    const string & getConfigurationFlag(const string &flag_name) const override;
    const string & getConfigurationFlagWithDefault(const string &default_val, const string &flag_name) const override;
    const string & getFilesystemPathConfig() const override;
    const string & getLogFilesPathConfig() const override;

    string getPolicyConfigPath(
        const string &name,
        ConfigFileType type,
        const string &tenant = "",
        const string &profile = "") const override;

    bool setConfiguration(TypeWrapper &&value, const std::vector<std::string> &paths) override;
    bool setResource(TypeWrapper &&value, const std::vector<std::string> &paths) override;
    bool setSetting(TypeWrapper &&value, const std::vector<std::string> &paths) override;

    void registerExpectedConfigFile(const string &file_name, ConfigFileType type) override;
    void registerExpectedConfiguration(unique_ptr<GenericConfig<true>> &&config) override;
    void registerExpectedResource(unique_ptr<GenericConfig<false>> &&config) override;
    void registerExpectedSetting(unique_ptr<GenericConfig<false>> &&config) override;


    bool loadConfiguration(istream &json_contents, const string &path) override;
    bool loadConfiguration(const vector<string> &configuration_flags) override;
    AsyncLoadConfigStatus reloadConfiguration(const string &version, bool is_async, uint id) override;
    bool saveConfiguration(ostream &) const override { return false; }

    void registerConfigPrepareCb(ConfigCb) override;
    void registerConfigLoadCb(ConfigCb) override;
    void registerConfigAbortCb(ConfigCb) override;
    void clearOldTenants() override;

private:
    bool areTenantAndProfileActive(const TenantProfilePair &tenant_profile) const;
    void periodicRegistrationRefresh();

    bool loadConfiguration(vector<shared_ptr<JSONInputArchive>> &file_archives, bool is_async);
    bool commitSuccess();
    bool commitFailure(const string &error);
    bool reloadConfigurationImpl(const string &version, bool is_async);
    void reloadConfigurationContinuesWrapper(const string &version, uint id);
    vector<string> fillMultiTenantConfigFiles(const map<string, set<string>> &tenants);
    vector<string> fillMultiTenantExpectedConfigFiles(const map<string, set<string>> &tenants);
    map<string, string> getProfileAgentSetting() const;

    string
    getActiveTenant() const
    {
        auto active_id = Singleton::Consume<I_Environment>::by<ConfigComponent>()->get<string>("ActiveTenantId");

        return active_id.ok() ? *active_id : default_tenant_id;
    }

    string
    getActiveProfile() const
    {
        auto active_id = Singleton::Consume<I_Environment>::by<ConfigComponent>()->get<string>("ActiveProfileId");

        return active_id.ok() ? *active_id : default_profile_id;
    }

    bool
    sendOrchestatorConfMsg(int env_listening_port)
    {
        registerExpectedConfigUpdates config_updates;

        config_updates.service_name = executable_name;
        config_updates.service_listening_port = env_listening_port;


        if (Singleton::exists<I_InstanceAwareness>()) {
            auto instance_awareness = Singleton::Consume<I_InstanceAwareness>::by<ConfigComponent>();
            if (instance_awareness->getUniqueID().ok()) {
                config_updates.service_id = instance_awareness->getUniqueID().unpack();
            }
        }

        vector<string> files;
        files.reserve(expected_configuration_files.size());
        for (const auto &conf : expected_configuration_files) {
            files.push_back(conf.first);
        }
        config_updates.expected_configurations = move(files);

        I_Messaging *messaging = Singleton::Consume<I_Messaging>::by<ConfigComponent>();
        ::Flags<MessageConnConfig> conn_flags;
        conn_flags.setFlag(MessageConnConfig::ONE_TIME_CONN);
        bool is_success = messaging->sendObject(
            config_updates,
            I_Messaging::Method::POST,
            "127.0.0.1",
            7777, // primary Orchestrator's port
            conn_flags,
            "/set-nano-service-config"
        );
        if (!is_success) {
            is_success = messaging->sendObject(
                config_updates,
                I_Messaging::Method::POST,
                "127.0.0.1",
                7778, // secondary Orchestrator's port
                conn_flags,
                "/set-nano-service-config"
            );
        }
        return is_success && config_updates.status.get();
    }

    void
    reloadFileSystemPaths()
    {
        auto &alternative_conf_path = getConfigurationFlag("configDirectoryPath");
        if (alternative_conf_path != "") {
            config_directory_path = alternative_conf_path;
        } else {
            filesystem_prefix = getConfigurationFlag("filesystem_path") != "" ?
                getConfigurationFlag("filesystem_path") :
                "/etc/cp";
            log_files_prefix = getConfigurationFlag("log_files_path") != "" ?
                getConfigurationFlag("log_files_path") :
                "/var/log";
            config_directory_path = filesystem_prefix + default_config_directory_path;
        }
        dbgTrace(D_CONFIG) << "File system path reloaded: " << config_directory_path;
    }

    void
    sendOrchestatorReloadStatusMsg(const LoadNewConfigurationStatus &status)
    {
        I_Messaging *messaging = Singleton::Consume<I_Messaging>::by<ConfigComponent>();
        ::Flags<MessageConnConfig> conn_flags;
        conn_flags.setFlag(MessageConnConfig::ONE_TIME_CONN);
        bool is_success = messaging->sendNoReplyObject(
            status,
            I_Messaging::Method::POST,
            "127.0.0.1",
            7777, // primary Orchestrator's port
            conn_flags,
            "/set-reconf-status"
        );
        if (!is_success) {
            messaging->sendNoReplyObject(
                status,
                I_Messaging::Method::POST,
                "127.0.0.1",
                7778, // secondary Orchestrator's port
                conn_flags,
                "/set-reconf-status"
            );
        }
    }

    unordered_map<TenantProfilePair, map<vector<string>, PerContextValue>> configuration_nodes;
    unordered_map<TenantProfilePair, map<vector<string>, TypeWrapper>> settings_nodes;
    unordered_map<string, string> config_flags;

    map<vector<string>, TypeWrapper> new_resource_nodes;
    unordered_map<TenantProfilePair, map<vector<string>, PerContextValue>> new_configuration_nodes;
    unordered_map<TenantProfilePair, map<vector<string>, TypeWrapper>> new_settings_nodes;
    unordered_map<string, string> new_config_flags;

    set<unique_ptr<GenericConfig<true>>> expected_configs;
    set<unique_ptr<GenericConfig<false>>> expected_resources;
    set<unique_ptr<GenericConfig<false>>> expected_settings;
    map<string, set<ConfigFileType>> expected_configuration_files;
    set<string> config_file_paths;

    I_TenantManager *tenant_manager = nullptr;

    vector<ConfigCb> configuration_prepare_cbs;
    vector<ConfigCb> configuration_commit_cbs;
    vector<ConfigCb> configuration_abort_cbs;

    bool is_continuous_report = false;
    const string default_tenant_id = "";
    const string default_profile_id = "";
    string executable_name = "";
    string filesystem_prefix = "/etc/cp";
    string log_files_prefix = "/var/log";
    string default_config_directory_path = "/conf/";
    string config_directory_path = "";

    TypeWrapper empty;
};

void
ConfigComponent::Impl::preload()
{
    I_Environment *environment = Singleton::Consume<I_Environment>::by<ConfigComponent>();
    auto executable = environment->get<string>("Executable Name");
    if (!executable.ok() || *executable == "") {
        dbgWarning(D_CONFIG)
            << "Could not load nano service's settings since \"Executable Name\" in not found in the environment";
        return;
    }

    executable_name = *executable;
    auto file_path_end = executable_name.find_last_of("/");
    if (file_path_end != string::npos) {
        executable_name = executable_name.substr(file_path_end + 1);
    }
    auto file_sufix_start = executable_name.find_first_of(".");
    if (file_sufix_start != string::npos) {
        executable_name = executable_name.substr(0, file_sufix_start);
    }

    config_file_paths.insert(executable_name + "-conf.json");
    config_file_paths.insert(executable_name + "-debug-conf.json");
    config_file_paths.insert("settings.json");
}

void
ConfigComponent::Impl::init()
{
    reloadFileSystemPaths();
    tenant_manager = Singleton::Consume<I_TenantManager>::by<ConfigComponent>();

    if (!Singleton::exists<I_MainLoop>()) return;
    auto mainloop = Singleton::Consume<I_MainLoop>::by<ConfigComponent>();

    if (executable_name != "cp-nano-orchestration") {
        mainloop->addOneTimeRoutine(
            I_MainLoop::RoutineType::System,
            [this] () { periodicRegistrationRefresh(); },
            "Configuration update registration",
            false
        );
    }
}

static
bool
checkContext(const shared_ptr<EnvironmentEvaluator<bool>> &ctx)
{
    if (ctx == nullptr) return true;
    auto res = ctx->evalVariable();
    return res.ok() && *res;
}

const TypeWrapper &
ConfigComponent::Impl::getConfiguration(const vector<string> &paths) const
{
    auto curr_configs = configuration_nodes.find(TenantProfilePair(getActiveTenant(), getActiveProfile()));

    if (curr_configs != configuration_nodes.end()) {
        auto requested_config = curr_configs->second.find(paths);
        if (requested_config != curr_configs->second.end()) {
            for (auto &value : requested_config->second) {
                if (checkContext(value.first)) return value.second;
            }
        }
    }

    auto global_config = configuration_nodes.find(TenantProfilePair(default_tenant_id, default_profile_id));
    if (global_config != configuration_nodes.end()) {
        auto requested_config = global_config->second.find(paths);
        if (requested_config != global_config->second.end()) {
            for (auto &value : requested_config->second) {
                if (checkContext(value.first)) return value.second;
            }
        }
    }

    return empty;
}

vector<pair<shared_ptr<EnvironmentEvaluator<bool>>, TypeWrapper>>
ConfigComponent::Impl::getAllConfiguration(const vector<string> &paths) const
{
    auto curr_configs = configuration_nodes.find(TenantProfilePair(getActiveTenant(), getActiveProfile()));

    if (curr_configs != configuration_nodes.end()) {
        auto requested_config = curr_configs->second.find(paths);
        if (requested_config != curr_configs->second.end()) return requested_config->second;
    }

    auto global_config = configuration_nodes.find(TenantProfilePair(default_tenant_id, default_profile_id));
    if (global_config != configuration_nodes.end()) {
        auto requested_config = global_config->second.find(paths);
        if (requested_config != global_config->second.end()) return requested_config->second;
    }

    return vector<pair<shared_ptr<EnvironmentEvaluator<bool>>, TypeWrapper>>();
}

const TypeWrapper &
ConfigComponent::Impl::getResource(const vector<string> &paths) const
{
    auto requested_resource = new_resource_nodes.find(paths);
    if (requested_resource != new_resource_nodes.end()) return requested_resource->second;

    return empty;
}

const TypeWrapper &
ConfigComponent::Impl::getSetting(const vector<string> &paths) const
{
    auto curr_configs = settings_nodes.find(TenantProfilePair(getActiveTenant(), getActiveProfile()));
    if (curr_configs != settings_nodes.end()) {
        auto requested_config = curr_configs->second.find(paths);
        if (requested_config != curr_configs->second.end()) return requested_config->second;
    }

    auto global_config = settings_nodes.find(TenantProfilePair(default_tenant_id, default_profile_id));
    if (global_config != settings_nodes.end()) {
        auto requested_config = global_config->second.find(paths);
        if (requested_config != global_config->second.end()) return requested_config->second;
    }

    return empty;
}

string
ConfigComponent::Impl::getProfileAgentSetting(const string &setting_name) const
{
    auto profile_settings = getProfileAgentSetting();
    auto setting_raw_val = profile_settings.find(setting_name);
    if (setting_raw_val != profile_settings.end()) return setting_raw_val->second;

    return not_found;
}

const string &
ConfigComponent::Impl::getConfigurationFlag(const string &flag_name) const
{
    auto flag = new_config_flags.find(flag_name);
    if (flag != new_config_flags.end()) return flag->second;

    flag = config_flags.find(flag_name);
    if (flag != config_flags.end()) return flag->second;

    return not_found;
}

const string &
ConfigComponent::Impl::getConfigurationFlagWithDefault(const string &default_val, const string &flag_name) const
{
    const string &val = getConfigurationFlag(flag_name);
    if (!val.empty()) return val;

    return default_val;
}

const string &
ConfigComponent::Impl::getFilesystemPathConfig() const
{
    dbgTrace(D_CONFIG) << "config get filesystem: " << filesystem_prefix;
    return filesystem_prefix;
}

const string &
ConfigComponent::Impl::getLogFilesPathConfig() const
{
    dbgTrace(D_CONFIG) << "config get log_files_prefix: " << log_files_prefix;
    return log_files_prefix;
}

string
ConfigComponent::Impl::getPolicyConfigPath(
    const string &config_name,
    ConfigFileType type,
    const string &tenant,
    const string &profile) const
{
    static const string policy_suffix = ".policy";
    static const string data_suffix = ".data";
    static const string tenant_prefix = "tenant_";
    static const string profile_prefix = "_profile_";

    string base_path =
        getConfigurationWithDefault(config_directory_path, "Config Component", "configuration path") +
        (tenant.empty() ? "" : tenant_prefix + tenant + profile_prefix + profile +"/");

    switch (type) {
        case ConfigFileType::Data: return base_path + "data/" + config_name + data_suffix;
        case ConfigFileType::RawData: return base_path + "data/" + config_name + data_suffix;
        case ConfigFileType::Policy: return base_path + config_name + "/" + config_name + policy_suffix;
        case ConfigFileType::COUNT: break;
    }

    dbgError(D_CONFIG) << "Received illegal configuration file type " << static_cast<uint>(type);
    return "";
}

bool
ConfigComponent::Impl::setConfiguration(TypeWrapper &&value, const vector<string> &paths)
{
    for (auto &tenant : configuration_nodes) {
        tenant.second.erase(paths);
    }

    PerContextValue value_vec;
    TenantProfilePair default_tenant_profile(default_tenant_id, default_profile_id);
    value_vec.emplace_back(nullptr, move(value));
    configuration_nodes[default_tenant_profile][paths] = move(value_vec);
    return true;
}

bool
ConfigComponent::Impl::setResource(TypeWrapper &&value, const vector<string> &paths)
{
    new_resource_nodes[paths] = move(value);
    return true;
}

bool
ConfigComponent::Impl::setSetting(TypeWrapper &&value, const vector<string> &paths)
{
    TenantProfilePair default_tenant_profile(default_tenant_id, default_profile_id);
    settings_nodes[default_tenant_profile][paths] = move(value);
    return true;
}

vector<string>
ConfigComponent::Impl::getProfileAgentSettings(const string &regex) const
{
    vector<string> setting_raw_values;
    boost::regex reg(regex);
    auto profile_settings = getProfileAgentSetting();
    for (auto &setting : profile_settings) {
        if (NGEN::Regex::regexMatch(__FILE__, __LINE__, setting.first, reg)) {
            setting_raw_values.push_back(setting.second);
        }
    }

    return setting_raw_values;
}

void
ConfigComponent::Impl::registerExpectedConfigFile(const string &config_name, ConfigFileType type)
{
    expected_configuration_files[config_name].insert(type);
    if (type != ConfigFileType::RawData) config_file_paths.insert(getPolicyConfigPath(config_name, type));
}

void
ConfigComponent::Impl::registerExpectedConfiguration(unique_ptr<GenericConfig<true>> &&expected_config)
{
    expected_configs.insert(move(expected_config));
}

void
ConfigComponent::Impl::registerExpectedResource(unique_ptr<GenericConfig<false>> &&expected_config)
{
    expected_resources.insert(move(expected_config));
}

void
ConfigComponent::Impl::registerExpectedSetting(unique_ptr<GenericConfig<false>> &&expected_config)
{
    expected_settings.insert(move(expected_config));
}

bool
ConfigComponent::Impl::loadConfiguration(istream &stream, const string &path)
{
    vector<shared_ptr<JSONInputArchive>> archive;
    try {
        archive.emplace_back(make_shared<JSONInputArchive>(stream));
    } catch (const cereal::Exception &e) {
        dbgError(D_CONFIG) << "Failed to serialize stream. Path: " << path << ", Error: " << e.what();
        return false;
    }
    return loadConfiguration(archive, false);
}

bool
ConfigComponent::Impl::loadConfiguration(const vector<string> &flags)
{
    for (auto &flag : flags) {
        if (flag.substr(0, 2) == "--") {
            auto equal_place = flag.find_first_of('=');
            if (equal_place == string::npos) continue;
            dbgDebug(D_CONFIG)
                << "Adding "
                << flag.substr(2, equal_place - 2)
                << "='"
                << flag.substr(equal_place +1)
                << "'";
            new_config_flags.emplace(flag.substr(2, equal_place - 2), flag.substr(equal_place +1));
        } else {
            dbgInfo(D_CONFIG) << "ignoring an illegal configuration argument. Argument: " << flag;
        }
    }
    reloadFileSystemPaths();

    auto &alternative_conf_path = getConfigurationFlag("configDirectoryPath");
    if (alternative_conf_path != "") {
        config_directory_path = alternative_conf_path;
        dbgTrace(D_CONFIG) << "File system path reloaded from configuration flag: " << config_directory_path;
    }

    auto res = reloadConfiguration("", false, 0) == I_Config::AsyncLoadConfigStatus::Success;

    if (res && !new_config_flags.empty()) {
        config_flags = move(new_config_flags);
    } else {
        new_config_flags.clear();
    }

    return res;
}

I_Config::AsyncLoadConfigStatus
ConfigComponent::Impl::reloadConfiguration(const string &version, bool is_async, uint id)
{
    if (is_continuous_report) {
        dbgWarning(D_CONFIG) << "Cannot start another continuous reload while another is running.";
        return AsyncLoadConfigStatus::Error;
    }

    if (!is_async) {
        bool res = reloadConfigurationImpl(version, false);
        return res ? I_Config::AsyncLoadConfigStatus::Success : I_Config::AsyncLoadConfigStatus::Error;
    }

    is_continuous_report = true;

    auto mainloop = Singleton::Consume<I_MainLoop>::by<ConfigComponent>();

    mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::System,
        [=] () { reloadConfigurationContinuesWrapper(version, id); },
        "A-Synchronize reload configuraion"
    );

    return AsyncLoadConfigStatus::InProgress;
}

void
ConfigComponent::Impl::registerConfigPrepareCb(ConfigCb cb)
{
    configuration_prepare_cbs.push_back(cb);
}

void
ConfigComponent::Impl::registerConfigLoadCb(ConfigCb cb)
{
    configuration_commit_cbs.push_back(cb);
}

void
ConfigComponent::Impl::registerConfigAbortCb(ConfigCb cb)
{
    configuration_abort_cbs.push_back(cb);
}

void
ConfigComponent::Impl::clearOldTenants()
{
    for (
        auto iter = configuration_nodes.begin();
        iter != configuration_nodes.end();
        !areTenantAndProfileActive(iter->first) ? iter = configuration_nodes.erase(iter) : ++iter
    );

    for (
        auto iter = settings_nodes.begin();
        iter != settings_nodes.end();
        !areTenantAndProfileActive(iter->first) ? iter = settings_nodes.erase(iter) : ++iter
    );
}

bool
ConfigComponent::Impl::areTenantAndProfileActive(const TenantProfilePair &tenant_profile) const
{
    return (tenant_profile.getTenantId() == default_tenant_id && tenant_profile.getProfileId() == default_profile_id)
        || tenant_manager->areTenantAndProfileActive(tenant_profile.getTenantId(), tenant_profile.getProfileId());
}

void
ConfigComponent::Impl::periodicRegistrationRefresh()
{
    I_Environment *environment = Singleton::Consume<I_Environment>::by<ConfigComponent>();
    I_MainLoop *mainloop = Singleton::Consume<I_MainLoop>::by<ConfigComponent>();

    while (true) {
        auto env_listening_port = environment->get<int>("Listening Port");

        if (!env_listening_port.ok()) {
            dbgTrace(D_CONFIG)
                << "Internal rest server listening port is not yet set."
                << " Setting retry attempt to 500 milliseconds from now";
            mainloop->yield(chrono::milliseconds(500));
        } else if (!sendOrchestatorConfMsg(env_listening_port.unpack())) {
            mainloop->yield(chrono::milliseconds(500));
        } else {
            uint next_iteration_in_sec = getConfigurationWithDefault<uint>(
                600,
                "Config Component",
                "Refresh config update registration time interval"
            );
            mainloop->yield(chrono::seconds(next_iteration_in_sec));
        }
    }
}

bool
ConfigComponent::Impl::loadConfiguration(vector<shared_ptr<JSONInputArchive>> &file_archives, bool is_async)
{
    auto mainloop = is_async ? Singleton::Consume<I_MainLoop>::by<ConfigComponent>() : nullptr;

    for (auto &cb : configuration_prepare_cbs) {
        cb();
    }

    try {
        for (auto &archive : file_archives) {
            for (auto &resource : expected_resources) {
                auto loaded = resource->loadConfiguration(*archive);
                if (loaded.ok()) new_resource_nodes[resource->getPath()] = loaded;
                if (is_async) mainloop->yield();
            }
        }

        for (auto &archive : file_archives) {
            string curr_tenant = default_tenant_id;
            string curr_profile = default_profile_id;
            try {
                (*archive)(cereal::make_nvp("tenantID", curr_tenant));
                dbgTrace(D_CONFIG) << "Found a tenant ID in the file: " << curr_tenant;
            } catch (cereal::Exception &e) {}
            try {
                (*archive)(cereal::make_nvp("profileID", curr_profile));
                dbgTrace(D_CONFIG) << "Found a profile ID in the file " << curr_profile;
            } catch (cereal::Exception &e) {}

            dbgTrace(D_CONFIG)
                << "Loading configuration for tenant: "
                << curr_tenant
                << " and profile: "
                << curr_profile
                << ", for the archive: "
                << (*archive).getNodeName();

            TenantProfilePair tenant_profile(curr_tenant, curr_profile);
            for (auto &config : expected_configs) {
                auto loaded = config->loadConfiguration(*archive);
                if (!loaded.empty()) new_configuration_nodes[tenant_profile][config->getPath()] = move(loaded);
                if (is_async) mainloop->yield();
            }
            for (auto &setting : expected_settings) {
                auto loaded = setting->loadConfiguration(*archive);
                if (loaded.ok()) new_settings_nodes[tenant_profile][setting->getPath()] = move(loaded);
                if (is_async) mainloop->yield();
            }
        }
    } catch (const cereal::Exception &e) {
        return commitFailure(e.what());
    } catch (const Config::ConfigException &e) {
        return commitFailure(e.getError());
    } catch (const EnvironmentHelper::EvaluatorParseError &e) {
        return commitFailure(e.getError());
    }

    return commitSuccess();
}

bool
ConfigComponent::Impl::commitSuccess()
{
    new_resource_nodes.clear();
    configuration_nodes = move(new_configuration_nodes);
    settings_nodes = move(new_settings_nodes);

    reloadFileSystemPaths();

    for (auto &cb : configuration_commit_cbs) {
        cb();
    }
    return true;
}

bool
ConfigComponent::Impl::commitFailure(const string &error)
{
    dbgError(D_CONFIG) << error;
    new_resource_nodes.clear();
    new_configuration_nodes.clear();
    new_settings_nodes.clear();
    for (auto &cb : configuration_abort_cbs) {
        cb();
    }
    return false;
}

vector<string>
ConfigComponent::Impl::fillMultiTenantConfigFiles(const map<string, set<string>> &active_tenants)
{
    vector<string> files;
    for (const auto &tenant_profiles : active_tenants) {
        const string &tenant = tenant_profiles.first;
        const set<string> &profile_ids = tenant_profiles.second;
        for (const auto &profile_id : profile_ids) {
            string settings_path =
                config_directory_path + "tenant_" + tenant + "_profile_" + profile_id + "_settings.json";
            files.push_back(settings_path);
        }
    }
    return files;
}

vector<string>
ConfigComponent::Impl::fillMultiTenantExpectedConfigFiles(const map<string, set<string>> &active_tenants)
{
    vector<string> files;
    for (const auto &config_file : expected_configuration_files) {
        for (const auto &type : config_file.second) {
            if (type == ConfigFileType::RawData) continue;
            auto global_path = getPolicyConfigPath(config_file.first, type);
            auto it = find(files.begin(), files.end(), global_path);
            if (it == files.end()) files.push_back(global_path);
            for (const auto &tenant_profiles : active_tenants) {
                const string &tenant = tenant_profiles.first;
                const set<string> &profile_ids = tenant_profiles.second;
                for (const auto &profile_id : profile_ids) {
                    auto tenant_path = getPolicyConfigPath(config_file.first, type, tenant, profile_id);
                    files.push_back(tenant_path);
                }
            }
        }
    }
    return files;
}

bool
ConfigComponent::Impl::reloadConfigurationImpl(const string &version, bool is_async)
{
    dbgFlow(D_CONFIG) << "Reloading configuration";
    auto env = Singleton::Consume<I_Environment>::by<ConfigComponent>();
    env->registerValue<string>("New Policy Version", version);
    auto cleanup = make_scope_exit([env] () { env->unregisterKey<string>("New Policy Version"); } );

    map<string, shared_ptr<ifstream>> files;
    for (const auto &path : config_file_paths) {
        dbgTrace(D_CONFIG) << "Inserting " << path << " to the list of files to be handled";
        auto fullpath = config_directory_path + path;
        files.emplace(fullpath, make_shared<ifstream>(fullpath));
    }

    map<string, set<string>> active_tenants =
        tenant_manager ? tenant_manager->fetchAndUpdateActiveTenantsAndProfiles(true) : map<string, set<string>>();

    dbgTrace(D_CONFIG) << "Number of active tenants found while reloading configuration: " << active_tenants.size();
    clearOldTenants();

    const vector<string> &config_files = fillMultiTenantConfigFiles(active_tenants);
    const vector<string> &expected_config_files = fillMultiTenantExpectedConfigFiles(active_tenants);
    for (const string &file : config_files) {
        dbgTrace(D_CONFIG) << "Inserting " << file << " to the list of files to be handled";
        files.emplace(file, make_shared<ifstream>(file));
    }
    for (const string &file : expected_config_files) {
        dbgTrace(D_CONFIG) << "Inserting " << file << " to the list of files to be handled";
        files.emplace(file, make_shared<ifstream>(file));
    }

    vector<shared_ptr<JSONInputArchive>> archives;
    for (const auto &file : files) {
        if (file.second->is_open()) {
            dbgTrace(D_CONFIG) << "Succesfully opened configuration file. File: " << file.first;
            try {
                archives.push_back(make_shared<JSONInputArchive>(*file.second));
            } catch (const cereal::Exception &e) {
                dbgError(D_CONFIG) << "Failed in file serialization. Path: " << file.first << ", Error: " << e.what();
                return false;
            }
        } else {
            dbgTrace(D_CONFIG) << "Could not open configuration file. Path: " << file.first;
        }
    }

    bool res = loadConfiguration(archives, is_async);
    if (res) env->registerValue<string>("Current Policy Version", version);
    return res;
}

map<string, string>
ConfigComponent::Impl::getProfileAgentSetting() const
{
    auto general_sets = getSettingWithDefault(AgentProfileSettings::default_profile_settings, "generalAgentSettings");

    auto settings = general_sets.getSettings();

    auto profile_sets = getSettingWithDefault(AgentProfileSettings::default_profile_settings, "agentSettings");
    auto profile_settings = profile_sets.getSettings();
    for (const auto &profile_setting : profile_settings) {
        settings.insert(profile_setting);
    }

    return settings;
}

void
ConfigComponent::Impl::reloadConfigurationContinuesWrapper(const string &version, uint id)
{
    dbgFlow(D_CONFIG) << "Running reloadConfigurationContinuesWrapper. Version: " << version << ", Id: " << id;
    auto mainloop = Singleton::Consume<I_MainLoop>::by<ConfigComponent>();
    auto maybe_service_name = Singleton::Consume<I_Environment>::by<ConfigComponent>()->get<string>("Service Name");
    string service_name = maybe_service_name.ok() ? maybe_service_name.unpack() : "serviceNameNotRegistered";
    LoadNewConfigurationStatus in_progress(id, service_name, false, false);
    auto routine_id = mainloop->addRecurringRoutine(
        I_MainLoop::RoutineType::Timer,
        std::chrono::seconds(30),
        [=] () { sendOrchestatorReloadStatusMsg(in_progress); },
        "A-Synchronize reload configuraion monitoring"
    );

    bool res = reloadConfigurationImpl(version, true);

    mainloop->stop(routine_id);
    LoadNewConfigurationStatus finished(id, service_name, !res, true);
    if (!res) finished.setError("Failed to reload configuration");
    sendOrchestatorReloadStatusMsg(finished);

    is_continuous_report = false;
}

ConfigComponent::ConfigComponent() : Component("ConfigComponent"), pimpl(make_unique<Impl>()) {}
ConfigComponent::~ConfigComponent() {}

void
ConfigComponent::preload()
{
    registerExpectedConfiguration<string>("Config Component", "configuration path");
    registerExpectedConfiguration<uint>("Config Component", "Refresh config update registration time interval");
    registerExpectedResource<bool>("Config Component", "Config Load Test");
    registerExpectedSetting<AgentProfileSettings>("agentSettings");
    pimpl->preload();
}

void
ConfigComponent::init()
{
    if (Singleton::exists<I_RestApi>()) {
        auto rest = Singleton::Consume<I_RestApi>::by<ConfigComponent>();
        rest->addRestCall<LoadNewConfiguration>(RestAction::SET, "new-configuration");
    }
    pimpl->init();
}
