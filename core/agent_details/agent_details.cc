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

#include "agent_details.h"

#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <boost/regex.hpp>
#include <boost/algorithm/string.hpp>

#include "config.h"
#include "debug.h"

using namespace std;

USE_DEBUG_FLAG(D_ORCHESTRATOR);

const map<string, I_AgentDetails::MachineType> AgentDetails::machineTypes({
    { "Amazon EC2",            I_AgentDetails::MachineType::AWS },
    { "Xen",                   I_AgentDetails::MachineType::AWS },
    { "Microsoft Corporation", I_AgentDetails::MachineType::AZURE },
    { "VMware, Inc.",          I_AgentDetails::MachineType::ON_PREM }
});

void
AgentDetails::init()
{
    registerMachineType();
    loadAccessToken();
    Singleton::Consume<I_MainLoop>::by<AgentDetails>()->addRecurringRoutine(
        I_MainLoop::RoutineType::System,
        chrono::seconds(60),
        [this] () { loadAccessToken(); },
        "Load access token"
    );
    proxies = {
        {ProxyProtocol::HTTP, ProxyData()},
        {ProxyProtocol::HTTPS, ProxyData()}
    };

    auto proxy_config = getProfileAgentSetting<string>("agent.config.message.proxy");
    if (proxy_config.ok()) {
        setProxy(*proxy_config);
        writeAgentDetails();
    }

    registerConfigLoadCb(
        [&]()
        {
            auto proxy_config = getProfileAgentSetting<string>("agent.config.message.proxy");
            if (proxy_config.ok()) {
                is_proxy_configured_via_settings = true;
                setProxy(*proxy_config);
                writeAgentDetails();
            } else if (is_proxy_configured_via_settings) {
                is_proxy_configured_via_settings = false;
                setProxy(string(""));
                writeAgentDetails();
            }
        }
    );

    auto load_env_proxy = loadProxy();
    if (!load_env_proxy.ok()) {
        dbgDebug(D_ORCHESTRATOR)
            << "Could not initialize load proxy from environment, Error: "
            << load_env_proxy.getErr();
    }
}

bool
AgentDetails::readAgentDetails()
{
    auto agent_details_path = getConfigurationWithDefault<string>(
        getFilesystemPathConfig() + "/conf/agent_details.json",
        "Agent details",
        "File path"
    );
    ifstream file(agent_details_path);
    if (!file.is_open()) {
        dbgWarning(D_ORCHESTRATOR) << "Agent details file does not exist. File: " << agent_details_path;
        return false;
    }

    stringstream file_stream;
    try {
        file_stream << file.rdbuf();
        cereal::JSONInputArchive archive_in(file_stream);
        serialize(archive_in);
    } catch (exception &e) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to parse agent details."
            << " File: " << agent_details_path
            << ", Error: " << e.what();
        return false;
    }
    file.close();
    return true;
}

bool
AgentDetails::writeAgentDetails()
{
    auto agent_details_path = getConfigurationWithDefault<string>(
        getFilesystemPathConfig() + "/conf/agent_details.json",
        "Agent details",
        "File path"
    );

    try {
        ofstream ostream(agent_details_path);
        cereal::JSONOutputArchive archive_out(ostream);
        serialize(archive_out);
    } catch (exception &e) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to write the agent details."
            << " File: " << agent_details_path
            << ", Error: " << e.what();
        return false;
    }
    return true;
}

void
AgentDetails::serialize(cereal::JSONOutputArchive &ar)
{
    ar(cereal::make_nvp("Fog domain", fog_domain));
    ar(cereal::make_nvp("Agent ID",   agent_id));
    ar(cereal::make_nvp("Fog port",   fog_port));
    ar(cereal::make_nvp("Tenant ID",  tenant_id));
    ar(cereal::make_nvp("Profile ID", profile_id));
    ar(cereal::make_nvp("Encrypted connection", encrypted_connection));
    ar(cereal::make_nvp("OpenSSL certificates directory",  openssl_dir));

    try {
        ar(cereal::make_nvp("Proxy", proxy));
    } catch (...) {
        ar.setNextName(nullptr);
    }

    try {
        ar(cereal::make_nvp("Cluster ID", cluster_id));
    } catch (...) {
        ar.setNextName(nullptr);
    }

    try {
        static const EnumArray<OrchestrationMode, std::string> orchestraiton_mode_str {
            "online_mode",
            "offline_mode",
            "hybrid_mode"
        };
        std::string orchestraiton_mode_string = orchestraiton_mode_str[orchestration_mode];
        ar(cereal::make_nvp("Orchestration mode", orchestraiton_mode_string));

        bool is_offline_mode = (orchestration_mode == OrchestrationMode::OFFLINE);
        ar(cereal::make_nvp("Is Offline Mode", is_offline_mode));
    } catch (...) {
        ar.setNextName(nullptr);
    }
}

void
AgentDetails::serialize(cereal::JSONInputArchive &ar)
{
    ar(cereal::make_nvp("Fog domain", fog_domain));
    ar(cereal::make_nvp("Agent ID",   agent_id));
    ar(cereal::make_nvp("Fog port",   fog_port));
    ar(cereal::make_nvp("Tenant ID",  tenant_id));
    ar(cereal::make_nvp("Profile ID", profile_id));
    ar(cereal::make_nvp("Encrypted connection", encrypted_connection));
    ar(cereal::make_nvp("OpenSSL certificates directory",  openssl_dir));

    try {
        ar(cereal::make_nvp("Proxy", proxy));
    } catch (...) {
        ar.setNextName(nullptr);
    }

    try {
        ar(cereal::make_nvp("Cluster ID", cluster_id));
        if (!cluster_id.empty()) {
            Singleton::Consume<I_Environment>::by<AgentDetails>()->getConfigurationContext().registerValue<string>(
                "k8sClusterId",
                cluster_id,
                EnvKeyAttr::LogSection::SOURCE
            );
        }
    } catch (...) {
        ar.setNextName(nullptr);
    }

    try {
        static const std::map<std::string, OrchestrationMode> orchestrationModeMap {
            { "online_mode",  OrchestrationMode::ONLINE },
            { "offline_mode", OrchestrationMode::OFFLINE },
            { "hybrid_mode",  OrchestrationMode::HYBRID }
        };
        std::string orchestraiton_mode_string;
        ar(cereal::make_nvp("Orchestration mode", orchestraiton_mode_string));
        auto iter = orchestrationModeMap.find(orchestraiton_mode_string);
        if (iter != orchestrationModeMap.end()) {
            orchestration_mode = iter->second;
        }
    } catch (...) {
        try {
            bool is_offline_mode = false;
            ar(cereal::make_nvp("Is Offline Mode", is_offline_mode));
            if (is_offline_mode) {
                orchestration_mode = OrchestrationMode::OFFLINE;
            } else {
                orchestration_mode = OrchestrationMode::ONLINE;
            }
        } catch (...) {
            ar.setNextName(nullptr);
        }
    }
}

string
AgentDetails::getAgentId() const
{
    static string default_agent_id = "Unknown";
    if (agent_id.empty()) return default_agent_id;
    return agent_id;
}

Maybe<string>
AgentDetails::getProxy() const
{
    if (proxy == "") return genError("Proxy not set");
    return proxy;
}

Maybe<uint16_t>
AgentDetails::getFogPort() const
{
    if (fog_port == 0) return genError("Fog port is unset");
    return fog_port;
}

Maybe<string>
AgentDetails::getFogDomain() const
{
    if (fog_domain.empty()) return genError("Fog domain is unset");
    return fog_domain;
}

void
AgentDetails::setClusterId(const std::string &_cluster_id)
{
    dbgTrace(D_ORCHESTRATOR) << "Setting Cluster Id in the agent details. Cluster ID: " << _cluster_id;
    cluster_id = _cluster_id;
    writeAgentDetails();
}

void
AgentDetails::preload()
{
    registerExpectedConfiguration<string>("orchestration", "Agent details path");
    registerConfigLoadCb([this] () { readAgentDetails(); });
}

string
AgentDetails::getTenantId() const
{
    return tenant_id;
}

string
AgentDetails::getProfileId() const
{
    return profile_id;
}

string
AgentDetails::getClusterId() const
{
    return cluster_id;
}

Maybe<string>
AgentDetails::getOpenSSLDir() const
{
    if (openssl_dir.empty()) return genError("OpenSSL certificates directory was not set");
    return openssl_dir;
}

OrchestrationMode
AgentDetails::getOrchestrationMode() const
{
    return orchestration_mode;
}

string
AgentDetails::getAccessToken() const
{
    return access_token;
}

void
AgentDetails::loadAccessToken()
{
    readAgentDetails();
    auto data_path = getConfigurationWithDefault<string>(
        getFilesystemPathConfig() + "/data/",
        "encryptor",
        "Data files directory"
    );
    ifstream token_file(data_path + session_token_file_name);
    if (!token_file.is_open()) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to open session token file: " << data_path + session_token_file_name;
        return;
    }
    stringstream token_steam;
    token_steam << token_file.rdbuf();

    auto new_token = token_steam.str();
    if (access_token != new_token) {
        access_token = new_token;
        dbgTrace(D_ORCHESTRATOR) << "Loaded the new token";
    }
}

Maybe<I_AgentDetails::MachineType>
AgentDetails::getMachineTypeFromDmiTable()
{
    static const string decode_machine_type_cmd = "dmidecode -s system-manufacturer | tr -d '\\n'";

    I_ShellCmd *i_shell_cmd = Singleton::Consume<I_ShellCmd>::by<AgentDetails>();
    auto machine_type = i_shell_cmd->getExecOutput(decode_machine_type_cmd);
    if (!machine_type.ok()) {
        dbgWarning(D_ORCHESTRATOR) << "Error. Could not decode the DMI table. " << machine_type.getErr();
        return I_AgentDetails::MachineType::UNRECOGNIZED;
    } else if (machine_type.unpack().empty()) {
        dbgWarning(D_ORCHESTRATOR) << "Error. Could not decode the DMI table. Table value is empty";
        return I_AgentDetails::MachineType::UNRECOGNIZED;
    }

    dbgInfo(D_ORCHESTRATOR) << "Decoded the DMI talble: " << machine_type.unpack();
    auto resolved_machine_type = machineTypes.find(*machine_type);
    if (resolved_machine_type == end(machineTypes)) return I_AgentDetails::MachineType::UNRECOGNIZED;

    return resolved_machine_type->second;
}

void
AgentDetails::registerMachineType()
{
    Maybe<I_AgentDetails::MachineType> machine_type = getMachineTypeFromDmiTable();
    if (!machine_type.ok()) {
        dbgWarning(D_ORCHESTRATOR)
            << "Error. Could not get machine type from the DMI table. "
            << machine_type.getErr();
        return;
    }
    if (machine_type.unpack() == I_AgentDetails::MachineType::UNRECOGNIZED) {
        dbgWarning(D_ORCHESTRATOR) << "Error. Machine type is unrecognized";
    }
    Singleton::Consume<I_Environment>::by<AgentDetails>()->registerValue<I_AgentDetails::MachineType>(
        "MachineType", machine_type.unpack()
    );
    dbgInfo(D_ORCHESTRATOR) << "Setting machine type " << static_cast<int>(machine_type.unpack());
}

string
AgentDetails::convertProxyProtocolToString(ProxyProtocol proto) const
{
    switch(proto) {
        case ProxyProtocol::HTTP: return "http";
        case ProxyProtocol::HTTPS: return "https";
    }
    dbgAssert(false) << "Unsupported Proxy Protocol " << static_cast<int>(proto);
    return "";
}

Maybe<void>
AgentDetails::verifyProxySyntax(
    const string &protocol,
    const string &auth,
    const string &domain,
    const string &port,
    const string &env_proxy)
{
    stringstream verify_string;
    verify_string
        << protocol
        << "://"
        << (!auth.empty() ? auth + string("@") : "")
        << domain
        << ":"
        << port
        << (env_proxy.back() == '/' ? "/" : "");

    if (env_proxy.compare(verify_string.str()) != 0) {
        return genError(string("Provided proxy has the wrong syntax:" ) + env_proxy);
    }
    return Maybe<void>();
}

Maybe<string>
AgentDetails::loadProxyType(const string &proxy_type)
{
    readAgentDetails();
    auto proxy_config = getProxy();
    if (proxy_config.ok()) {
        if (proxy_config.unpack() == "none") {
            return Maybe<string>(string());
        }
        return proxy_config;
    }

#ifdef gaia
    I_ShellCmd *shell_cmd = Singleton::Consume<I_ShellCmd>::by<AgentDetails>();
    auto proxy_ip = shell_cmd->getExecOutput("dbget proxy:ip-address| tr -d '\n'");
    if (!proxy_ip.ok()) return proxy_ip;
    auto proxy_port = shell_cmd->getExecOutput("dbget proxy:port| tr -d '\n'");
    if (!proxy_port.ok()) return proxy_port;
    if (*proxy_port != "" && *proxy_ip != "") return ("http://" + *proxy_ip + ":" + *proxy_port);

    const string umis_file_path(string(getenv("CPDIR")) + "/tmp/umis_objects.C");

    {
        ifstream umis_file(umis_file_path.c_str());
        if (!umis_file.good()) return Maybe<string>(string());
    }

    const string read_umis_cmd = "cat " + umis_file_path + " | grep -w \"";
    const string parse_value_command = "\" | awk -F \"[ \\t]+\" '{printf $NF}' | tr -d \"()\"";

    auto use_proxy = shell_cmd->getExecOutput(read_umis_cmd + "use_proxy" + parse_value_command);
    if (!use_proxy.ok())
        return genError("Failed to read use_proxy from " + umis_file_path + ": " + use_proxy.getErr());

    if (use_proxy.unpack() == "true") {
        auto umis_proxy_add = shell_cmd->getExecOutput(read_umis_cmd + "proxy_address" + parse_value_command);
        if (!umis_proxy_add.ok() || *umis_proxy_add == "") return umis_proxy_add;
        auto umis_proxy_port = shell_cmd->getExecOutput(read_umis_cmd + "proxy_port" + parse_value_command);
        if (!umis_proxy_port.ok() || *umis_proxy_port == "") return umis_proxy_port;

        return ("http://" + *umis_proxy_add + ":" + *umis_proxy_port);
    } else {
        dbgTrace(D_ORCHESTRATOR) << "Smart Console Proxy is turned off";
    }
    return Maybe<string>(string());
#else // not gaia
    char *proxy = getenv(proxy_type.c_str());
    if (proxy) return string(proxy);

    proxy = getenv(boost::algorithm::to_upper_copy(proxy_type).c_str());
    if (proxy) return string(proxy);
    return Maybe<string>(string());
#endif // gaia
}

Maybe<void>
AgentDetails::loadProxyType(ProxyProtocol protocol)
{
    dbgAssert(protocol == ProxyProtocol::HTTP || protocol == ProxyProtocol::HTTPS)
        << "Unsupported Proxy Protocol " << static_cast<int>(protocol);

    static const map<ProxyProtocol, string> env_var_name = {
        {ProxyProtocol::HTTPS, "https_proxy"},
        {ProxyProtocol::HTTP, "http_proxy"}
    };
    auto env_proxy = loadProxyType(env_var_name.at(protocol));
    if (!env_proxy.ok()) return genError(env_proxy.getErr());
    if (env_proxy.unpack().empty()) {
        return Maybe<void>();
    }

    string protocol_regex = "(http|https)://";
    const static boost::regex no_auth_proxy_regex(protocol_regex + "(.)*:[0-9]{0,5}(/|)");
    const static boost::regex auth_proxy_regex(protocol_regex + "(.)*:(.)*@(.)*:[0-9]{0,5}(/|)");

    ProxyData env_proxy_data;
    env_proxy_data.is_exists = true;
    string proxy_copy;
    if (!NGEN::Regex::regexMatch(__FILE__, __LINE__, env_proxy.unpack(), boost::regex(protocol_regex + "(.)*"))) {
        env_proxy = "http://" + env_proxy.unpack();
    }
    proxy_copy.assign(env_proxy.unpack());
    env_proxy_data.protocol = env_proxy.unpack().substr(0, proxy_copy.find(":"));
    proxy_copy.erase(0, proxy_copy.find(":") + 3); //remove "http://" or "https://"

    if (NGEN::Regex::regexMatch(__FILE__, __LINE__, env_proxy.unpack(), auth_proxy_regex)) {
        env_proxy_data.auth = string(&proxy_copy[0], &proxy_copy[proxy_copy.find("@")]);
        proxy_copy.erase(0, proxy_copy.find("@") + 1); // remove "user:pass@"
    } else if (!NGEN::Regex::regexMatch(__FILE__, __LINE__, env_proxy.unpack(), no_auth_proxy_regex)) {
        return genError(string("Provided proxy has wrong syntax: ") + env_proxy.unpack());
    }
    env_proxy_data.domain = proxy_copy.substr(0, proxy_copy.find(":"));
    proxy_copy.erase(0, proxy_copy.find(":") + 1); // remove "host:"
    env_proxy_data.port = static_cast<uint16_t>(stoi(proxy_copy));

    auto proxy_syntax = verifyProxySyntax(
        env_proxy_data.protocol,
        env_proxy_data.auth,
        env_proxy_data.domain,
        to_string(env_proxy_data.port),
        env_proxy.unpack()
    );
    if (!proxy_syntax.ok()) return proxy_syntax;
    if (env_proxy_data == proxies.at(protocol)) {
        return Maybe<void>();
    }

    proxies.at(protocol) = env_proxy_data;
    dbgInfo(D_ORCHESTRATOR)
        << convertProxyProtocolToString(protocol)
        << " proxy was successfully loaded, "
        << getProxyAddress(protocol).unpack();

    return Maybe<void>();
}

Maybe<string>
AgentDetails::getProxyDomain(ProxyProtocol protocol) const
{
    if (proxies.find(protocol) == proxies.end()) {
        return genError("Proxy type is not loaded in map, type: " + convertProxyProtocolToString(protocol));
    }
    if (proxies.at(protocol).domain.empty()) return genError(
        convertProxyProtocolToString(protocol) + string(" proxy domain is unset")
    );
    return proxies.at(protocol).domain;
}

Maybe<string>
AgentDetails::getProxyCredentials(ProxyProtocol protocol) const
{
    if (proxies.find(protocol) == proxies.end()) {
        return genError("Proxy type is not loaded in map, type: " + convertProxyProtocolToString(protocol));
    }
    if (proxies.at(protocol).auth.empty()) return genError(
        convertProxyProtocolToString(protocol) + string(" proxy auth is unset")
    );
    return proxies.at(protocol).auth;
}

Maybe<uint16_t>
AgentDetails::getProxyPort(ProxyProtocol protocol) const
{
    if (proxies.find(protocol) == proxies.end()) {
        return genError("Proxy type is not loaded in map, type: " + convertProxyProtocolToString(protocol));
    }
    if (proxies.at(protocol).port == 0) return genError(
        convertProxyProtocolToString(protocol) + string(" proxy port is unset")
    );
    return proxies.at(protocol).port;
}

bool
AgentDetails::getProxyExists(ProxyProtocol protocol) const
{
    if (proxies.find(protocol) == proxies.end()) {
        dbgInfo(D_ORCHESTRATOR)
            << "Proxy type is not loaded in map, type: "
            << convertProxyProtocolToString(protocol);
        return false;
    }
    return proxies.at(protocol).is_exists;
}

Maybe<string>
AgentDetails::getProxyAddress(ProxyProtocol protocol) const
{
    if (proxies.find(protocol) == proxies.end()) {
        return genError("Proxy type is not loaded in map, type: " + convertProxyProtocolToString(protocol));
    }
    if (proxies.at(protocol).protocol.empty() ||
        proxies.at(protocol).domain.empty() ||
        proxies.at(protocol).port == 0) {
        return genError(
            string("Can't construct ") +
            convertProxyProtocolToString(protocol) +
            string(" proxy address")
        );
    }
    return proxies.at(protocol).protocol +
        "://" +
        proxies.at(protocol).domain +
        ":" +
        to_string(proxies.at(protocol).port);
}

Maybe<void>
AgentDetails::loadProxy()
{
    if (getConfigurationFlag("orchestration-mode") == "offline_mode") return Maybe<void>();
    for (const auto &proxy_type : proxies) {
        auto loaded_proxy = loadProxyType(proxy_type.first);
        if (!loaded_proxy.ok()) return loaded_proxy;
    }
    return Maybe<void>();
}
