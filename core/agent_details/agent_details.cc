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

#include "config.h"
#include "debug.h"
#include "sasal.h"

SASAL_START // Orchestration - Communication

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

SASAL_END
