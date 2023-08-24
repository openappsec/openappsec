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

#ifndef __AGENT_DETAILS_H__
#define __AGENT_DETAILS_H__

#include <cereal/archives/json.hpp>

#include "i_agent_details.h"
#include "i_encryptor.h"
#include "i_shell_cmd.h"
#include "i_environment.h"
#include "i_mainloop.h"
#include "i_proxy_configuration.h"
#include "singleton.h"
#include "component.h"
#include "enum_array.h"
#include "agent_core_utilities.h"

class ProxyData
{
public:
    bool
    operator==(const ProxyData &other) const
    {
        return protocol==other.protocol &&
            domain==other.domain &&
            is_exists==other.is_exists &&
            port==other.port &&
            auth==other.auth;
    }

    std::string protocol = "";
    std::string domain = "";
    std::string auth = "";
    bool is_exists = false;
    uint16_t port = 0;
};

class AgentDetails
        :
    public Component,
    Singleton::Provide<I_AgentDetails>::SelfInterface,
    Singleton::Provide<I_ProxyConfiguration>::SelfInterface,
    Singleton::Consume<I_Encryptor>,
    Singleton::Consume<I_ShellCmd>,
    Singleton::Consume<I_Environment>,
    Singleton::Consume<I_MainLoop>
{
public:
    AgentDetails() : Component("AgentDetails") {}

    void preload();

    void init();

    Maybe<std::string> getProxy()            const;
    Maybe<std::string> getFogDomain()        const;
    Maybe<uint16_t> getFogPort()             const;
    std::string getAgentId()                 const;
    std::string getTenantId()                const;
    std::string getProfileId()               const;
    Maybe<std::string> getOpenSSLDir()       const;
    std::string getClusterId()               const;
    OrchestrationMode getOrchestrationMode() const;
    std::string getAccessToken()             const;
    void loadAccessToken();

    void setFogDomain(const std::string &_fog_domain)   { fog_domain  = _fog_domain; }
    void setFogPort(const uint16_t _fog_port)           { fog_port    = _fog_port; }
    void setProxy(const std::string &_proxy)            { proxy       = _proxy; }
    void setAgentId(const std::string &_agent_id)       { agent_id    = _agent_id; }
    void setProfileId(const std::string &_profile_id)   { profile_id  = _profile_id; }
    void setTenantId(const std::string &_tenant_id)     { tenant_id   = _tenant_id; }
    void setOpenSSLDir(const std::string &_openssl_dir) { openssl_dir = _openssl_dir; }
    void setSSLFlag(const bool _encrypted_connection)   { encrypted_connection  = _encrypted_connection; }
    void setOrchestrationMode(OrchestrationMode _orchstration_mode)  { orchestration_mode = _orchstration_mode; }
    bool getSSLFlag() const                             { return encrypted_connection; }

    bool readAgentDetails();
    bool writeAgentDetails();

    void serialize(cereal::JSONOutputArchive &ar);
    void serialize(cereal::JSONInputArchive &ar);

    void setClusterId(const std::string &_cluster_id);

    Maybe<std::string> getProxyDomain(ProxyProtocol protocol)      const;
    Maybe<std::string> getProxyCredentials(ProxyProtocol protocol) const;
    Maybe<uint16_t> getProxyPort(ProxyProtocol protocol)           const;
    bool getProxyExists(ProxyProtocol protocol)                    const;
    Maybe<std::string> getProxyAddress(ProxyProtocol protocol)     const;
    Maybe<void> loadProxy();

private:
    std::string fog_domain      = "";
    std::string agent_id        = "";
    std::string tenant_id       = "";
    std::string profile_id      = "";
    std::string proxy           = "";
    std::string openssl_dir     = "";
    std::string cluster_id      = "";
    std::string filesystem_path = "/etc/cp";
    std::string log_files_path  = "/var/log";
    std::string access_token    = "";
    uint16_t fog_port           = 0;
    bool encrypted_connection   = false;
    OrchestrationMode orchestration_mode = OrchestrationMode::ONLINE;
    bool is_proxy_configured_via_settings = false;
    std::map<ProxyProtocol, ProxyData> proxies;

    static const std::map<std::string, I_AgentDetails::MachineType> machineTypes;
    void registerMachineType();
    Maybe<I_AgentDetails::MachineType> getMachineTypeFromDmiTable();

    std::string convertProxyProtocolToString(ProxyProtocol proto) const;
    Maybe<void> verifyProxySyntax(
        const std::string &protocol,
        const std::string &auth,
        const std::string &domain,
        const std::string &port,
        const std::string &env_proxy
    );
    Maybe<std::string> loadProxyType(const std::string &proxy_type);
    Maybe<void> loadProxyType(ProxyProtocol protocol);
};

#endif // __AGENT_DETAILS_H__
