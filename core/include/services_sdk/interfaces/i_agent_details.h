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

#ifndef __I_AGENT_DETAILS_H__
#define __I_AGENT_DETAILS_H__

#include <string>
#include <map>
#include "maybe_res.h"

enum class OrchestrationMode { ONLINE, OFFLINE, HYBRID, COUNT };

class I_AgentDetails
{
public:

    // Fog Details
    virtual void setFogPort(const uint16_t _fog_port)           = 0;
    virtual void setSSLFlag(const bool _is_over_ssl)            = 0;
    virtual void setFogDomain(const std::string &_fog_domain)   = 0;
    virtual void setProfileId(const std::string &_profile_id)   = 0;
    virtual void setTenantId(const std::string &_tenant_id)     = 0;

    virtual Maybe<uint16_t> getFogPort()                  const = 0;
    virtual bool getSSLFlag()                             const = 0;
    virtual Maybe<std::string> getFogDomain()             const = 0;
    virtual std::string getTenantId()                     const = 0;
    virtual std::string getProfileId()                    const = 0;

    // Agent Details
    virtual Maybe<std::string> getProxy()                             const = 0;
    virtual void setProxy(const std::string &_proxy)                        = 0;
    virtual void setAgentId(const std::string &_agent_id)                   = 0;
    virtual std::string getAgentId()                                  const = 0;
    virtual void setOrchestrationMode(OrchestrationMode _orchstration_mode) = 0;
    virtual OrchestrationMode getOrchestrationMode()                  const = 0;
    virtual std::string getAccessToken()                              const = 0;
    virtual void loadAccessToken()                                          = 0;

    // OpenSSL
    virtual void setOpenSSLDir(const std::string &openssl_dir)  = 0;
    virtual Maybe<std::string> getOpenSSLDir()            const = 0;

    // Serialization
    virtual bool readAgentDetails()                             = 0;
    virtual bool writeAgentDetails()                            = 0;

    // Environment
    virtual void setClusterId(const std::string &_cluster_id)   = 0;

    enum class MachineType { AZURE, AWS, ON_PREM, UNRECOGNIZED };
};

#endif // __I_AGENT_DETAILS_H__
