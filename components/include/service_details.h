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

#ifndef __SERVICE_DETAILS_H__
#define __SERVICE_DETAILS_H__

#include <string>
#include <vector>

#include "connkey.h"
#include "rest.h"
#include "config.h"
#include "i_service_controller.h"

class ServiceDetails : Singleton::Consume<I_ServiceController>
{
public:
    ServiceDetails() = default;
    ServiceDetails(
        const std::string &name,
        const PortNumber &port,
        const std::vector<std::string> relevant_configurations,
        const std::string &id = "")
            :
        service_name(name),
        service_id(id),
        service_port(port)
    {
        relevant_configs.insert(relevant_configurations.begin(), relevant_configurations.end());
    }

    template <typename Archive>
    void serialize(Archive &ar);

    ReconfStatus sendNewConfigurations(int conf_id, const std::string &policy_version);

    bool isConfigurationRelevant(const std::string &config) const { return relevant_configs.count(config) > 0; }

    bool sendRequest(const std::string &uri, ClientRest &request_json) const;

    bool isServiceActive() const;

    const PortNumber & getPort() const { return service_port; }

    const std::string & getServiceID() const {return service_id; }

    const std::string & getServiceName() const {return service_name; }

private:

    std::string service_name;
    std::string service_id;
    PortNumber service_port;
    std::unordered_set<std::string> relevant_configs;
};

class SetNanoServiceConfig : public ServerRest
{
public:
    void doCall() override;

    C2S_PARAM(std::string, service_name);
    C2S_OPTIONAL_PARAM(std::string, service_id);
    C2S_PARAM(int, service_listening_port);
    C2S_PARAM(std::vector<std::string>, expected_configurations);
    S2C_PARAM(bool, status);
};

#endif // __SERVICE_DETAILS_H__
