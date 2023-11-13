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

#ifndef __I_SERVICE_CONTROLLER_H__
#define __I_SERVICE_CONTROLLER_H__

#include <string>
#include <vector>
#include <map>

#include "connkey.h"
#include "maybe_res.h"
#include "rest.h"

enum class ReconfStatus { SUCCEEDED, IN_PROGRESS, FAILED, INACTIVE };

class I_ServiceController
{
public:
    virtual void refreshPendingServices() = 0;
    virtual const std::string & getPolicyVersions() const = 0;
    virtual const std::string & getPolicyVersion() const = 0;
    virtual const std::string & getUpdatePolicyVersion() const = 0;
    virtual void updateReconfStatus(int id, const std::string &service_name, ReconfStatus status) = 0;
    virtual void startReconfStatus(
        int id,
        ReconfStatus status,
        const std::string &service_name,
        const std::string &service_id
    ) = 0;

    virtual Maybe<void>
    updateServiceConfiguration(
        const std::string &new_policy_path,
        const std::string &new_settings_path,
        const std::vector<std::string> &new_data_files = {},
        const std::string &child_tenant_id = "",
        const std::string &child_profile_id = "",
        const bool last_iteration = false
    ) = 0;

    virtual bool doesFailedServicesExist() = 0;

    virtual void clearFailedServices() = 0;

    virtual std::set<std::string> && moveChangedPolicies() = 0;

    virtual bool isServiceInstalled(const std::string &service_name) = 0;

    virtual void registerServiceConfig(
        const std::string &service_name,
        PortNumber listening_port,
        const std::vector<std::string> &expected_configurations,
        const std::string &service_id
    ) = 0;

    virtual std::map<std::string, PortNumber> getServiceToPortMap() = 0;

protected:
    virtual ~I_ServiceController() {}
};

#endif // __I_SERVICE_CONTROLLER_H__
