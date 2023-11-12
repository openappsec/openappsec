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

#ifndef __MOCK_SERVICE_CONTROLLER_H__
#define __MOCK_SERVICE_CONTROLLER_H__

#include "i_service_controller.h"

#include "cptest.h"
#include <string>

class MockServiceController :
    public Singleton::Provide<I_ServiceController>::From<MockProvider<I_ServiceController>>

{
public:
    MOCK_METHOD0(refreshPendingServices, void());

    MOCK_METHOD0(mockMoveChangedPolicies, std::set<std::string>());
    std::set<std::string> tmp;
    std::set<std::string> && moveChangedPolicies() override { tmp = mockMoveChangedPolicies(); return std::move(tmp); }

    MOCK_METHOD0(doesFailedServicesExist, bool());

    MOCK_METHOD0(clearFailedServices, void());

    MOCK_CONST_METHOD0(getPolicyVersion, const std::string &());

    MOCK_CONST_METHOD0(getUpdatePolicyVersion, const std::string &());

    MOCK_CONST_METHOD0(getPolicyVersions, const std::string &());

    MOCK_METHOD6(
        updateServiceConfiguration,
        Maybe<void>(
            const std::string &new_policy_path,
            const std::string &new_settings_path,
            const std::vector<std::string> &new_data_files,
            const std::string &child_tenant_id,
            const std::string &child_profile_id,
            const bool last_iteration
        )
    );

    MOCK_METHOD1(isServiceInstalled, bool(const std::string &service_name));

    MOCK_METHOD4(
        registerServiceConfig,
        void(
            const std::string &service_name,
            PortNumber listening_port,
            const std::vector<std::string> &expected_configurations,
            const std::string &id
        )
    );

    typedef std::map<std::string, PortNumber> ServicePortMap;
    MOCK_METHOD0(getServiceToPortMap, ServicePortMap());
    MOCK_METHOD3(updateReconfStatus, void(int id, const std::string &service_name, ReconfStatus status));
    MOCK_METHOD4(
        startReconfStatus,
        void(int id, ReconfStatus status, const std::string &serivce_name, const std::string &service_id)
    );
};

#endif // __MOCK_SERVICE_CONTROLLER_H__
