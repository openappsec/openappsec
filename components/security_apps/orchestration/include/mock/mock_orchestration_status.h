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

#ifndef __MOCK_ORCHESTRATION_STATUS_H__
#define __MOCK_ORCHESTRATION_STATUS_H__

#include "i_orchestration_status.h"
#include "cptest.h"

class MockOrchestrationStatus
        :
    public Singleton::Provide<I_OrchestrationStatus>::From<MockProvider<I_OrchestrationStatus>>
{
public:
    MOCK_METHOD0(writeStatusToFile, void());
    MOCK_METHOD0(recoverFields, void());
    MOCK_METHOD1(setUpgradeMode, void(const std::string &));
    MOCK_METHOD1(setAgentType, void(const std::string &));
    MOCK_METHOD1(setRegistrationStatus, void(const std::string &));
    MOCK_METHOD1(setFogAddress, void(const std::string &));
    MOCK_METHOD1(setPolicyVersion, void(const std::string &));
    MOCK_METHOD1(setIsConfigurationUpdated, void(EnumArray<OrchestrationStatusConfigType, bool> config_types));
    MOCK_METHOD0(setLastUpdateAttempt, void());
    MOCK_METHOD3(setAgentDetails, void(const std::string &, const std::string &, const std::string &));
    MOCK_METHOD3(setFieldStatus,
        void(const OrchestrationStatusFieldType &, const OrchestrationStatusResult &, const std::string &));
    MOCK_METHOD4(setRegistrationDetails,
        void(const std::string &, const std::string &, const std::string &, const std::string &)
    );
    MOCK_METHOD3(setServiceConfiguration,
        void(const std::string &, const std::string &, const OrchestrationStatusConfigType &)
    );
    MOCK_CONST_METHOD0(getLastUpdateAttempt, const std::string&());
    MOCK_CONST_METHOD0(getUpdateStatus, const std::string&());
    MOCK_CONST_METHOD0(getUpdateTime, const std::string&());
    MOCK_CONST_METHOD0(getLastManifestUpdate, const std::string&());
    MOCK_CONST_METHOD0(getPolicyVersion, const std::string&());
    MOCK_CONST_METHOD0(getLastPolicyUpdate, const std::string&());
    MOCK_CONST_METHOD0(getLastSettingsUpdate, const std::string&());
    MOCK_CONST_METHOD0(getUpgradeMode, const std::string&());
    MOCK_CONST_METHOD0(getFogAddress, const std::string&());
    MOCK_CONST_METHOD0(getRegistrationStatus, const std::string&());
    MOCK_CONST_METHOD0(getAgentId, const std::string&());
    MOCK_CONST_METHOD0(getProfileId, const std::string&());
    MOCK_CONST_METHOD0(getTenantId, const std::string&());
    MOCK_CONST_METHOD0(getManifestStatus, const std::string&());
    MOCK_CONST_METHOD0(getManifestError, const std::string&());
    MOCK_CONST_METHOD0(getServicePolicies, const std::map<std::string, std::string>&());
    MOCK_CONST_METHOD0(getServiceSettings, const std::map<std::string, std::string>&());
    MOCK_CONST_METHOD0(getRegistrationDetails, const std::string());
};

#endif // __MOCK_ORCHESTRATION_STATUS_H__
