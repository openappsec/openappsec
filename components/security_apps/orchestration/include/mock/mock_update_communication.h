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

#ifndef __MOCK_UPDATE_COMMUNICATION_H__
#define __MOCK_UPDATE_COMMUNICATION_H__

#include "i_update_communication.h"
#include "cptest.h"

std::ostream &
operator<<(std::ostream &os, const CheckUpdateRequest &)
{
    return os;
}

class MockUpdateCommunication :
    public Singleton::Provide<I_UpdateCommunication>::From<MockProvider<I_UpdateCommunication>>
{
public:
    void init() {}
    MOCK_METHOD0(authenticateAgent, Maybe<void>());
    MOCK_METHOD1(getUpdate, Maybe<void>(CheckUpdateRequest &));
    MOCK_METHOD2(
        downloadAttributeFile,
        Maybe<std::string>(const GetResourceFile &, const std::string &)
    );
    MOCK_METHOD1(setAddressExtenesion, void(const std::string &));
    MOCK_CONST_METHOD2(sendPolicyVersion, Maybe<void>(const std::string &, const std::string &));
};

#endif // __MOCK_UPDATE_COMMUNICATION_H__
