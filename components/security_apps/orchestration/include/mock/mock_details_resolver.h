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

#ifndef __MOCK_DETAILS_RESOLVER_H__
#define __MOCK_DETAILS_RESOLVER_H__

#include <iostream>

#include "i_details_resolver.h"
#include "cptest.h"
#include "maybe_res.h"

std::ostream &
operator<<(std::ostream &os, const Maybe<std::tuple<std::string, std::string, std::string>> &)
{
    return os;
}

class MockDetailsResolver
        :
    public Singleton::Provide<I_DetailsResolver>::From<MockProvider<I_DetailsResolver>>
{
public:
    MOCK_METHOD0(getHostname,                Maybe<std::string>());
    MOCK_METHOD0(getPlatform,                Maybe<std::string>());
    MOCK_METHOD0(getArch,                    Maybe<std::string>());
    MOCK_METHOD0(getAgentVersion,            std::string());
    MOCK_METHOD0(isReverseProxy,             bool());
    MOCK_METHOD0(isKernelVersion3OrHigher,   bool());
    MOCK_METHOD0(isGwNotVsx,                 bool());
    MOCK_METHOD0(getResolvedDetails,         std::map<std::string, std::string>());
    MOCK_METHOD0(isVersionEqualOrAboveR8110, bool());
    MOCK_METHOD0(parseNginxMetadata, Maybe<std::tuple<std::string, std::string, std::string>>());
};

#endif // __MOCK_DETAILS_RESOLVER_H__
