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

#ifndef __MOCK_ORCHESTRATION_TOOLS_H__
#define __MOCK_ORCHESTRATION_TOOLS_H__

#include "cptest.h"
#include "i_orchestration_tools.h"

template <typename T>
std::ostream &
operator<<(std::ostream &os, const std::vector<T> &)
{
    return os;
}

template <typename T, typename S>
std::ostream &
operator<<(std::ostream &os, const std::map<T, S> &)
{
    return os;
}

class MockOrchestrationTools
        :
    public Singleton::Provide<I_OrchestrationTools>::From<MockProvider<I_OrchestrationTools>>
{
public:
    MOCK_CONST_METHOD1(loadPackagesFromJson, Maybe<std::map<std::string, Package>>(const std::string &));
    MOCK_CONST_METHOD2(packagesToJsonFile,   bool(const std::map<std::string, Package> &, const std::string &));
    MOCK_CONST_METHOD1(isNonEmptyFile,       bool(const std::string &));
    MOCK_CONST_METHOD1(readFile,             Maybe<std::string>(const std::string &));
    MOCK_CONST_METHOD2(writeFile,            bool(const std::string &, const std::string &));
    MOCK_CONST_METHOD1(removeFile,           bool(const std::string &));
    MOCK_CONST_METHOD2(copyFile,             bool(const std::string &, const std::string &));
    MOCK_CONST_METHOD2(calculateChecksum,    Maybe<std::string>(Package::ChecksumTypes, const std::string &));
    MOCK_CONST_METHOD3(
        jsonObjectSplitter,
        Maybe<std::map<std::string, std::string>>(const std::string &, const std::string &, const std::string &)
    );
    MOCK_CONST_METHOD1(doesFileExist,        bool(const std::string &));
    MOCK_CONST_METHOD3(fillKeyInJson,        void(const std::string &, const std::string &, const std::string &));
    MOCK_CONST_METHOD1(createDirectory,      bool(const std::string &));
    MOCK_CONST_METHOD1(doesDirectoryExist,   bool(const std::string &));
    MOCK_CONST_METHOD1(executeCmd,           bool(const std::string &));
    MOCK_CONST_METHOD1(base64Encode,         std::string(const std::string &));
    MOCK_CONST_METHOD1(base64Decode,         std::string(const std::string &));
    MOCK_CONST_METHOD2(removeDirectory,      bool(const std::string &, bool delete_content));
    MOCK_CONST_METHOD1(loadTenantsFromDir,   void(const std::string &));
    MOCK_CONST_METHOD3(
        deleteVirtualTenantProfileFiles,
        void(const std::string &tenant_id, const std::string &profile_id, const std::string &conf_path)
    );
};
#endif // __MOCK_ORCHESTRATION_TOOLS_H__
