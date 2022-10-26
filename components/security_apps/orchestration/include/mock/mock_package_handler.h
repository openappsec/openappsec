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

#ifndef __MOCK_PACKAGE_HANDLER_H__
#define __MOCK_PACKAGE_HANDLER_H__

#include "i_package_handler.h"
#include "cptest.h"

class MockPackageHandler :
    public Singleton::Provide<I_PackageHandler>::From<MockProvider<I_PackageHandler>>
{
public:
    MOCK_CONST_METHOD3(installPackage, bool(const std::string &, const std::string &, bool));
    MOCK_CONST_METHOD3(uninstallPackage, bool(const std::string &, const std::string &, const std::string &));
    MOCK_CONST_METHOD2(preInstallPackage, bool(const std::string &, const std::string &));
    MOCK_CONST_METHOD2(postInstallPackage, bool(const std::string &, const std::string &));
    MOCK_CONST_METHOD2(updateSavedPackage, bool(const std::string &, const std::string &));
    MOCK_CONST_METHOD2(shouldInstallPackage, bool(const std::string &, const std::string &));
};
#endif // __MOCK_PACKAGE_HANDLER_H__
