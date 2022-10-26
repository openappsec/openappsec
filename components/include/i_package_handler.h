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

#ifndef __I_PACKAGE_HANDLER_H__
#define __I_PACKAGE_HANDLER_H__

#include <string>

class I_PackageHandler
{
public:
    virtual bool shouldInstallPackage(const std::string &package_name, const std::string &install_file_path) const = 0;

    virtual bool installPackage(
        const std::string &package_name,
        const std::string &install_file_path,
        bool restore_mode
    ) const = 0;
    virtual bool uninstallPackage(
        const std::string &package_name,
        const std::string &package_path,
        const std::string &install_file_path
    ) const = 0;
    virtual bool preInstallPackage(
        const std::string &package_name,
        const std::string &install_file_path
    ) const = 0;
    virtual bool postInstallPackage(
        const std::string &package_name,
        const std::string &install_file_path
    ) const = 0;
    virtual bool updateSavedPackage(
        const std::string &package_name,
        const std::string &install_file_path
    ) const = 0;
};
#endif // __I_PACKAGE_HANDLER_H__
