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

#ifndef __MANIFEST_HANDLER_H__
#define __MANIFEST_HANDLER_H__

#include "package.h"
#include "i_package_handler.h"
#include "i_downloader.h"
#include "i_orchestration_tools.h"
#include "i_orchestration_status.h"
#include "i_environment.h"
#include "i_agent_details.h"
#include "i_details_resolver.h"
#include "i_time_get.h"

class ManifestHandler
        :
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_AgentDetails>,
    Singleton::Consume<I_OrchestrationTools>,
    Singleton::Consume<I_PackageHandler>,
    Singleton::Consume<I_Downloader>,
    Singleton::Consume<I_Environment>,
    Singleton::Consume<I_OrchestrationStatus>,
    Singleton::Consume<I_DetailsResolver>
{
public:
    using packageFilePath = std::string;

    ManifestHandler() = default;
    void init();

    bool
    downloadPackages(
        const std::vector<Package> &updated_packages,
        std::vector<std::pair<Package, packageFilePath>> &downloaded_packages
    );

    bool
    installPackages(
        const std::vector<std::pair<Package, packageFilePath>> &downloaded_packages_files,
        std::map<packageFilePath, Package> &current_packages,
        std::map<packageFilePath, Package> &corrupted_packages
    );

    bool uninstallPackage(Package &removed_package);

    bool
    selfUpdate(
        const Package &updated_package,
        std::map<packageFilePath, Package> &current_packages,
        const packageFilePath &installation_file
    );

private:
    Maybe<std::string> downloadPackage(const Package &package, bool is_clean_installation);

    std::string manifest_file_path;
    std::string temp_ext;
    std::string backup_ext;
    std::string packages_dir;
    std::string orch_service_name;
    std::string default_dir;
};
#endif // __MANIFEST_HANDLER_H__
