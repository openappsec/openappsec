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

#ifndef __MANIFEST_DIFF_CALCULATOR_H__
#define __MANIFEST_DIFF_CALCULATOR_H__

#include "package.h"
#include "i_orchestration_tools.h"

class ManifestDiffCalculator : Singleton::Consume<I_OrchestrationTools>
{
public:
    ManifestDiffCalculator() = default;

    void init();

    std::map<std::string, Package>
    filterUntrackedPackages(
        const std::map<std::string, Package> &current_packages,
        std::map<std::string, Package> &new_packages
    );

    bool
    filterCorruptedPackages(
        std::map<std::string, Package> &new_packages,
        std::map<std::string, Package> &corrupted_packages
    );

    bool
    buildInstallationQueue(
        const Package &updated_package,
        std::vector<Package> &installation_queue,
        const std::map<std::string, Package> &current_packages,
        const std::map<std::string, Package> &new_packages
    );

private:
    std::string corrupted_file_path;
};
#endif // __MANIFEST_DIFF_CALCULATOR_H__
