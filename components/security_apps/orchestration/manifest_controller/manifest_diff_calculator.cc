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

#include "manifest_diff_calculator.h"

#include "debug.h"
#include "config.h"

using namespace std;

USE_DEBUG_FLAG(D_ORCHESTRATOR);

void
ManifestDiffCalculator::init()
{
    dbgTrace(D_ORCHESTRATOR)
        << "Initializing Manifest diff calculator, file system path prefix:: "
        << getFilesystemPathConfig();

    corrupted_file_path = getConfigurationWithDefault<string>(
        getFilesystemPathConfig() + "/conf/corrupted_packages.json",
        "orchestration",
        "Manifest corrupted files path"
    );
}

// If one of the new packages is already installed, new_packages map is updated accordingly.
// This function return map<string, Package> which contain all packages that should be uninstalled
// based on new manifest
map<string, Package>
ManifestDiffCalculator::filterUntrackedPackages(
    const map<string, Package> &current_packages,
    map<string, Package> &new_packages)
{
    dbgDebug(D_ORCHESTRATOR) << "Starting to scan old packages to remove";
    map<string, Package> packages_to_remove;
    for (auto current_package = current_packages.begin(); current_package != current_packages.end();) {
        auto package = new_packages.find(current_package->first);
        if (package == new_packages.end()) {
            packages_to_remove.insert(pair<string, Package>(current_package->first, current_package->second));
        } else {
            if (current_package->second == package->second) {
                // if package is already installed, new_packages is updated
                new_packages.erase(package);
            }
        }
        current_package++;
    }
    return packages_to_remove;
}

// If one of the new packages is already known as corrupted, new_packages map is
// updated accordingly.
// Otherwise, corrupted_packages is updated and old corrupted package is deleted.
bool
ManifestDiffCalculator::filterCorruptedPackages(
    map<string, Package> &new_packages,
    map<string, Package> &corrupted_packages)
{
    bool no_corrupted_package_exist = true;
    bool any_corrupted_removed = false;
    for (auto corrupted_package = corrupted_packages.begin(); corrupted_package != corrupted_packages.end();) {
        auto package = new_packages.find(corrupted_package->first);
        if (package == new_packages.end()) {
            // The corrupted package is not in the new packages list,
            // so it should be removed from the corrupted list.
            corrupted_package = corrupted_packages.erase(corrupted_package);
            any_corrupted_removed = true;
        } else {
            if (corrupted_package->second == package->second) {
                // The corrupted package is still in the new packages list,
                // so it should be removed
                dbgWarning(D_ORCHESTRATOR) << "Installation package is corrupted."
                    << " Package: " << package->second.getName();
                new_packages.erase(package);
                corrupted_package++;
                no_corrupted_package_exist = false;
            } else {
                // New version of corrupted package was received
                corrupted_package = corrupted_packages.erase(corrupted_package);
                any_corrupted_removed = true;
            }
        }
    }
    if (any_corrupted_removed) {
        dbgDebug(D_ORCHESTRATOR) << "Updating corrupted file. File: " << corrupted_file_path;
        auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<ManifestDiffCalculator>();
        if (!orchestration_tools->packagesToJsonFile(corrupted_packages, corrupted_file_path)) {
            dbgWarning(D_ORCHESTRATOR) << "Failed to update corrupted file. Path: " << corrupted_file_path;
            return false;
        }
    }
    return no_corrupted_package_exist;
}

// This function build the installation queue recursively and return true if succeeded, false otherwise
//  At the beginning, installation_queue is empty and will be filled according package dependences
bool
ManifestDiffCalculator::buildInstallationQueue(
    const Package &updated_package,
    vector<Package> &installation_queue,
    const map<string, Package> &current_packages,
    const map<string, Package> &new_packages)
{
    vector<string> requires = updated_package.getRequire();

    for (size_t i = 0; i < requires.size(); i++) {
        auto installed_package = current_packages.find(requires[i]);
        auto new_package = new_packages.find(requires[i]);

        if (installed_package == current_packages.end() ||
            (new_package != new_packages.end() && *installed_package != *new_package)) {
                if(!buildInstallationQueue(new_package->second,
                                            installation_queue,
                                            current_packages,
                                            new_packages)) {
                    return false;
                }
            } else if (installed_package != current_packages.end()) {
                dbgDebug(D_ORCHESTRATOR) << "Package is already installed. Package: " << installed_package->first;
            } else if (new_package == new_packages.end()) {
                dbgWarning(D_ORCHESTRATOR) << "One of the requested dependencies is corrupted or doesn't exist."
                    << " Package: "<< requires[i];
                return false;
            }
    }
    installation_queue.push_back(updated_package);
    return true;
}
