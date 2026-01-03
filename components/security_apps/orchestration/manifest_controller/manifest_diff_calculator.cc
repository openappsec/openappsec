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

#include <algorithm>

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

// LCOV_EXCL_START Reason: temp disabling corrupted packages mechanism

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
// LCOV_EXCL_STOP

Maybe<void>
ManifestDiffCalculator::buildRecInstallationQueue(
    const Package &package,
    vector<Package> &installation_queue,
    const map<string, Package> &current_packages,
    const map<string, Package> &new_packages)
{
    const vector<string> &requires_packages = package.getRequire();

    for (const auto &require : requires_packages) {
        auto installed_package = current_packages.find(require);
        auto new_package = new_packages.find(require);

        if (installed_package == current_packages.end() ||
            (new_package != new_packages.end() && *installed_package != *new_package)) {
                auto rec_res = buildRecInstallationQueue(
                    new_package->second,
                    installation_queue,
                    current_packages,
                    new_packages
                );
                if (!rec_res.ok()) return rec_res.passErr();
            } else if (installed_package != current_packages.end()) {
                dbgDebug(D_ORCHESTRATOR) << "Package is already in the queue. Package: " << installed_package->first;
            } else if (new_package == new_packages.end()) {
                return genError(
                    "One of the requested dependencies is corrupted or doesn't exist. Package: " + require
                );
            }
    }
    if (find(installation_queue.begin(), installation_queue.end(), package) == installation_queue.end()) {
        installation_queue.push_back(package);
    }
    return Maybe<void>();
}

// This function build the installation queue recursively and return true if succeeded, false otherwise
//  At the beginning, installation_queue is empty and will be filled according package dependences
Maybe<vector<Package>>
ManifestDiffCalculator::buildInstallationQueue(
    const map<string, Package> &current_packages,
    const map<string, Package> &new_packages)
{
    vector<Package> installation_queue;
    installation_queue.reserve(new_packages.size());
    auto orchestration_it = new_packages.find("orchestration");
    if (orchestration_it != new_packages.end()) {
        installation_queue.push_back(orchestration_it->second);
    }

    auto shared_libs_it = new_packages.find("sharedLibs");
    if (shared_libs_it != new_packages.end()) {
        installation_queue.push_back(shared_libs_it->second);
    }


    auto wlp_standalone_it = new_packages.find("wlpStandalone");
    if (wlp_standalone_it != new_packages.end()){
        installation_queue.push_back(wlp_standalone_it->second);
    }

    for (auto &package_pair : new_packages) {
        auto build_queue_res = buildRecInstallationQueue(
            package_pair.second,
            installation_queue,
            current_packages,
            new_packages
        );
        if (!build_queue_res.ok()) return build_queue_res.passErr();
    }
    return installation_queue;
}
