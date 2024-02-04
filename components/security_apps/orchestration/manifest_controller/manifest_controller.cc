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

#include "manifest_controller.h"

#include <algorithm>

#include "config.h"
#include "debug.h"
#include "environment.h"
#include "version.h"
#include "log_generator.h"
#include "orchestration_comp.h"

using namespace std;
using namespace ReportIS;

USE_DEBUG_FLAG(D_ORCHESTRATOR);

class IgnoredPackages
{
public:
    void
    load(istream &input, char delim)
    {
        string ignored_package;
        while (getline(input, ignored_package, delim))
        {
            if (ignored_package == "all") {
                ignore_packages.clear();
                ignore_packages.insert(ignored_package);
                dbgInfo(D_ORCHESTRATOR) << "Will ignore updates for all packages";
                break;
            } else if (ignored_package == "none") {
                ignore_packages.clear();
                dbgInfo(D_ORCHESTRATOR) << "Will not ignore updates of any packages";
                break;
            }

            if (ignored_package.size() > 0) {
                ignore_packages.insert(ignored_package);
                dbgInfo(D_ORCHESTRATOR) << "Updates for package " << ignored_package << " will be ignored";
            }
        }
    }

    void
    load(const string &raw_value)
    {
        string token;
        istringstream tokenStream(raw_value);
        load(tokenStream, ',');
    }

    const set<string> & operator*() const { return ignore_packages; }

private:
    set<string> ignore_packages;
};

class ManifestController::Impl : Singleton::Provide<I_ManifestController>::From<ManifestController>
{
public:
    void init();

    bool updateManifest(const string &new_manifest_file) override;
    bool loadAfterSelfUpdate() override;

private:
    bool changeManifestFile(const string &new_manifest_file);
    bool updateIgnoreListForNSaaS();

    bool
    handlePackage(
        const pair<Package, string> &package_downloaded_file,
        map<string, Package> &current_packages,
        map<string, Package> &corrupted_packages
    );

    bool isIgnoreFile(const string &new_manifest_file) const;

    ManifestDiffCalculator manifest_diff_calc;
    ManifestHandler manifest_handler;

    string manifest_file_path;
    string corrupted_file_list;
    string temp_ext;
    string backup_ext;
    string packages_dir;
    string orch_service_name;
    set<string> ignore_packages;
};

void
ManifestController::Impl::init()
{
    manifest_diff_calc.init();
    manifest_handler.init();

    dbgTrace(D_ORCHESTRATOR) << "Manifest controller, file system path prefix: " << getFilesystemPathConfig();

    manifest_file_path = getConfigurationWithDefault<string>(
        getFilesystemPathConfig() + "/conf/manifest.json",
        "orchestration",
        "Manifest file path"
    );
    corrupted_file_list = getConfigurationWithDefault<string>(
        getFilesystemPathConfig() + "/conf/corrupted_packages.json",
        "orchestration",
        "Manifest corrupted files path"
    );
    temp_ext = getConfigurationWithDefault<string>("_temp", "orchestration", "Temp file extension");
    backup_ext = getConfigurationWithDefault<string>(".bk", "orchestration", "Backup file extension");
    packages_dir = getConfigurationWithDefault<string>(
        getFilesystemPathConfig() + "/packages",
        "orchestration",
        "Packages directory"
    );
    orch_service_name = getConfigurationWithDefault<string>("orchestration", "orchestration", "Service name");

    auto ignore_packages_path = getConfigurationWithDefault<string>(
        getFilesystemPathConfig() + "/conf/ignore-packages.txt",
        "orchestration",
        "Ignore packages list file path"
    );

    if (Singleton::Consume<I_OrchestrationTools>::by<ManifestController>()->doesFileExist(ignore_packages_path)) {
        try {
            ifstream input_stream(ignore_packages_path);
            if (!input_stream) {
                dbgWarning(D_ORCHESTRATOR)
                    <<  "Cannot open the file with ignored packages. "
                    <<  "File: " << ignore_packages_path;
            } else {
                IgnoredPackages packages_to_ignore;
                packages_to_ignore.load(input_stream, '\n');
                ignore_packages = *packages_to_ignore;

                input_stream.close();
            }
        } catch (ifstream::failure &f) {
            dbgWarning(D_ORCHESTRATOR)
                << "Cannot read the file with ignored packages."
                << " File: " << ignore_packages_path
                << " Error: " << f.what();
        }
    }
}

bool
ManifestController::Impl::updateIgnoreListForNSaaS()
{
    if (!getProfileAgentSettingWithDefault<bool>(false, "accessControl.isAwsNSaaS")) return false;

    auto ignore_packages_path = getConfigurationWithDefault<string>(
        getFilesystemPathConfig() + "/conf/ignore-packages.txt",
        "orchestration",
        "Ignore packages list file path"
    );
    ofstream ignore_file(ignore_packages_path);
    if (!ignore_file.is_open()) {
        dbgWarning(D_ORCHESTRATOR) << "Unable to open file " << ignore_packages_path << " for writing";
        return false;
    }

    ignore_file << "all";
    ignore_file.close();
    dbgInfo(D_ORCHESTRATOR) << "Updated " << ignore_packages_path << " to ignore all packages";

    return true;
}

static vector<pair<Package, string>>::const_iterator
findPackage(const vector<pair<Package, string>> &packages, const string &name)
{
    using Pair = pair<Package, string>;
    return find_if(packages.begin(), packages.end(), [&] (const Pair &pair) { return pair.first.getName() == name; });
}

static vector<pair<Package, string>>
sortByInstallationQueue(
    const vector<pair<Package, string>> &downloaded_files,
    const vector<Package> &installation_queue)
{
    vector<pair<Package, string>> sorted_queue;
    for (auto &package_file : installation_queue) {
        if (package_file.getName() == "accessControlApp" || package_file.getName() == "accessControlKernel") continue;

        auto package_it = findPackage(downloaded_files, package_file.getName());
        if (package_it != downloaded_files.end()) sorted_queue.push_back(*package_it);
    }

    auto ac_app_it = findPackage(downloaded_files, "accessControlApp");
    auto ac_kernel_it = findPackage(downloaded_files, "accessControlKernel");
    if (ac_app_it != downloaded_files.end()) sorted_queue.push_back(*ac_app_it);
    if (ac_kernel_it != downloaded_files.end()) sorted_queue.push_back(*ac_kernel_it);

    return sorted_queue;
}

bool
ManifestController::Impl::updateManifest(const string &new_manifest_file)
{
    auto i_env = Singleton::Consume<I_Environment>::by<ManifestController>();
    auto span_scope = i_env->startNewSpanScope(Span::ContextType::CHILD_OF);
    auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<ManifestController>();
    static bool ignore_packages_update = false;

    if (isIgnoreFile(new_manifest_file)) {
        if (!orchestration_tools->copyFile(new_manifest_file, manifest_file_path)) {
            dbgWarning(D_ORCHESTRATOR) << "Failed to copy a new manifest file";
            return false;
        }
        return true;
    }

    dbgDebug(D_ORCHESTRATOR) << "Starting to update manifest file";
    auto ignored_settings_packages = getProfileAgentSetting<IgnoredPackages>("orchestration.IgnoredPackagesList");
    set<string> packages_to_ignore = ignore_packages;
    if (ignored_settings_packages.ok()) {
        packages_to_ignore = *(*ignored_settings_packages);
        ignore_packages_update = false;
    }

    if (ignore_packages_update || packages_to_ignore.count("all") > 0) {
        dbgTrace(D_ORCHESTRATOR) << "Nothing to update (\"ignore all\" turned on)";

        if (!orchestration_tools->copyFile(new_manifest_file, manifest_file_path)) {
            dbgWarning(D_ORCHESTRATOR) << "Failed to copy a new manifest file";
            return false;
        }
        return true;
    }

    Maybe<map<string, Package>> parsed_manifest = orchestration_tools->loadPackagesFromJson(new_manifest_file);
    if (!parsed_manifest.ok()) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to parse the new manifest file. File: " << new_manifest_file;
        return false;
    }

    map<string, Package> new_packages = parsed_manifest.unpack();
    map<string, Package> all_packages = parsed_manifest.unpack();
    map<string, Package> current_packages;
    parsed_manifest = orchestration_tools->loadPackagesFromJson(manifest_file_path);

    if (!parsed_manifest.ok()){
        dbgWarning(D_ORCHESTRATOR) << "Can not parse the current manifest file, start with new one.";
    } else {
        current_packages = parsed_manifest.unpack();
    }

    // Remove any update of all ignore packages
    for (const auto &ignore_package : packages_to_ignore) {
        dbgInfo(D_ORCHESTRATOR) << "Ignoring a package from the manifest. Package name: " << ignore_package;
        if (new_packages.count(ignore_package) > 0) {
            // Get the change as-is of the ignore package - it won"t update the service
            current_packages[ignore_package] = new_packages[ignore_package];
        } else {
            // Remove the ignore package from the current manifest file - it won't uninstall the service
            current_packages.erase(ignore_package);
        }
    }

    map<string, Package> corrupted_packages;
    parsed_manifest = orchestration_tools->loadPackagesFromJson(corrupted_file_list);

    if (!parsed_manifest.ok()){
        dbgWarning(D_ORCHESTRATOR) << "Can not parse corrupted services file, start with new one.";
    } else {
        corrupted_packages = parsed_manifest.unpack();
    }

    bool all_cleaned = true;
    bool uninstall_done = false;
    // Removes all the untracked packages. new_packages will be cleaned from already installed packages
    auto packages_to_remove = manifest_diff_calc.filterUntrackedPackages(current_packages, new_packages);
    for (auto remove_package = packages_to_remove.begin(); remove_package != packages_to_remove.end();) {
        bool uninstall_response = true;
        if (remove_package->second.isInstallable()) {
            uninstall_response = manifest_handler.uninstallPackage(remove_package->second);
        }

        if (!uninstall_response) {
            dbgWarning(D_ORCHESTRATOR)
                << "Failed to uninstall package. Package: "
                << remove_package->second.getName();
            all_cleaned = false;
            remove_package++;
        } else {
            uninstall_done = true;
            current_packages.erase(remove_package->first);
            remove_package = packages_to_remove.erase(remove_package);
        }
    }

    if (uninstall_done) {
        if (!orchestration_tools->packagesToJsonFile(current_packages, manifest_file_path)) {
            dbgWarning(D_ORCHESTRATOR) << "Failed to update manifest file. File: "
                <<  manifest_file_path;
        } else {
            dbgInfo(D_ORCHESTRATOR) << "Manifest file was updated successfully. File: "
            << manifest_file_path;
        }
    }

    bool no_change = new_packages.size() == 0;
    // Both new_packages & corrupted_packages will be updated based on updated manifest

    const auto &download_packages_res = manifest_handler.downloadPackages(new_packages);
    if (!download_packages_res.ok()) {
        dbgWarning(D_ORCHESTRATOR)
            << "Failed to download required packages. Error: "
            << download_packages_res.getErr();
        return false;
    }
    const vector<pair<Package, string>> &downloaded_files = download_packages_res.unpack();
    const auto &installation_queue_res = manifest_diff_calc.buildInstallationQueue(
            current_packages,
            new_packages
    );
    if (!installation_queue_res.ok()) {
        dbgWarning(D_ORCHESTRATOR)
            << "Failed building installation queue. Error: "
            << installation_queue_res.getErr();
        return false;
    }
    const vector<Package> &installation_queue = installation_queue_res.unpack();

    const auto &sortd_downloaded_files = sortByInstallationQueue(downloaded_files, installation_queue);

    bool all_installed = true;
    bool any_installed = false;

    dbgDebug(D_ORCHESTRATOR) << "Starting to handle " << downloaded_files.size() << " new packages";
    for (auto &package : sortd_downloaded_files) {
        if (package.first.getType() != Package::PackageType::Service) continue;
        size_t prev_size = corrupted_packages.size();

        bool handling_response = handlePackage(
            package,
            current_packages,
            corrupted_packages
        );

        // During handlePackage function, package installation might fail so it will be added to
        // corrupted_packages. Corrupted file needs to be updated accordingly
        if (prev_size < corrupted_packages.size() &&
            !orchestration_tools->packagesToJsonFile(corrupted_packages, corrupted_file_list)) {
            dbgWarning(D_ORCHESTRATOR) << "Failed to update corrupted packages list.";
        }

        // Orchestration needs special handling as manifest should be backup differently
        if (package.first.getName().compare(orch_service_name) == 0) {
            return handling_response;
        }
        if (package.first.getName().compare("wlpStandalone") == 0) {
            return handling_response;
        }

        any_installed = any_installed || handling_response;
        all_installed = all_installed && handling_response;
    }

    bool manifest_file_update = true;

    if (all_installed && (any_installed || no_change)) {
        manifest_file_update = changeManifestFile(new_manifest_file);
        // In NSaaS - set ignore packages to any
        ignore_packages_update = updateIgnoreListForNSaaS();
    } else if (any_installed) {
        manifest_file_update = orchestration_tools->packagesToJsonFile(current_packages, manifest_file_path);
    }
    if (all_installed) {
        auto orchestration_downloader = Singleton::Consume<I_Downloader>::by<ManifestHandler>();
        for (auto &package : all_packages) {
            dbgDebug(D_ORCHESTRATOR)
                << "Removing temp Download file after successfull installation : " << package.second.getName();
            orchestration_downloader->removeDownloadFile(package.second.getName());
        }
    }
    return all_installed && manifest_file_update && all_cleaned;
}

// Orchestration package needs a special handling. Old service will die during the upgrade
// so we need to keep temporary manifest file to prevent overwriting. Once Orchestration upgrade
// finish, we return to regular path.
bool
ManifestController::Impl::loadAfterSelfUpdate()
{
    dbgDebug(D_ORCHESTRATOR) << "Starting load after the self update function";
    string temp_manifest_path = manifest_file_path + temp_ext;
    auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<ManifestController>();
    if (!orchestration_tools->doesFileExist(temp_manifest_path)) {
        return true;
    }

    dbgDebug(D_ORCHESTRATOR) << "Orchestration updated itself";
    // Run post installation test
    auto package_handler = Singleton::Consume<I_PackageHandler>::by<ManifestController>();
    string current_file = packages_dir + "/" + orch_service_name + "/" + orch_service_name;
    if (!package_handler->postInstallPackage(orch_service_name, current_file + temp_ext)) {
        dbgWarning(D_ORCHESTRATOR) << "Failed in post install test. Package: " << orch_service_name;
        return false;
    }
    dbgDebug(D_ORCHESTRATOR) << "Post installation test for the self update package succeed";

    if (!changeManifestFile(temp_manifest_path)) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to change manifest file after update the orchestration service.";
        return false;
    }
    dbgDebug(D_ORCHESTRATOR) << "Update the temporary manifest to be the running manifest";

    string backup_file = current_file + backup_ext;
    string backup_temp_file = backup_file + temp_ext;

    if (!package_handler->updateSavedPackage(orch_service_name, current_file + temp_ext)) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to update the saved package. Package: " << orch_service_name;
        return false;
    }

    return true;
}

bool
ManifestController::Impl::changeManifestFile(const string &new_manifest_file)
{
    dbgDebug(D_ORCHESTRATOR) << "Backup the old manifest file";
    auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<ManifestController>();

    if (orchestration_tools->doesFileExist(manifest_file_path)) {
        if (!orchestration_tools->copyFile(manifest_file_path,
                                            manifest_file_path + backup_ext)) {
            dbgWarning(D_ORCHESTRATOR) << "Failed to backup the old manifest file";
        }
    }

    dbgDebug(D_ORCHESTRATOR) << "Writing new manifest to file";
    if (!orchestration_tools->copyFile(new_manifest_file, manifest_file_path)) {
        dbgWarning(D_ORCHESTRATOR) << "Failed write new manifest to file";
        return false;
    }

    if (!orchestration_tools->isNonEmptyFile(manifest_file_path)) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to get manifest file data";
        return false;
    }

    dbgInfo(D_ORCHESTRATOR) << "Manifest file has been updated.";

    if (!orchestration_tools->removeFile(new_manifest_file)) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to remove new manifest file. Path: " << new_manifest_file;
    }
    return true;
}

bool
ManifestController::Impl::handlePackage(
    const pair<Package, string> &package_downloaded_file,
    map<string, Package> &current_packages,
    map<string, Package> &corrupted_packages)
{
    auto &package = package_downloaded_file.first;

    auto i_env = Singleton::Consume<I_Environment>::by<ManifestController>();
    auto span_scope = i_env->startNewSpanScope(Span::ContextType::CHILD_OF);
    dbgDebug(D_ORCHESTRATOR) << "Handling package. Package: " << package.getName();

    if (!package.isInstallable()) {
        string report_msg =
            "Skipping installation of package: " + package.getName() + ". Reason: " + package.getErrorMessage();
        dbgWarning(D_ORCHESTRATOR) << report_msg;
        LogGen(report_msg, Audience::SECURITY, Severity::CRITICAL, Priority::HIGH, Tags::ORCHESTRATOR);
        current_packages.insert(make_pair(package.getName(), package));
        return true;
    }

    if (!manifest_handler.installPackage(package_downloaded_file, current_packages, corrupted_packages)) {
        LogGen(
            "Failed to install package: " + package.getName(),
            Audience::SECURITY,
            Severity::CRITICAL,
            Priority::HIGH,
            Tags::ORCHESTRATOR
        );
        return false;
    }

    dbgInfo(D_ORCHESTRATOR) << "Package was installed successfully. Package: " <<  package.getName();
    return true;
}

bool
ManifestController::Impl::isIgnoreFile(const string &new_manifest_file) const
{
    ifstream manifest(new_manifest_file);

    char ch;
    manifest.get(ch);

    while (manifest.good() && isspace(ch)) {
        manifest.get(ch);
    }

    if (!manifest.good() || ch != '{') return false;
    manifest.get(ch);

    while (manifest.good() && isspace(ch)) {
        manifest.get(ch);
    }

    if (!manifest.good() || ch != '"') return false;
    manifest.get(ch);
    if (!manifest.good() || ch != 'p') return false;
    manifest.get(ch);
    if (!manifest.good() || ch != 'a') return false;
    manifest.get(ch);
    if (!manifest.good() || ch != 'c') return false;
    manifest.get(ch);
    if (!manifest.good() || ch != 'k') return false;
    manifest.get(ch);
    if (!manifest.good() || ch != 'a') return false;
    manifest.get(ch);
    if (!manifest.good() || ch != 'g') return false;
    manifest.get(ch);
    if (!manifest.good() || ch != 'e') return false;
    manifest.get(ch);
    if (!manifest.good() || ch != 's') return false;
    manifest.get(ch);
    if (!manifest.good() || ch != '"') return false;
    manifest.get(ch);

    while (manifest.good() && isspace(ch)) {
        manifest.get(ch);
    }

    if (!manifest.good() || ch != ':') return false;
    manifest.get(ch);

    while (manifest.good() && isspace(ch)) {
        manifest.get(ch);
    }

    if (!manifest.good() || ch != 'n') return false;
    manifest.get(ch);
    if (!manifest.good() || ch != 'u') return false;
    manifest.get(ch);
    if (!manifest.good() || ch != 'l') return false;
    manifest.get(ch);
    if (!manifest.good() || ch != 'l') return false;
    manifest.get(ch);


    while (manifest.good() && isspace(ch)) {
        manifest.get(ch);
    }

    return manifest.good() && ch == '}';
}

ManifestController::ManifestController() : Component("ManifestController"), pimpl(make_unique<Impl>()) {}

ManifestController::~ManifestController() {}

void
ManifestController::init()
{
    pimpl->init();
}
