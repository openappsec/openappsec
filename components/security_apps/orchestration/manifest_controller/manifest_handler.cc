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

#include "manifest_handler.h"

#include <algorithm>

#include "debug.h"
#include "config.h"
#include "agent_details.h"
#include "orchestration_comp.h"
#include "updates_process_event.h"

using namespace std;

USE_DEBUG_FLAG(D_ORCHESTRATOR);

void
ManifestHandler::init()
{
    dbgTrace(D_ORCHESTRATOR)
        << "Initializing Manifest handler, file system path prefix: "
        << getFilesystemPathConfig();

    manifest_file_path = getConfigurationWithDefault<string>(
        getFilesystemPathConfig() + "/conf/manifest.json",
        "orchestration",
        "Manifest file path"
    );
    temp_ext = getConfigurationWithDefault<string>("_temp", "orchestration", "Temp file extension");
    backup_ext = getConfigurationWithDefault<string>(".bk", "orchestration", "Backup file extension");
    packages_dir = getConfigurationWithDefault<string>(
        getFilesystemPathConfig() + "/packages", "orchestration",
        "Packages directory"
    );
    orch_service_name = getConfigurationWithDefault<string>("orchestration", "orchestration", "Service name");
    default_dir = getConfigurationWithDefault<string>(
        getFilesystemPathConfig(),
        "orchestration",
        "Default Check Point directory"
    );
}

Maybe<string>
ManifestHandler::downloadPackage(const Package &package, bool is_clean_installation)
{
    Maybe<string> package_download_file = genError("failed to download package, Package: " + package.getName());
    Maybe<string> fog_domain = genError("No Fog domain was found");
    if (Singleton::exists<I_AgentDetails>()) {
        fog_domain = Singleton::Consume<I_AgentDetails>::by<ManifestHandler>()->getFogDomain();
    }

    auto orchestration_downloader = Singleton::Consume<I_Downloader>::by<ManifestHandler>();
    auto maybe_package_exists = orchestration_downloader->checkIfFileExists(package);
    if (maybe_package_exists.ok()) return maybe_package_exists;

    if (!is_clean_installation) {
        I_MainLoop *i_mainloop = Singleton::Consume<I_MainLoop>::by<ManifestHandler>();
        auto pending_time_frame_seconds = getConfigurationWithDefault<int>(
            60,
            "orchestration",
            "Download pending time frame seconds"
        );
        int pending_time = rand() % pending_time_frame_seconds;
        dbgInfo(D_ORCHESTRATOR)
            << "Pending downloading of package "
            << package.getName()
            << " for "
            << pending_time
            << " seconds";
        chrono::microseconds pending_time_micro = chrono::seconds(pending_time);
        i_mainloop->yield(pending_time_micro);
        dbgTrace(D_ORCHESTRATOR) << "Proceeding to package downloading. Package name " << package.getName();
    }

    if (!package.getRelativeDownloadPath().empty() && fog_domain.ok()) {
        string download_path =
            "<JWT>https://" + fog_domain.unpack() + "/download" + package.getRelativeDownloadPath();
        package_download_file = orchestration_downloader->downloadFileFromURL(
            download_path,
            package.getChecksum(),
            package.getChecksumType(),
            package.getName()
        );
    }

    if (!package_download_file.ok()) {
        package_download_file = orchestration_downloader->downloadFileFromURL(
            package.getDownloadPath(),
            package.getChecksum(),
            package.getChecksumType(),
            package.getName()
        );
    }
    return package_download_file;
}

Maybe<vector<pair<Package, packageFilePath>>>
ManifestHandler::downloadPackages(const map<string, Package> &new_packages_to_download)
{
    auto i_env = Singleton::Consume<I_Environment>::by<ManifestHandler>();
    auto i_orch_tools = Singleton::Consume<I_OrchestrationTools>::by<ManifestHandler>();
    auto span_scope = i_env->startNewSpanScope(Span::ContextType::CHILD_OF);

    vector<pair<Package, packageFilePath>> downloaded_packages;
    for (auto &package_pair : new_packages_to_download) {
        const Package &package = package_pair.second;
        if (!package.isInstallable()) {
            dbgTrace(D_ORCHESTRATOR)
                << "Skipping package download, package isn't installable. Package: "
                    << package.getName() << ". Reason: " << package.getErrorMessage();
            continue;
        }
        dbgInfo(D_ORCHESTRATOR) << "Downloading package file." << " Package: " <<  package.getName();

        string packages_dir = getConfigurationWithDefault<string>(
            "/etc/cp/packages",
            "orchestration",
            "Packages directory"
        );

        string current_installation_file = packages_dir + "/" + package.getName() + "/" + package.getName();
        bool is_clean_installation = !i_orch_tools->doesFileExist(current_installation_file);

        Maybe<string> package_download_file = downloadPackage(package, is_clean_installation);

        if (package_download_file.ok()) {
            dbgDebug(D_ORCHESTRATOR)
                << "Installation package was downloaded successfully."
                << " Package: " << package.getName();
            downloaded_packages.push_back(pair<Package, packageFilePath>(package, package_download_file.unpack()));
        } else {
            dbgWarning(D_ORCHESTRATOR)
                << "Failed to download installation package. "
                << "Package: " << package.getName()
                << ", Error: " << package_download_file.getErr();

            for (auto &package_file : downloaded_packages) {
                if (i_orch_tools->removeFile(package_file.second)) {
                    dbgDebug(D_ORCHESTRATOR) << "Corrupted downloaded package was removed. Package: "
                        << package_file.first.getName();
                } else {
                    dbgWarning(D_ORCHESTRATOR)
                        << "Failed to removed the download file. Package: "
                        << package_file.first.getName()
                        << ", Path: "
                        << package_file.second;
                }
            }
            downloaded_packages.clear();

            auto agent_details = Singleton::Consume<I_AgentDetails>::by<ManifestHandler>();
            auto hostname = Singleton::Consume<I_DetailsResolver>::by<ManifestHandler>()->getHostname();
            string err_hostname = (hostname.ok() ? "on host '" + *hostname : "'" + agent_details->getAgentId()) + "'";
            string install_error;
            if (is_clean_installation) {
                install_error =
                    "Critical Error: Agent/Gateway was not fully deployed " +
                    err_hostname +
                    " and is not enforcing a security policy. Retry installation or contact Check Point support.";
            } else {
                install_error =
                    "Warning: Agent/Gateway " +
                    err_hostname +
                    " software update failed. Agent is running previous software. Contact Check Point support.";
            }

            UpdatesProcessEvent(
                UpdatesProcessResult::FAILED,
                UpdatesConfigType::MANIFEST,
                UpdatesFailureReason::DOWNLOAD_FILE,
                package.getName(),
                install_error
            ).notify();
            return genError(
                "Failed to download installation package. Package: " +
                package.getName() +
                ", Error: " + package_download_file.getErr());
        }
    }
    return downloaded_packages;
}

bool
ManifestHandler::installPackage(
    const pair<Package, string> &package_downloaded_file,
    map<packageFilePath, Package> &current_packages,
    map<packageFilePath, Package> &corrupted_packages)
{
    auto i_env = Singleton::Consume<I_Environment>::by<ManifestHandler>();
    auto span_scope = i_env->startNewSpanScope(Span::ContextType::CHILD_OF);
    auto orchestration_status = Singleton::Consume<I_OrchestrationStatus>::by<ManifestHandler>();

    auto &package = package_downloaded_file.first;
    auto &package_name = package.getName();
    auto &package_handler_path = package_downloaded_file.second;

    dbgInfo(D_ORCHESTRATOR) << "Handling package installation. Package: " << package_name;

    if (package_name.compare(orch_service_name) == 0) {
        orchestration_status->writeStatusToFile();
        bool self_update_status = selfUpdate(package, current_packages, package_handler_path);
        if (!self_update_status) {
            auto details = Singleton::Consume<I_AgentDetails>::by<ManifestHandler>();
            auto hostname = Singleton::Consume<I_DetailsResolver>::by<ManifestHandler>()->getHostname();
            string err_hostname = (hostname.ok() ? "on host '" + *hostname : "'" + details->getAgentId()) + "'";
            string install_error =
                "Warning: Agent/Gateway " +
                err_hostname +
                " software update failed. Agent is running previous software. Contact Check Point support.";
            if (orchestration_status->getManifestError().find("Gateway was not fully deployed") == string::npos) {
                UpdatesProcessEvent(
                    UpdatesProcessResult::FAILED,
                    UpdatesConfigType::MANIFEST,
                    UpdatesFailureReason::INSTALL_PACKAGE,
                    package_name,
                    install_error
                ).notify();
            }
        }
        return self_update_status;
    }

    string packages_dir = getConfigurationWithDefault<string>(
        "/etc/cp/packages",
        "orchestration",
        "Packages directory"
    );

    auto package_handler = Singleton::Consume<I_PackageHandler>::by<ManifestHandler>();
    if (!package_handler->shouldInstallPackage(package_name, package_handler_path)) {
        current_packages.insert(make_pair(package_name, package));
        dbgInfo(D_ORCHESTRATOR)
            << "Skipping installation of new package with the same version as current. Package: "
            << package_name;
        return true;
    }
    string current_installation_file = packages_dir + "/" + package_name + "/" + package_name;
    auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<ManifestHandler>();
    bool is_clean_installation = !orchestration_tools->doesFileExist(current_installation_file);


    bool current_result = true;
    bool is_service = package.getType() == Package::PackageType::Service;
    if (is_service) {
        current_result = package_handler->preInstallPackage(package_name, package_handler_path);
    }

    current_result = current_result && package_handler->installPackage(
        package_name,
        package_handler_path,
        false
    );

    if (current_result && is_service) {
        current_result = package_handler->postInstallPackage(package_name, package_handler_path);
    }

    if (current_result && is_service) {
        current_result = package_handler->updateSavedPackage(package_name, package_handler_path);
    }

    if (!current_result) {
        auto agent_details = Singleton::Consume<I_AgentDetails>::by<ManifestHandler>();
        auto hostname = Singleton::Consume<I_DetailsResolver>::by<ManifestHandler>()->getHostname();
        string err_hostname = (hostname.ok() ? "on host '" + *hostname : "'" +agent_details->getAgentId()) + "'";
        string install_error;
        if (is_clean_installation) {
            install_error =
                "Critical Error: Agent/Gateway was not fully deployed " +
                err_hostname +
                " and is not enforcing a security policy. Retry installation or contact Check Point support.";
        } else {
            install_error =
                "Warning: Agent/Gateway " +
                err_hostname +
                " software update failed. Agent is running previous software. Contact Check Point support.";
        }
        corrupted_packages.insert(make_pair(package_name, package));
        dbgWarning(D_ORCHESTRATOR) << "Failed to install package. Package: " << package_name;

        auto orchestration_status = Singleton::Consume<I_OrchestrationStatus>::by<ManifestHandler>();
        if (orchestration_status->getManifestError().find("Gateway was not fully deployed") == string::npos) {
            UpdatesProcessEvent(
                UpdatesProcessResult::FAILED,
                UpdatesConfigType::MANIFEST,
                UpdatesFailureReason::INSTALL_PACKAGE,
                package_name,
                install_error
            ).notify();
        }
        return false;
    }

    current_packages.insert(make_pair(package_name, package));
    return true;
}

bool
ManifestHandler::uninstallPackage(Package &removed_package)
{
    dbgDebug(D_ORCHESTRATOR) << "Starting uninstalling. Package: " << removed_package.getName();
    string package_name  = removed_package.getName();
    string package_path = default_dir + "/" + package_name + "/" + package_name;
    string installation_package = packages_dir + "/" + package_name + "/" + package_name;
    auto package_handler = Singleton::Consume<I_PackageHandler>::by<ManifestHandler>();
    return package_handler->uninstallPackage(package_name, package_path, installation_package);
}

bool
ManifestHandler::selfUpdate(
    const Package &updated_package,
    map<packageFilePath, Package> &current_packages,
    const string &installation_file)
{
    dbgInfo(D_ORCHESTRATOR) << "Updating orchestration service";

    auto current_service = current_packages.find(updated_package.getName());
    if (current_service != current_packages.end()) {
        current_service->second = updated_package;
    } else {
        current_packages.insert(pair<packageFilePath, Package>(updated_package.getName(), updated_package));
    }

    string temp_manifest_path = manifest_file_path + temp_ext;

    auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<ManifestHandler>();
    if (!orchestration_tools->packagesToJsonFile(current_packages, temp_manifest_path)) {
        dbgWarning(D_ORCHESTRATOR) << "Updating manifest temporary file has failed. File: " << temp_manifest_path;
        return false;
    }

    string current_file = packages_dir + "/" + orch_service_name + "/" + orch_service_name;
    string backup_file = current_file + backup_ext;

    dbgDebug(D_ORCHESTRATOR) << "Saving the temporary backup file.";
    if (orchestration_tools->doesFileExist(current_file)) {
        dbgDebug(D_ORCHESTRATOR) << "Backup current installation package. Destination: " << backup_file;
        if (!orchestration_tools->copyFile(current_file, backup_file + temp_ext)) {
            dbgWarning(D_ORCHESTRATOR) << "Failed to backup installation file. File: " << current_file;
            return false;
        }
    } else {
        dbgDebug(D_ORCHESTRATOR) << "There is no previous version for Orchestration";
    }

    string current_installation_file = current_file + temp_ext;
    dbgDebug(D_ORCHESTRATOR) << "Saving the installation file: " << current_installation_file;
    if (!orchestration_tools->copyFile(installation_file, current_installation_file)) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to save the installation file: " << current_installation_file;
        return false;
    }

    dbgDebug(D_ORCHESTRATOR) << "Starting to install the orchestration: " << current_installation_file;

    auto package_handler = Singleton::Consume<I_PackageHandler>::by<ManifestHandler>();
    return
        package_handler->preInstallPackage(orch_service_name, current_installation_file) &&
        package_handler->installPackage(orch_service_name, current_installation_file, false);
}
