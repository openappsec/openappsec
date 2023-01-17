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

#include "package_handler.h"
#include "config.h"
#include "i_shell_cmd.h"

#include <sys/stat.h>
#include <vector>

USE_DEBUG_FLAG(D_ORCHESTRATOR);

using namespace std;

#ifdef smb
static const string InstallEnvPrefix = "TMPDIR=/storage/tmp ";
#else
static const string InstallEnvPrefix = "";
#endif

enum class PackageHandlerActions {
    INSTALL,
    UNINSTALL,
    PREINSTALL,
    POSTINSTALL,
    UNREGISTER,
    GET_VERSION
};

class AdditionalFlagsConfiguration
{
public:
    AdditionalFlagsConfiguration() : flags() {}

    void
    load(cereal::JSONInputArchive &ar)
    {
        try {
            ar(cereal::make_nvp("flags", flags));
        } catch (cereal::Exception &) {
            ar.setNextName(nullptr);
        }
    }

    const vector<string> & getFlags() const { return flags; }

private:
    vector<string> flags;
};

class PackageHandler::Impl : Singleton::Provide<I_PackageHandler>::From<PackageHandler>
{
public:
    void
    init()
    {
        filesystem_prefix = getFilesystemPathConfig();
        dbgTrace(D_ORCHESTRATOR) << "Initializing Packet handler, file system path prefix: " << filesystem_prefix;
    }
    bool shouldInstallPackage(const string &package_name, const string &install_file_path) const override;

    bool installPackage(const string &package_name, const string &install_file_path, bool restore_mode) const override;

    bool
    uninstallPackage(
        const string &package_name,
        const string &package_path,
        const string &install_file_path
    ) const override;

    bool preInstallPackage(const string &package_name, const string &install_file_path) const override;

    bool postInstallPackage(const string &package_name, const string &install_file_path) const override;

    bool updateSavedPackage(const string &package_name, const string &install_file_path) const override;

private:
    void
    revertPackage(
        const string &package_name,
        bool restore_mode,
        const string &current_installation_file,
        const string &backup_installation_file
    ) const;

    bool setExecutionMode(const string &install_file_path) const;

    string filesystem_prefix;
};

static string
packageHandlerActionsToString(PackageHandlerActions action)
{
    switch(action) {
        case PackageHandlerActions::INSTALL: {
            string installation_mode = " --install";
            auto trusted_ca_directory = getConfiguration<string>("message", "Trusted CA directory");
            if (trusted_ca_directory.ok() && !trusted_ca_directory.unpack().empty()) {
                installation_mode += " --certs-dir ";
                installation_mode += trusted_ca_directory.unpack();
            }
            AdditionalFlagsConfiguration additional_flags = getConfigurationWithDefault<AdditionalFlagsConfiguration>(
                AdditionalFlagsConfiguration(),
                "orchestration",
                "additional flags"
            );
            for (const auto &flag : additional_flags.getFlags()) {
                installation_mode += " " + flag;
            }

            return installation_mode;
        }
        case PackageHandlerActions::UNINSTALL: {
            return string(" --uninstall");
        }
        case PackageHandlerActions::PREINSTALL: {
            return string(" --pre_install_test");
        }
        case PackageHandlerActions::POSTINSTALL: {
            return string(" --post_install_test");
        }
        case PackageHandlerActions::UNREGISTER: {
            return string(" --un-register ");
        }
        case PackageHandlerActions::GET_VERSION: {
            return string(" --version");
        }
    }

    dbgAssert(false) << "Package handler action is not supported. Action: " << static_cast<unsigned int>(action);
    return string();
}

void
PackageHandler::init()
{
    pimpl->init();
}

void
PackageHandler::preload()
{
    registerExpectedConfiguration<bool>("orchestration", "Debug mode");
    registerExpectedConfiguration<AdditionalFlagsConfiguration>("orchestration", "additional flags");
    registerExpectedConfiguration<uint>("orchestration", "Shell command execution time out");
}

bool
PackageHandler::Impl::setExecutionMode(const string &install_file_path) const
{
    return (chmod(install_file_path.c_str(), S_IRUSR | S_IWUSR | S_IXUSR) == 0);
}

bool
PackageHandler::Impl::shouldInstallPackage(const string &package_name, const string &install_file_path) const
{
    string packages_dir = getConfigurationWithDefault<string>(
        filesystem_prefix + "/packages",
        "orchestration",
        "Packages directory"
    );

    I_OrchestrationTools *orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<PackageHandler>();
    string current_installation_file = packages_dir + "/" + package_name + "/" + package_name;
    if (!orchestration_tools->doesFileExist(current_installation_file)) {
        dbgDebug(D_ORCHESTRATOR) << "Clean installation - package should be installed. Package name: " << package_name;
        return true;
    }

    setExecutionMode(current_installation_file);
    setExecutionMode(install_file_path);

    dbgDebug(D_ORCHESTRATOR) << "Checking if new and current packages has different versions";

    uint timeout = getConfigurationWithDefault<uint>(5000, "orchestration", "Shell command execution time out");
    static const string action = packageHandlerActionsToString(PackageHandlerActions::GET_VERSION);

    I_ShellCmd *shell_cmd = Singleton::Consume<I_ShellCmd>::by<PackageHandler>();
    Maybe<string> current_package_version = shell_cmd->getExecOutput(current_installation_file + action, timeout);
    Maybe<string> new_package_version = shell_cmd->getExecOutput(install_file_path + action, timeout);

    if (!current_package_version.ok()) {
        dbgWarning(D_ORCHESTRATOR)
            << "Failed to get version of current package - Upgrade will be executed. Package name: "
            << package_name
            << ", Error: "
            << current_package_version.getErr();
        return true;
    }

    if (!new_package_version.ok()) {
        dbgWarning(D_ORCHESTRATOR)
            << "Failed to get version of new package - Upgrade will be executed. Package name: "
            << package_name
            << ", Error: "
            << new_package_version.getErr();
        return true;
    }

    bool should_install = current_package_version.unpack() != new_package_version.unpack();

    dbgInfo(D_ORCHESTRATOR)
        << "Version for both new and current version successfully extracted. Package name: "
        << package_name
        << ", Current version: "
        << current_package_version.unpack()
        << ", New version: "
        << new_package_version.unpack()
        << ", Should install: "
        << (should_install ? "yes" : "no");

    return should_install;
}

bool
PackageHandler::Impl::installPackage(
    const string &package_name,
    const string &install_file_path,
    bool restore_mode = false) const
{
    I_OrchestrationTools *orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<PackageHandler>();
    if (!orchestration_tools->doesFileExist(install_file_path)) {
        dbgWarning(D_ORCHESTRATOR)
            << "Installation file is not valid for update. File path: "
            << install_file_path
            << " , package: "
            << package_name;
        return false;
    }

    string packages_dir = getConfigurationWithDefault<string>(
        filesystem_prefix + "/packages",
        "orchestration",
        "Packages directory"
    );
    string backup_extension = getConfigurationWithDefault<string>(".bk", "orchestration", "Backup file extension");
    string current_installation_file = packages_dir + "/" + package_name + "/" + package_name;
    string backup_installation_file = current_installation_file + backup_extension;

    if (restore_mode) {
        dbgDebug(D_ORCHESTRATOR) << "Installing package: " << package_name << " from backup.";
    } else {
        dbgDebug(D_ORCHESTRATOR) << "Installing package: " << package_name;
    }

    dbgDebug(D_ORCHESTRATOR) << "Changing permissions to execute installation file " << install_file_path;
    if (!setExecutionMode(install_file_path)) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to change permission for the installation file of " << package_name;
        return false;
    }

    dbgDebug(D_ORCHESTRATOR) << "Start running installation file. Package: "
        << package_name
        << ", path: "
        << install_file_path;
    auto action = packageHandlerActionsToString(PackageHandlerActions::INSTALL);
    bool cmd_result = orchestration_tools->executeCmd(InstallEnvPrefix + install_file_path + action);
    if (!cmd_result) {
        dbgWarning(D_ORCHESTRATOR) << "Failed installing package: " << package_name;
        revertPackage(package_name, restore_mode, current_installation_file, backup_installation_file);
        return false;
    }

    // In restore mode, we should exit to prevent infinite loop
    if (restore_mode) return true;

    if (
        !orchestration_tools->doesFileExist(current_installation_file) &&
        !orchestration_tools->copyFile(install_file_path, current_installation_file)
    ) {
        dbgWarning(D_ORCHESTRATOR)
            << "Failed to save installation file. File: "
            << install_file_path
            << ". Target path: "
            << current_installation_file;
        return false;
    }

    dbgDebug(D_ORCHESTRATOR) << "Backup installation file to " << backup_installation_file;
    if (!orchestration_tools->copyFile(current_installation_file, backup_installation_file)) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to backup installation file: " << current_installation_file;
        return false;
    }

    return true;
}

void
PackageHandler::Impl::revertPackage(
    const string &package_name,
    bool restore_mode,
    const string &current_installation_file,
    const string &backup_installation_file) const
{
    string orch_service_name = getConfigurationWithDefault<string>(
        "orchestration",
        "orchestration",
        "Service name"
    );
    string packages_dir = getConfigurationWithDefault<string>(
        filesystem_prefix + "/packages",
        "orchestration",
        "Packages directory"
    );
    if (package_name == orch_service_name) {
        string manifest_file_path = getConfigurationWithDefault<string>(
            filesystem_prefix + "/conf/manifest.json",
            "orchestration",
            "Manifest file path"
        );
        string temp_extension = getConfigurationWithDefault<string>("_temp", "orchestration", "Temp file extension");
        string temp_manifest_file(manifest_file_path + temp_extension);

        I_OrchestrationTools *orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<PackageHandler>();
        orchestration_tools->removeFile(temp_manifest_file);
    }

    if (restore_mode) return;

    // First we try to recover to last running package and then to
    // the backup (2 recent versions are kept)
    if (!installPackage(package_name, current_installation_file, true)) {
        dbgWarning(D_ORCHESTRATOR)
            << "Failed to recover from current installation package,"
            << " trying to use backup package. Current package: "
            << current_installation_file;
        if (!installPackage(package_name, backup_installation_file, true)) {
            dbgWarning(D_ORCHESTRATOR)
                << "Failed to recover from backup installation package. Backup package: "
                << backup_installation_file;
        } else {
            dbgInfo(D_ORCHESTRATOR)
                << "Installation of the backup package succeeded. Backup package: "
                << backup_installation_file;
        }
    } else {
        dbgInfo(D_ORCHESTRATOR)
            << "Installation of the latest package succeeded. Current package: "
            << current_installation_file;
    }
}

bool
PackageHandler::Impl::uninstallPackage(
    const string &package_name,
    const string &package_path,
    const string &install_file_path) const
{
    I_OrchestrationTools *orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<PackageHandler>();
    if (!orchestration_tools->doesFileExist(install_file_path)) {
        dbgWarning(D_ORCHESTRATOR) << "Installation file does not exist. File: " << install_file_path;
        return false;
    }

    string watchdog_path = getConfigurationWithDefault<string>(
        filesystem_prefix,
        "orchestration",
        "Default Check Point directory"
    ) + "/watchdog/cp-nano-watchdog";
    auto action = packageHandlerActionsToString(PackageHandlerActions::UNREGISTER);
    if (!orchestration_tools->executeCmd(InstallEnvPrefix + watchdog_path + action + package_path)) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to unregister package from watchdog. Package: " << package_name;
        return false;
    }

    if (!setExecutionMode(install_file_path)) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to change package permission. Package: " << package_name;
        return false;
    }

    action = packageHandlerActionsToString(PackageHandlerActions::UNINSTALL);
    if (!orchestration_tools->executeCmd(InstallEnvPrefix + install_file_path + action)) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to uninstall package. Package: " << package_name;
        return false;
    }

    if (!orchestration_tools->removeFile(install_file_path)) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to remove installation package files. Package: " << package_name;
    }

    string backup_ext = getConfigurationWithDefault<string>(
        ".bk",
        "orchestration",
        "Backup file extension"
    );

    if (!orchestration_tools->removeFile(install_file_path + backup_ext)) {
        dbgDebug(D_ORCHESTRATOR) << "Failed to remove backup installation package files. Package: " << package_name;
    }

    dbgInfo(D_ORCHESTRATOR) << "Package was uninstalled successfully. Package: " << package_name;
    return true;
}

bool
PackageHandler::Impl::preInstallPackage(const string &package_name, const string &install_file_path) const
{
    I_OrchestrationTools *orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<PackageHandler>();
    if (!orchestration_tools->doesFileExist(install_file_path)) {
        dbgWarning(D_ORCHESTRATOR) << "Installation file does not exist. File: " << install_file_path;
        return false;
    }

    if (!setExecutionMode(install_file_path)) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to change package permission. Package: " << package_name;
        return false;
    }

    auto action = packageHandlerActionsToString(PackageHandlerActions::PREINSTALL);
    auto cmd_result = orchestration_tools->executeCmd(InstallEnvPrefix + install_file_path + action);
    if (!cmd_result) {
        dbgWarning(D_ORCHESTRATOR) << "Failed during pre installation test. Package: " << package_name;
        return false;
    }

    dbgInfo(D_ORCHESTRATOR) << "Pre installation test passed successfully. Package: " << package_name;
    return true;
}

bool
PackageHandler::Impl::postInstallPackage(const string &package_name, const string &install_file_path) const
{
    I_OrchestrationTools *orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<PackageHandler>();
    if (!orchestration_tools->doesFileExist(install_file_path)) {
        dbgWarning(D_ORCHESTRATOR) << "Installation file does not exist. File: " << install_file_path;
        return false;
    }

    if (!setExecutionMode(install_file_path)) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to change package permission. Package: " << package_name;
        return false;
    }

    auto action = packageHandlerActionsToString(PackageHandlerActions::POSTINSTALL);
    auto cmd_result = orchestration_tools->executeCmd(InstallEnvPrefix + install_file_path + action);
    if (!cmd_result) {
        dbgWarning(D_ORCHESTRATOR) << "Failed during post installation test. Package: " << package_name;
        string backup_extension = getConfigurationWithDefault<string>(".bk", "orchestration", "Backup file extension");
        string packages_dir = getConfigurationWithDefault<string>(
            filesystem_prefix + "/packages",
            "orchestration",
            "Packages directory"
        );
        string current_installation_file = packages_dir + "/" + package_name + "/" + package_name;
        revertPackage(package_name, false, current_installation_file, current_installation_file + backup_extension);
        return false;
    }
    dbgInfo(D_ORCHESTRATOR) << "Post installation test passed successfully. Package: " << package_name;
    return true;
}

bool
PackageHandler::Impl::updateSavedPackage(const string &package_name, const string &install_file_path) const
{
    string packages_dir = getConfigurationWithDefault<string>(
        filesystem_prefix + "/packages",
        "orchestration",
        "Packages directory"
    );
    string backup_extension = getConfigurationWithDefault<string>(".bk", "orchestration", "Backup file extension");
    string temp_extension = getConfigurationWithDefault<string>("_temp", "orchestration", "Temp file extension");
    string current_installation_file = packages_dir + "/" + package_name + "/" + package_name;
    string current_installation_file_backup = current_installation_file + backup_extension;
    string tmp_backup = current_installation_file_backup + temp_extension;

    I_OrchestrationTools *orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<PackageHandler>();
    // Step 1 - save current installation file backup to temporary file.
    orchestration_tools->copyFile(current_installation_file_backup, tmp_backup);
    // Step 2 - save current installation file to the backuop file.
    orchestration_tools->copyFile(current_installation_file, current_installation_file_backup);
    dbgDebug(D_ORCHESTRATOR) << "Saving the installation file. "
        << "From: " << install_file_path << ", "
        << " To: " << current_installation_file;
    // Step 3 - save the new installation file to the saved package.
    if (!orchestration_tools->copyFile(install_file_path, current_installation_file)) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to save installation file. File: " << install_file_path;
        // Step 3.1 - Revet the backup package
        orchestration_tools->copyFile(tmp_backup, current_installation_file_backup);
        return false;
    }
    // Step 4 - remove the current package file
    if (!orchestration_tools->removeFile(install_file_path)) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to remove temporary installation file. File: " << install_file_path;
    }
    // Step 5 - remove the temporary backup file
    orchestration_tools->removeFile(tmp_backup);

    return true;
}

PackageHandler::PackageHandler() : Component("PackageHandler"), pimpl(make_unique<Impl>()) {}

PackageHandler::~PackageHandler() {}
