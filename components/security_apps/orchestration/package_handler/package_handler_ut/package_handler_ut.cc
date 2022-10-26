#include "package_handler.h"

#include "cptest.h"
#include "config.h"
#include "config_component.h"
#include "mock/mock_orchestration_tools.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_time_get.h"
#include "mock/mock_shell_cmd.h"

#include <boost/filesystem.hpp>

using namespace std;
using namespace testing;

class PackageHandlerTest : public Test
{
public:
    PackageHandlerTest()
            :
        package_dir("/tmp/packages"),
        backup_ext(".bk")
    {
        setConfiguration<string>(package_dir, "orchestration", "Packages directory");
        setConfiguration<string>(backup_ext, "orchestration", "Backup file extension");
        setConfiguration<string>("/tmp", "orchestration", "Default Check Point directory");

        writeFile("#!/bin/bash\necho \"bb\"\nexit 1", "/tmp/bad.sh");
        writeFile("#!/bin/bash\necho \"bb\"", "/tmp/packages/good/good");
        writeFile("#!/bin/bash\necho \"bb\"", "/tmp/good.sh");
        writeFile("#!/bin/bash\necho \"bb\"", "/tmp/packages/a/a");
        package_handler.init();
    }

    ~PackageHandlerTest()
    {
        namespace fs = boost::filesystem;
        fs::path path_to_clean(package_dir);
        if (fs::is_directory(path_to_clean)) {
            for (fs::directory_iterator iter(path_to_clean); iter != fs::directory_iterator(); ++iter) {
                fs::remove_all(iter->path());
            }
            fs::remove_all(package_dir);
        }
    }

    void
    preload()
    {
        package_handler.preload();
    }

    bool
    writeFile(const string &text, const string &path) const
    {
        if (path.find('/') != string::npos) {
            try {
                string dir_path = path.substr(0, path.find_last_of('/'));
                boost::filesystem::create_directories(dir_path);
            } catch (const boost::filesystem::filesystem_error& e) {
                return false;
            }
        }
        try {
            ofstream fout(path);
            fout << text;
            return true;
        } catch (const boost::filesystem::filesystem_error& e) {
        }
        return false;
    }

    string package_dir;
    string backup_ext;
    ::Environment env;
    ConfigComponent config;
    NiceMock<MockOrchestrationTools> mock_orchestration_tools;
    PackageHandler package_handler;
    I_PackageHandler *i_package_handler = Singleton::Consume<I_PackageHandler>::from(package_handler);
    NiceMock<MockMainLoop> mock_mainloop;
    NiceMock<MockTimeGet> mock_timer;
    StrictMock<MockShellCmd> mock_shell;
};

TEST_F(PackageHandlerTest, doNothing)
{
}

TEST_F(PackageHandlerTest, registerExpectedConfig)
{
    env.preload();
    env.init();

    preload();
    string config_json =
        "{\n"
        "    \"orchestration\": {\n"
        "        \"Debug mode\": [\n"
        "            {\n"
        "                \"value\": true\n"
        "            }\n"
        "        ]\n"
        "    }\n"
        "}";

    istringstream string_stream(config_json);
    Singleton::Consume<Config::I_Config>::from(config)->loadConfiguration(string_stream);
    EXPECT_THAT(getConfiguration<bool>("orchestration", "Debug mode"), IsValue(true));
    env.fini();
}

TEST_F(PackageHandlerTest, useAdditionalFlags)
{
    env.preload();
    env.init();
    preload();
    registerExpectedConfiguration<string>("orchestration", "Packages directory");
    registerExpectedConfiguration<string>("orchestration", "Backup file extension");
    registerExpectedConfiguration<string>("orchestration", "Default Check Point directory");

    string config_json =
        "{\n"
        "    \"orchestration\": {\n"
        "        \"additional flags\": [\n"
        "            {\n"
        "                \"flags\": [\n"
        "                    \"--flag1\",\n"
        "                    \"--flag2\"\n"
        "                ]\n"
        "            }\n"
        "        ],\n"
        "        \"Packages directory\": [ { \"value\": \"" + package_dir + "\"}],\n"
        "        \"Backup file extension\": [ { \"value\": \"" + backup_ext + "\"}],\n"
        "        \"Default Check Point directory\": [ { \"value\": \"/tmp\"}]"
        "    }\n"
        "}";
    istringstream string_stream(config_json);
    Singleton::Consume<Config::I_Config>::from(config)->loadConfiguration(string_stream);

    string script_path = "/tmp/good.sh";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(script_path)).WillOnce(Return(true));
    string package_file = package_dir + "/a/a";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(package_file)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(package_file, package_file + backup_ext)).WillOnce(Return(true));

    string install_command = script_path + " --install --flag1 --flag2";
    EXPECT_CALL(mock_orchestration_tools, executeCmd(install_command)).WillOnce(Return(true));
    EXPECT_TRUE(i_package_handler->installPackage("a", script_path, false));

    env.fini();
}

TEST_F(PackageHandlerTest, fileNotExist)
{
    EXPECT_CALL(mock_orchestration_tools, doesFileExist("test.json")).WillOnce(Return(false));
    EXPECT_NE(true, i_package_handler->installPackage("", "test.json", false));
}

TEST_F(PackageHandlerTest, goodInstall)
{
    string script_path = "/tmp/good.sh";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(script_path)).WillOnce(Return(true));
    string package_file = package_dir + "/a/a";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(package_file)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(package_file, package_file + backup_ext)).WillOnce(Return(true));

    string command = script_path + " --install";
    EXPECT_CALL(mock_orchestration_tools, executeCmd(command)).WillOnce(Return(true));
    EXPECT_TRUE(i_package_handler->installPackage("a", script_path, false));
}

TEST_F(PackageHandlerTest, badInstall)
{
    string package_name = "a";
    string package_file = package_dir + "/" + package_name + "/" + package_name;
    string script_path = "/tmp/bad.sh";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(script_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(package_file)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(package_file + backup_ext)).WillOnce(Return(false));
    string command = script_path + " --install";
    EXPECT_CALL(mock_orchestration_tools, executeCmd(command)).WillOnce(Return(false));
    EXPECT_FALSE(i_package_handler->installPackage(package_name, script_path, false));
}

TEST_F(PackageHandlerTest, orcInstallErrorWhileCopyCurrent)
{
    string script_path = "/tmp/good.sh";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(script_path)).WillOnce(Return(true));
    string package_file = package_dir + "/a/a";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(package_file)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(package_file, package_file + backup_ext)).WillOnce(Return(false));

    string command = script_path + " --install";
    EXPECT_CALL(mock_orchestration_tools, executeCmd(command)).WillOnce(Return(true));
    EXPECT_FALSE(i_package_handler->installPackage("a", script_path, false));
}

TEST_F(PackageHandlerTest, orcInstallErrorWhileRemovingNew)
{
    string script_path = "/tmp/good.sh";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(script_path)).WillOnce(Return(true));
    string package_file = package_dir + "/a/a";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(package_file)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(package_file, package_file + backup_ext)).WillOnce(Return(true));

    string command = script_path + " --install";
    EXPECT_CALL(mock_orchestration_tools, executeCmd(command)).WillOnce(Return(true));
    EXPECT_TRUE(i_package_handler->installPackage("a", script_path, false));
}
TEST_F(PackageHandlerTest, badInstallAndRecovery)
{
    string package_name = "a";
    string package_file = package_dir + "/" + package_name + "/" + package_name;
    string script_path = "/tmp/bad.sh";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(script_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(package_file)).WillOnce(Return(true));

    string command = script_path + " --install";
    EXPECT_CALL(mock_orchestration_tools, executeCmd(command)).WillOnce(Return(false));

    command = package_file + " --install";
    EXPECT_CALL(mock_orchestration_tools, executeCmd(command)).WillOnce(Return(true));

    EXPECT_FALSE(i_package_handler->installPackage(package_name, script_path, false));
}

TEST_F(PackageHandlerTest, badOrcInstallAndRecoveryWithDefualValuesChange)
{
    setConfiguration<string>("good", "orchestration", "Service name");
    string manifest_file_path = getConfigurationWithDefault<string>("/etc/cp/conf/manifest.json",
                                    "orchestration", "Manifest file path");
    string temp_ext = getConfigurationWithDefault<string>("_temp", "orchestration", "Temp file extension");
    string temp_manifest_file = manifest_file_path + temp_ext;
    string package_file = package_dir + "/good/good";

    EXPECT_CALL(mock_orchestration_tools, doesFileExist("/tmp/bad.sh")).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(package_file)).WillOnce(Return(true));

    string command = "/tmp/bad.sh --install";
    EXPECT_CALL(mock_orchestration_tools, executeCmd(command)).WillOnce(Return(false));

    command = package_file + " --install";
    EXPECT_CALL(mock_orchestration_tools, executeCmd(command)).WillOnce(Return(true));

    EXPECT_FALSE(i_package_handler->installPackage("good", "/tmp/bad.sh", false));
}

TEST_F(PackageHandlerTest, shouldInstall)
{
    string old_script_path = "/tmp/packages/my-script/my-script";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(old_script_path)).WillOnce(Return(true));
    string new_script_path = "/tmp/new-script.sh";
    string version_command = " --version";
    EXPECT_CALL(mock_shell, getExecOutput(old_script_path + version_command, 5000, _)).WillOnce(Return(string("a")));
    EXPECT_CALL(mock_shell, getExecOutput(new_script_path + version_command, 5000, _)).WillOnce(Return(string("b")));

    EXPECT_TRUE(i_package_handler->shouldInstallPackage("my-script", new_script_path));

    EXPECT_CALL(mock_orchestration_tools, doesFileExist(old_script_path)).WillOnce(Return(false));
    EXPECT_TRUE(i_package_handler->shouldInstallPackage("my-script", new_script_path));

    EXPECT_CALL(mock_orchestration_tools, doesFileExist(old_script_path)).WillOnce(Return(true));
    EXPECT_CALL(
        mock_shell,
        getExecOutput(old_script_path + version_command, 5000, _)
    ).WillOnce(Return(Maybe<string>(genError("Failed"))));
    EXPECT_CALL(mock_shell, getExecOutput(new_script_path + version_command, 5000, _)).WillOnce(Return(string("a")));
    EXPECT_TRUE(i_package_handler->shouldInstallPackage("my-script", new_script_path));
}

TEST_F(PackageHandlerTest, shouldNotInstall)
{
    string old_script_path = "/tmp/packages/my-script/my-script";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(old_script_path)).WillOnce(Return(true));
    string version_command = " --version";
    EXPECT_CALL(mock_shell, getExecOutput(old_script_path + version_command, 5000, _)).WillOnce(Return(string("a")));
    string new_script_path = "/tmp/new-script.sh";
    EXPECT_CALL(mock_shell, getExecOutput(new_script_path + version_command, 5000, _)).WillOnce(Return(string("a")));
    EXPECT_FALSE(i_package_handler->shouldInstallPackage("my-script", new_script_path));
}

TEST_F(PackageHandlerTest, badPreInstall)
{
    string script_path = "/tmp/bad.sh";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(script_path)).WillOnce(Return(false));
    EXPECT_FALSE(i_package_handler->preInstallPackage("a", script_path));

    EXPECT_CALL(mock_orchestration_tools, doesFileExist(script_path)).WillOnce(Return(true));
    string command = script_path + " --pre_install_test";
    EXPECT_CALL(mock_orchestration_tools, executeCmd(command)).WillOnce(Return(false));
    EXPECT_FALSE(i_package_handler->preInstallPackage("a", script_path));
}

TEST_F(PackageHandlerTest, goodPreInstall)
{
    string script_path = "/tmp/good.sh";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(script_path)).WillOnce(Return(true));
    string command = script_path + " --pre_install_test";
    EXPECT_CALL(mock_orchestration_tools, executeCmd(command)).WillOnce(Return(true));
    EXPECT_TRUE(i_package_handler->preInstallPackage("a", script_path));
}

TEST_F(PackageHandlerTest, badPostInstall)
{
    string script_path = "/tmp/bad.sh";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(script_path)).WillOnce(Return(false));
    EXPECT_FALSE(i_package_handler->postInstallPackage("a", script_path));

    string package_file = package_dir + "/a/a";
    string command = script_path + " --post_install_test";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(script_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, executeCmd(command)).WillOnce(Return(false));

    EXPECT_CALL(mock_orchestration_tools, doesFileExist(package_file)).WillOnce(Return(true));
    command = package_file + " --install";
    EXPECT_CALL(mock_orchestration_tools, executeCmd(command)).WillOnce(Return(true));

    EXPECT_FALSE(i_package_handler->postInstallPackage("a", script_path));
}

TEST_F(PackageHandlerTest, goodPostInstall)
{
    string script_path = "/tmp/good.sh";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(script_path)).WillOnce(Return(true));
    string package_file = package_dir + "/a/a";
    string command = script_path + " --post_install_test";
    EXPECT_CALL(mock_orchestration_tools, executeCmd(command)).WillOnce(Return(true));
    EXPECT_TRUE(i_package_handler->postInstallPackage("a", script_path));
}

TEST_F(PackageHandlerTest, badUninstall)
{
    string script_path = "/tmp/good.sh";
    string watchdog_dir = "/tmp/watchdog";
    string watchdog_path = watchdog_dir + "/cp-nano-watchdog";
    string package_file = package_dir + "/a/a";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(script_path)).WillOnce(Return(false));
    EXPECT_FALSE(i_package_handler->uninstallPackage("a", package_file, script_path));

    string command = watchdog_path + " --un-register " + package_file;
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(script_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, executeCmd(command)).WillOnce(Return(false));
    EXPECT_FALSE(i_package_handler->uninstallPackage("a", package_file, script_path));

    EXPECT_CALL(mock_orchestration_tools, doesFileExist(script_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, executeCmd(command)).WillOnce(Return(true));
    command = script_path + " --uninstall";
    EXPECT_CALL(mock_orchestration_tools, executeCmd(command)).WillOnce(Return(false));
    EXPECT_FALSE(i_package_handler->uninstallPackage("a", package_file, script_path));
}

TEST_F(PackageHandlerTest, goodUninstall)
{
    string script_path = "/tmp/good.sh";
    string watchdog_dir = "/tmp/watchdog";
    string watchdog_path = watchdog_dir + "/cp-nano-watchdog";
    string package_file = package_dir + "/a/a";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(script_path)).WillOnce(Return(true));

    string command = watchdog_path + " --un-register " + package_file;
    EXPECT_CALL(mock_orchestration_tools, executeCmd(command)).WillOnce(Return(true));

    command = script_path + " --uninstall";
    EXPECT_CALL(mock_orchestration_tools, executeCmd(command)).WillOnce(Return(true));
    EXPECT_TRUE(i_package_handler->uninstallPackage("a", package_file, script_path));
}

TEST_F(PackageHandlerTest, badupdateSavedPackage)
{
    string script_path = "/tmp/good.sh";
    string package_file = package_dir + "/a/a";
    string package_file_backup = package_dir + "/a/a.bk";
    string package_file_backup_temp = package_dir + "/a/a.bk_temp";
    EXPECT_CALL(mock_orchestration_tools,
        copyFile(package_file_backup, package_file_backup_temp)).Times(2).WillRepeatedly(Return(false));
    EXPECT_CALL(mock_orchestration_tools,
        copyFile(package_file, package_file_backup)).Times(2).WillRepeatedly(Return(false));

    EXPECT_CALL(mock_orchestration_tools, copyFile(script_path, package_file)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools,
        copyFile(package_file_backup_temp, package_file_backup)).WillOnce(Return(false));
    EXPECT_FALSE(i_package_handler->updateSavedPackage("a", script_path));

    EXPECT_CALL(mock_orchestration_tools, copyFile(script_path, package_file)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, removeFile(script_path)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, removeFile(package_file_backup_temp)).WillOnce(Return(false));
    EXPECT_TRUE(i_package_handler->updateSavedPackage("a", script_path));
}

TEST_F(PackageHandlerTest, goodupdateSavedPackage)
{
    string script_path = "/tmp/good.sh";
    string package_file = package_dir + "/a/a";
    string package_file_backup = package_dir + "/a/a.bk";
    string package_file_backup_temp = package_dir + "/a/a.bk_temp";
    EXPECT_CALL(mock_orchestration_tools,
        copyFile(package_file_backup, package_file_backup_temp)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, copyFile(package_file, package_file_backup)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, copyFile(script_path, package_file)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, removeFile(script_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, removeFile(package_file_backup_temp)).WillOnce(Return(true));

    EXPECT_TRUE(i_package_handler->updateSavedPackage("a", script_path));
}
