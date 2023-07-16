#include "manifest_controller.h"

#include <vector>

#include "cptest.h"
#include "orchestration_tools.h"
#include "config.h"
#include "config_component.h"
#include "mock/mock_package_handler.h"
#include "mock/mock_downloader.h"
#include "mock/mock_orchestration_tools.h"
#include "mock/mock_orchestration_status.h"
#include "mock/mock_logging.h"
#include "environment.h"
#include "mock/mock_shell_cmd.h"
#include "agent_details.h"
#include "mock/mock_time_get.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_agent_details.h"
#include "mock/mock_details_resolver.h"

using namespace std;
using namespace testing;

// Loading for multimap<string, Package>
template <class Archive, class C, class A,
        cereal::traits::EnableIf<cereal::traits::is_text_archive<Archive>::value> = cereal::traits::sfinae>
inline void
load(Archive &ar, map<string, Package, C, A> &packages)
{
    packages.clear();
    auto hint = packages.begin();
    while (true)
    {
        try {
            Package value;
            ar(value);
            hint = packages.emplace_hint(hint, move(value.getName()), move(Package(value)));
        } catch (const cereal::Exception &) {
            break;
        }
    }
}

class ManifestControllerTest : public Test
{
public:
    ManifestControllerTest()
    {
        env.preload();
        env.init();
        i_env = Singleton::Consume<I_Environment>::from(env);
        i_env->startNewTrace();
        Debug::setUnitTestFlag(D_ORCHESTRATOR, Debug::DebugLevel::TRACE);
        const string ignore_packages_file = "/etc/cp/conf/ignore-packages.txt";
        EXPECT_CALL(mock_orchestration_tools, doesFileExist(ignore_packages_file)).WillOnce(Return(false));
        manifest_controller.init();
        manifest_file_path = getConfigurationWithDefault<string>(
            "/etc/cp/conf/manifest.json",
            "orchestration",
            "Manifest file path"
        );
        corrupted_file_list = getConfigurationWithDefault<string>(
            "/etc/cp/conf/corrupted_packages.json",
            "orchestration",
            "Manifest corrupted files path"
        );
        temp_ext = getConfigurationWithDefault<string>("_temp", "orchestration", "Temp file extension");
        backup_ext = getConfigurationWithDefault<string>(".bk", "orchestration", "Backup file extension");
        file_name = "new_manifest.json";
        packages_dir = getConfigurationWithDefault<string>("/etc/cp/packages", "orchestration", "Packages directory");
        orch_service_name = getConfigurationWithDefault<string>("orchestration", "orchestration", "Service name");

        EXPECT_CALL(
            mock_shell_cmd,
            getExecOutput("cpprod_util CPPROD_IsConfigured CPwaap", _, _)
        ).WillRepeatedly(Return(string("1")));
    }

    ~ManifestControllerTest()
    {
        i_env->finishSpan();
        i_env->finishTrace();
        env.fini();
    }

    void load(string &manifest, map<string, Package> &ret)
    {
        std::stringstream os(manifest);
        cereal::JSONInputArchive archive_in(os);
        archive_in(ret);
    }

    string manifest_file_path;
    string corrupted_file_list;
    string temp_ext;
    string backup_ext;
    string file_name = "new_manifest.json";
    string packages_dir;
    string orch_service_name;
    string old_manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "           \"require\": []"
        "       }"
        "   ]"
        "}";

    map<string, Package> new_services;
    map<string, Package> old_services;
    map<string, Package> corrupted_packages;

    NiceMock<MockTimeGet> mock_time_get;
    NiceMock<MockMainLoop> mock_mainloop;
    ::Environment env;
    ConfigComponent config;
    I_Environment *i_env;
    AgentDetails agent_details;

    NiceMock<MockLogging> mock_log;
    StrictMock<MockPackageHandler> mock_package_handler;
    StrictMock<MockDownloader> mock_downloader;
    StrictMock<MockOrchestrationTools> mock_orchestration_tools;
    StrictMock<MockOrchestrationStatus> mock_status;
    StrictMock<MockDetailsResolver> mock_details_resolver;
    NiceMock<MockShellCmd> mock_shell_cmd;
    ManifestController manifest_controller;
    I_ManifestController *i_manifest_controller = Singleton::Consume<I_ManifestController>::from(manifest_controller);
};

TEST_F(ManifestControllerTest, constructorTest)
{
}

TEST_F(ManifestControllerTest, createNewManifest)
{
    new_services.clear();
    old_services.clear();

    string manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"my\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    //mock_downloader
    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/my.sh",
            "a58bbab8020b0e6d08568714b5e582a3adf9c805",
            Package::ChecksumTypes::SHA1,
            "my"
        )
    ).WillOnce(Return(string("/tmp/temp_file")));

    //mock_package_handler
    EXPECT_CALL(mock_package_handler, shouldInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, preInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, installPackage("my", "/tmp/temp_file", _)).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, postInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, updateSavedPackage("my", "/tmp/temp_file")).WillOnce(Return(true));

    load(manifest, new_services);
    load(old_manifest, old_services);

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(corrupted_file_list))
        .WillOnce(Return(corrupted_packages));

    EXPECT_CALL(mock_orchestration_tools, doesFileExist(manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist("/etc/cp/packages/my/my")).Times(2).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, copyFile(manifest_file_path, "/etc/cp/conf/manifest.json.bk"))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, isNonEmptyFile(manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, removeFile(file_name)).WillOnce(Return(true));
    EXPECT_TRUE(i_manifest_controller->updateManifest(file_name));
}

TEST_F(ManifestControllerTest, badChecksum)
{
    new_services.clear();
    old_services.clear();
    string manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"my\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d0aa8568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    //mock_downloader
    Maybe<string> err(genError("Empty"));
    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/my.sh",
            "a58bbab8020b0e6d0aa8568714b5e582a3adf9c805",
            Package::ChecksumTypes::SHA1,
            "my"
        )
    ).WillOnce(Return(err));

    //mock_orchestration_tools
    load(manifest, new_services);
    load(old_manifest, old_services);

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools,
                loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    EXPECT_CALL(mock_orchestration_tools,
                loadPackagesFromJson(corrupted_file_list)).WillOnce(Return(corrupted_packages));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist("/etc/cp/packages/my/my")).WillOnce(Return(false));

    string hostname = "hostname";
    string empty_err;
    EXPECT_CALL(mock_status, getManifestError()).WillOnce(ReturnRef(empty_err));
    EXPECT_CALL(mock_details_resolver, getHostname()).WillOnce(Return( Maybe<string>(hostname)));
    EXPECT_CALL(
        mock_status,
        setFieldStatus(OrchestrationStatusFieldType::MANIFEST, OrchestrationStatusResult::FAILED, _)
    );
    EXPECT_FALSE(i_manifest_controller->updateManifest(file_name));
}

TEST_F(ManifestControllerTest, updateManifest)
{
    new_services.clear();
    old_services.clear();
    string manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"name\": \"my\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";
    //mock_downloader
    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/my.sh",
            "a58bbab8020b0e6d08568714b5e582a3adf9c805",
            Package::ChecksumTypes::SHA1,
            "my"
        )
    ).WillOnce(Return(string("/tmp/temp_file")));

    //mock_package_handler
    EXPECT_CALL(mock_package_handler, shouldInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, preInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, installPackage("my", "/tmp/temp_file", _)).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, postInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, updateSavedPackage("my", "/tmp/temp_file")).WillOnce(Return(true));

    load(manifest, new_services);
    load(old_manifest, old_services);

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    EXPECT_CALL(mock_orchestration_tools,
            loadPackagesFromJson(corrupted_file_list)).Times(2).WillRepeatedly(Return(corrupted_packages));

    EXPECT_CALL(mock_orchestration_tools, doesFileExist(manifest_file_path)).Times(2).WillRepeatedly(Return(true));
    EXPECT_CALL(
        mock_orchestration_tools,
        doesFileExist("/etc/cp/packages/my/my")
    ).Times(4).WillRepeatedly(Return(false));
    EXPECT_CALL(mock_orchestration_tools,
                copyFile(manifest_file_path, "/etc/cp/conf/manifest.json.bk")).Times(2).WillRepeatedly(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, manifest_file_path))
                .Times(2).WillRepeatedly(Return(true));
    EXPECT_CALL(mock_orchestration_tools, isNonEmptyFile(manifest_file_path)).Times(2).WillRepeatedly(Return(true));
    EXPECT_CALL(mock_orchestration_tools, removeFile(file_name)).Times(2).WillRepeatedly(Return(true));

    EXPECT_TRUE(i_manifest_controller->updateManifest(file_name));

    manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"name\": \"my\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"77ecfeb6d5ec73a596ff406713f4f5d1f233adb6\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/my.sh",
            "77ecfeb6d5ec73a596ff406713f4f5d1f233adb6",
            Package::ChecksumTypes::SHA1,
            "my"
        )
    ).WillOnce(Return(string("/tmp/temp_file")));

    //mock_package_handler
    EXPECT_CALL(mock_package_handler, shouldInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, preInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, installPackage("my", "/tmp/temp_file", _)).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, postInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, updateSavedPackage("my", "/tmp/temp_file")).WillOnce(Return(true));

    //mock_orchestration_tools
    load(manifest, new_services);

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools,
                loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    EXPECT_TRUE(i_manifest_controller->updateManifest(file_name));
}

TEST_F(ManifestControllerTest, selfUpdate)
{
    new_services.clear();
    old_services.clear();
    string manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/my.sh",
            "a58bbab8020b0e6d08568714b5e582a3adf9c805",
            Package::ChecksumTypes::SHA1,
            "orchestration"
        )
    ).WillOnce(Return(string("/tmp/temp_file")));
    string temp_orc_file = "/etc/cp/packages/orchestration/orchestration_temp";
    EXPECT_CALL(mock_status, writeStatusToFile());
    EXPECT_CALL(mock_package_handler, preInstallPackage(orch_service_name, temp_orc_file)).WillOnce(Return(true));
    EXPECT_CALL(
        mock_package_handler,
        installPackage(orch_service_name, temp_orc_file, _)
    ).WillOnce(Return(true));
    EXPECT_CALL(
        mock_orchestration_tools,
        loadPackagesFromJson(corrupted_file_list)).WillOnce(Return(corrupted_packages)
    );

    load(manifest, new_services);

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    string temp_manifest_path = manifest_file_path + temp_ext;
    EXPECT_CALL(mock_orchestration_tools, packagesToJsonFile(new_services, temp_manifest_path)).WillOnce(Return(true));

    string path = packages_dir + "/" + orch_service_name + "/" +
                            orch_service_name;
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(path)).Times(2).WillOnce(Return(false));

    EXPECT_CALL(mock_orchestration_tools, copyFile("/tmp/temp_file", path +
                                                    temp_ext)).WillOnce(Return(true));
    EXPECT_TRUE(i_manifest_controller->updateManifest(file_name));
}

TEST_F(ManifestControllerTest, loadAfterNoSelfUpdate)
{
    string temp_path = manifest_file_path + temp_ext;
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(temp_path)).WillOnce(Return(false));
    EXPECT_TRUE(i_manifest_controller->loadAfterSelfUpdate());
}

TEST_F(ManifestControllerTest, failureWhileLoadAfterSelfUpdate)
{
    string temp_path = manifest_file_path + temp_ext;
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(temp_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(manifest_file_path, manifest_file_path
                                                    + backup_ext)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(temp_path, manifest_file_path)).WillOnce(Return(false));
    string path = packages_dir + "/" + orch_service_name + "/" + orch_service_name + temp_ext;
    EXPECT_CALL(mock_package_handler, postInstallPackage(orch_service_name, path)).WillOnce(Return(true));

    EXPECT_FALSE(i_manifest_controller->loadAfterSelfUpdate());
}

TEST_F(ManifestControllerTest, successLoadAfteSelfUpdate)
{
    string temp_path = manifest_file_path + temp_ext;
    string current_file = packages_dir + "/" + orch_service_name + "/" + orch_service_name;
    string backup_file = current_file + backup_ext;
    string backup_temp_file = backup_file + temp_ext;
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(temp_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(manifest_file_path, manifest_file_path
                                                    + backup_ext)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(temp_path, manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, isNonEmptyFile(manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, removeFile(temp_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, postInstallPackage(orch_service_name, current_file + temp_ext))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, updateSavedPackage(orch_service_name, current_file + temp_ext))
        .WillOnce(Return(true));

    EXPECT_TRUE(i_manifest_controller->loadAfterSelfUpdate());
}

TEST_F(ManifestControllerTest, updateWhileErrorPackageExist)
{
    new_services.clear();
    old_services.clear();
    string manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"name\": \"my\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    string corrupted_packages_manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"name\": \"my\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    load(manifest, new_services);
    load(old_manifest, old_services);
    load(corrupted_packages_manifest, corrupted_packages);

    EXPECT_CALL(mock_orchestration_tools,
        loadPackagesFromJson(corrupted_file_list)).WillOnce(Return(corrupted_packages));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    EXPECT_FALSE(i_manifest_controller->updateManifest(file_name));
}

TEST_F(ManifestControllerTest, removeCurrentErrorPackage)
{
    new_services.clear();
    old_services.clear();
    string manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"name\": \"my\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    string corrupted_packages_manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"name\": \"my\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d0000000000000\","
        "           \"package-type\": \"service\","
        "           \"require\": []"
        "       }"
        "   ]"
        "}";

    load(manifest, new_services);
    load(old_manifest, old_services);
    load(corrupted_packages_manifest, corrupted_packages);

    //mock_downloader
    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/my.sh",
            "a58bbab8020b0e6d08568714b5e582a3adf9c805",
            Package::ChecksumTypes::SHA1,
            "my"
        )
    ).WillOnce(Return(string("/tmp/temp_file")));
    //mock_package_handler
    EXPECT_CALL(mock_package_handler, shouldInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, preInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, installPackage("my", "/tmp/temp_file", _)).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, postInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, updateSavedPackage("my", "/tmp/temp_file")).WillOnce(Return(true));

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    EXPECT_CALL(mock_orchestration_tools,
                loadPackagesFromJson(corrupted_file_list)).WillOnce(Return(corrupted_packages));

    EXPECT_CALL(mock_orchestration_tools, doesFileExist(manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist("/etc/cp/packages/my/my")).Times(2).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, copyFile(manifest_file_path, "/etc/cp/conf/manifest.json.bk"))
                .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, isNonEmptyFile(manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, removeFile(file_name)).WillOnce(Return(true));

    corrupted_packages.clear();
    EXPECT_CALL(mock_orchestration_tools, packagesToJsonFile(corrupted_packages,
                                                            corrupted_file_list)).WillOnce(Return(true));
    EXPECT_TRUE(i_manifest_controller->updateManifest(file_name));
}

TEST_F(ManifestControllerTest, selfUpdateWithOldCopy)
{
    new_services.clear();
    old_services.clear();
    corrupted_packages.clear();

    string manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/my.sh",
            "a58bbab8020b0e6d08568714b5e582a3adf9c805",
            Package::ChecksumTypes::SHA1,
            "orchestration"
        )
    ).WillOnce(Return(string("/tmp/temp_file")));
    string temp_orc_file = "/etc/cp/packages/orchestration/orchestration_temp";
    EXPECT_CALL(mock_package_handler, preInstallPackage(orch_service_name, temp_orc_file)).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, installPackage(orch_service_name, temp_orc_file, _)).WillOnce(Return(true));
    EXPECT_CALL(mock_status, writeStatusToFile());
    load(manifest, new_services);

    EXPECT_CALL(mock_orchestration_tools,
            loadPackagesFromJson(corrupted_file_list)).WillOnce(Return(corrupted_packages));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    string temp_manifest_path = manifest_file_path + temp_ext;
    EXPECT_CALL(mock_orchestration_tools, packagesToJsonFile(new_services, temp_manifest_path)).WillOnce(Return(true));

    string path = packages_dir + "/" + orch_service_name + "/" +
                            orch_service_name;
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(path)).WillOnce(Return(false)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(path, path + backup_ext + temp_ext)).WillOnce(Return(true));

    EXPECT_CALL(mock_orchestration_tools, copyFile("/tmp/temp_file", path +
                                                    temp_ext)).WillOnce(Return(true));
    EXPECT_TRUE(i_manifest_controller->updateManifest(file_name));
}

TEST_F(ManifestControllerTest, selfUpdateWithOldCopyWithError)
{
    new_services.clear();
    old_services.clear();
    corrupted_packages.clear();

    string manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/my.sh",
            "a58bbab8020b0e6d08568714b5e582a3adf9c805",
            Package::ChecksumTypes::SHA1,
            "orchestration"
        )
    ).WillOnce(Return(string("/tmp/temp_file")));
    EXPECT_CALL(mock_status, writeStatusToFile());
    string hostname = "hostname";
    string empty_err;
    EXPECT_CALL(mock_status, getManifestError()).WillOnce(ReturnRef(empty_err));
    EXPECT_CALL(
        mock_status,
        setFieldStatus(OrchestrationStatusFieldType::MANIFEST, OrchestrationStatusResult::FAILED, _)
    );
    load(manifest, new_services);

    EXPECT_CALL(mock_orchestration_tools,
        loadPackagesFromJson(corrupted_file_list)).WillOnce(Return(corrupted_packages));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    string temp_manifest_path = manifest_file_path + temp_ext;
    EXPECT_CALL(mock_orchestration_tools, packagesToJsonFile(new_services, temp_manifest_path)).WillOnce(Return(true));

    string path = packages_dir + "/" + orch_service_name + "/" +
                            orch_service_name;
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(path)).WillOnce(Return(false)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(path, path + backup_ext + temp_ext)).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, getHostname()).WillOnce(Return(hostname));
    EXPECT_FALSE(i_manifest_controller->updateManifest(file_name));
}

TEST_F(ManifestControllerTest, installAndRemove)
{
    new_services.clear();
    old_services.clear();
    corrupted_packages.clear();
    string manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"name\": \"my\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    //mock_downloader
    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/my.sh",
            "a58bbab8020b0e6d08568714b5e582a3adf9c805",
            Package::ChecksumTypes::SHA1,
            "my"
        )
    ).WillOnce(Return(string("/tmp/temp_file")));

    //mock_package_handler
    EXPECT_CALL(mock_package_handler, shouldInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, preInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, installPackage("my", "/tmp/temp_file", _)).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, postInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, updateSavedPackage("my", "/tmp/temp_file")).WillOnce(Return(true));

    load(manifest, new_services);
    load(old_manifest, old_services);

    EXPECT_CALL(mock_orchestration_tools,
        loadPackagesFromJson(corrupted_file_list)).Times(2).WillRepeatedly(Return(corrupted_packages));

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));

    EXPECT_CALL(mock_orchestration_tools, doesFileExist(manifest_file_path)).Times(2).WillRepeatedly(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist("/etc/cp/packages/my/my")).Times(2).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools,
                copyFile(manifest_file_path, "/etc/cp/conf/manifest.json.bk")).Times(2).WillRepeatedly(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, manifest_file_path))
                .Times(2).WillRepeatedly(Return(true));
    EXPECT_CALL(mock_orchestration_tools, isNonEmptyFile(manifest_file_path)).Times(2).WillRepeatedly(Return(true));
    EXPECT_CALL(mock_orchestration_tools, removeFile(file_name)).Times(2).WillRepeatedly(Return(true));

    EXPECT_TRUE(i_manifest_controller->updateManifest(file_name));

    string new_manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"name\": \"my1\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"77ecfeb6d5ec73a596ff406713f4f5d1f233adb6\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/my.sh",
            "77ecfeb6d5ec73a596ff406713f4f5d1f233adb6",
            Package::ChecksumTypes::SHA1,
            "my1"
        )
    ).WillOnce(Return(string("/tmp/temp_file")));

    // //mock_package_handler
    EXPECT_CALL(mock_package_handler, shouldInstallPackage("my1", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, preInstallPackage("my1", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, installPackage("my1", "/tmp/temp_file", _)).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, postInstallPackage("my1", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, updateSavedPackage("my1", "/tmp/temp_file")).WillOnce(Return(true));

    EXPECT_CALL(mock_orchestration_tools, packagesToJsonFile(old_services, manifest_file_path)).WillOnce(Return(true));
    load(manifest, old_services);
    load(new_manifest, new_services);

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    EXPECT_CALL(mock_package_handler, uninstallPackage("my", "/etc/cp/my/my", "/etc/cp/packages/my/my"))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist("/etc/cp/packages/my1/my1")).Times(2)
        .WillOnce(Return(false));
    EXPECT_TRUE(i_manifest_controller->updateManifest(file_name));
}

TEST_F(ManifestControllerTest, badInstall)
{
    new_services.clear();
    old_services.clear();
    corrupted_packages.clear();
    string manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"name\": \"my\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    //mock_downloader
    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/my.sh",
            "a58bbab8020b0e6d08568714b5e582a3adf9c805",
            Package::ChecksumTypes::SHA1,
            "my"
        )
    ).WillOnce(Return(string("/tmp/temp_file")));

    //mock_package_handler
    EXPECT_CALL(mock_package_handler, shouldInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, preInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, installPackage("my", "/tmp/temp_file", _)).WillOnce(Return(false));


    load(manifest, new_services);
    load(old_manifest, old_services);

    EXPECT_CALL(mock_orchestration_tools,
                loadPackagesFromJson(corrupted_file_list)).WillOnce(Return(corrupted_packages));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist("/etc/cp/packages/my/my")).Times(2).WillOnce(Return(false));

    string hostname = "hostname";
    string empty_err;
    EXPECT_CALL(mock_status, getManifestError()).WillOnce(ReturnRef(empty_err));
    EXPECT_CALL(mock_details_resolver, getHostname()).WillOnce(Return( Maybe<string>(hostname)));
    EXPECT_CALL(
        mock_status,
        setFieldStatus(OrchestrationStatusFieldType::MANIFEST, OrchestrationStatusResult::FAILED, _)
    );

    string corrupted_packages_manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"name\": \"my\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    load(corrupted_packages_manifest, corrupted_packages);
    EXPECT_CALL(mock_orchestration_tools,
        packagesToJsonFile(corrupted_packages, corrupted_file_list)).WillOnce(Return(true));

    EXPECT_FALSE(i_manifest_controller->updateManifest(file_name));
}

TEST_F(ManifestControllerTest, failToDownloadWithselfUpdate)
{
    new_services.clear();
    old_services.clear();
    corrupted_packages.clear();
    string manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    Maybe<string> err(genError("Empty"));
    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/my.sh",
            "a58bbab8020b0e6d08568714b5e582a3adf9c805",
            Package::ChecksumTypes::SHA1,
            "orchestration"
        )
    ).WillOnce(Return(err));


    load(manifest, new_services);

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(corrupted_file_list))
        .WillOnce(Return(corrupted_packages));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    EXPECT_CALL(
        mock_orchestration_tools,
        doesFileExist("/etc/cp/packages/orchestration/orchestration")
    ).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, getHostname()).WillOnce(Return(string("hostname")));
    EXPECT_CALL(
        mock_status,
        setFieldStatus(OrchestrationStatusFieldType::MANIFEST, OrchestrationStatusResult::FAILED, _)
    );
    string not_error;
    EXPECT_CALL(mock_status, getManifestError()).WillOnce(ReturnRef(not_error));
    EXPECT_FALSE(i_manifest_controller->updateManifest(file_name));
}

TEST_F(ManifestControllerTest, requireUpdate)
{
    new_services.clear();
    old_services.clear();
    string manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": [ \"pre_orchestration\" ]"
        "       },"
        "       {"
        "           \"name\": \"pre_orchestration\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c806\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";
    EXPECT_CALL(mock_status, writeStatusToFile());
    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/my.sh",
            "a58bbab8020b0e6d08568714b5e582a3adf9c805",
            Package::ChecksumTypes::SHA1,
            "orchestration"
        )
    ).WillOnce(Return(string("/tmp/temp_file1")));
    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/my.sh",
            "a58bbab8020b0e6d08568714b5e582a3adf9c806",
            Package::ChecksumTypes::SHA1,
            "pre_orchestration"
        )
    ).WillOnce(Return(string("/tmp/temp_file2")));
    string temp_orc_file = "/etc/cp/packages/orchestration/orchestration_temp";
    EXPECT_CALL(mock_package_handler, preInstallPackage(orch_service_name, temp_orc_file))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, installPackage(orch_service_name, temp_orc_file, _))
        .WillOnce(Return(true));

    EXPECT_CALL(
        mock_package_handler,
        shouldInstallPackage("pre_orchestration", "/tmp/temp_file2")
    ).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, preInstallPackage("pre_orchestration", "/tmp/temp_file2"))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, installPackage("pre_orchestration", "/tmp/temp_file2", _))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, postInstallPackage("pre_orchestration", "/tmp/temp_file2"))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, updateSavedPackage("pre_orchestration", "/tmp/temp_file2"))
        .WillOnce(Return(true));


    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(corrupted_file_list))
        .WillOnce(Return(corrupted_packages));

    load(manifest, new_services);

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name))
        .WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path))
        .WillOnce(Return(old_services));
    string temp_manifest_path = manifest_file_path + temp_ext;
    EXPECT_CALL(mock_orchestration_tools, packagesToJsonFile(new_services, temp_manifest_path))
        .WillOnce(Return(true));

    string path = packages_dir + "/" + orch_service_name + "/" +
                            orch_service_name;
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(path)).Times(2).WillOnce(Return(false));
    EXPECT_CALL(
        mock_orchestration_tools,
        doesFileExist("/etc/cp/packages/pre_orchestration/pre_orchestration")
    ).Times(2).WillOnce(Return(true));

    EXPECT_CALL(mock_orchestration_tools, copyFile("/tmp/temp_file1", path + temp_ext))
        .WillOnce(Return(true));
    EXPECT_TRUE(i_manifest_controller->updateManifest(file_name));
}

TEST_F(ManifestControllerTest, sharedObjectNotInstalled)
{
    new_services.clear();
    old_services.clear();
    string manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"name\": \"pre_orchestration\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c806\","
        "           \"package-type\": \"shared objects\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";
    EXPECT_CALL(mock_status, writeStatusToFile());
    load(manifest, new_services);
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    EXPECT_CALL(mock_orchestration_tools,
        loadPackagesFromJson(corrupted_file_list)).WillOnce(Return(corrupted_packages));

    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/my.sh",
            "a58bbab8020b0e6d08568714b5e582a3adf9c805",
            Package::ChecksumTypes::SHA1,
            "orchestration"
        )
    ).WillOnce(Return(string("/tmp/temp_file1")));

    string temp_manifest_path = manifest_file_path + temp_ext;
    string writen_manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    map<string, Package> writen;
    load(writen_manifest, writen);
    EXPECT_CALL(mock_orchestration_tools, packagesToJsonFile(writen, temp_manifest_path)).WillOnce(Return(true));
    string temp_orc_file = "/etc/cp/packages/orchestration/orchestration_temp";

    EXPECT_CALL(mock_package_handler, preInstallPackage(orch_service_name,
                    temp_orc_file)).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, installPackage(orch_service_name,
                    temp_orc_file, _)).WillOnce(Return(true));

    string path = packages_dir + "/" + orch_service_name + "/" +
        orch_service_name;
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(path)).Times(2).WillOnce(Return(false));

    EXPECT_CALL(mock_orchestration_tools, copyFile("/tmp/temp_file1", path +
        temp_ext)).WillOnce(Return(true));
    EXPECT_TRUE(i_manifest_controller->updateManifest(file_name));
}

TEST_F(ManifestControllerTest, requireSharedObjectUpdate)
{
    new_services.clear();
    old_services.clear();
    string manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": [ \"pre_orchestration\" ]"
        "       },"
        "       {"
        "           \"name\": \"pre_orchestration\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c806\","
        "           \"package-type\": \"shared objects\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/my.sh",
            "a58bbab8020b0e6d08568714b5e582a3adf9c805",
            Package::ChecksumTypes::SHA1,
            "orchestration"
        )
    ).WillOnce(Return(string("/tmp/temp_file1")));
    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/my.sh",
            "a58bbab8020b0e6d08568714b5e582a3adf9c806",
            Package::ChecksumTypes::SHA1,
            "pre_orchestration"
        )
    ).WillOnce(Return(string("/tmp/temp_file2")));
    EXPECT_CALL(mock_status, writeStatusToFile());
    string temp_orc_file = "/etc/cp/packages/orchestration/orchestration_temp";
    EXPECT_CALL(mock_package_handler, shouldInstallPackage(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock_package_handler, preInstallPackage(orch_service_name,
        temp_orc_file)).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, installPackage(orch_service_name,
        temp_orc_file, _)).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, installPackage("pre_orchestration",
        "/tmp/temp_file2", _)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools,
        loadPackagesFromJson(corrupted_file_list)).WillOnce(Return(corrupted_packages));

    load(manifest, new_services);

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    string temp_manifest_path = manifest_file_path + temp_ext;
    EXPECT_CALL(mock_orchestration_tools, packagesToJsonFile(new_services, temp_manifest_path)).WillOnce(Return(true));

    string path = packages_dir + "/" + orch_service_name + "/" +
        orch_service_name;
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(path)).Times(2).WillOnce(Return(false));
    EXPECT_CALL(
        mock_orchestration_tools,
        doesFileExist("/etc/cp/packages/pre_orchestration/pre_orchestration")
    ).Times(2).WillOnce(Return(false));

    EXPECT_CALL(mock_orchestration_tools, copyFile("/tmp/temp_file1", path +
        temp_ext)).WillOnce(Return(true));
    EXPECT_TRUE(i_manifest_controller->updateManifest(file_name));
}

TEST_F(ManifestControllerTest, failureOnDownloadSharedObject)
{
    new_services.clear();
    old_services.clear();
    string manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": [ \"pre_orchestration\" ]"
        "       },"
        "       {"
        "           \"name\": \"pre_orchestration\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c806\","
        "           \"package-type\": \"shared objects\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    Maybe<string> err = genError("error");
    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/my.sh",
            "a58bbab8020b0e6d08568714b5e582a3adf9c806",
            Package::ChecksumTypes::SHA1,
            "pre_orchestration"
        )
    ).WillOnce(Return(err));
    EXPECT_CALL(mock_orchestration_tools,
        loadPackagesFromJson(corrupted_file_list)).WillOnce(Return(corrupted_packages));

    load(manifest, new_services);

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    EXPECT_CALL(
        mock_orchestration_tools,
        doesFileExist("/etc/cp/packages/pre_orchestration/pre_orchestration")
    ).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, getHostname()).WillOnce(Return(string("hostname")));
    EXPECT_CALL(
        mock_status,
        setFieldStatus(OrchestrationStatusFieldType::MANIFEST, OrchestrationStatusResult::FAILED, _)
    );
    string not_error;
    EXPECT_CALL(mock_status, getManifestError()).WillOnce(ReturnRef(not_error));

    EXPECT_FALSE(i_manifest_controller->updateManifest(file_name));
}

TEST_F(ManifestControllerTest, multiRequireUpdate)
{
    new_services.clear();
    old_services.clear();
    string manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": [ \"pre_orchestration002\" ]"
        "       },"
        "       {"
        "           \"name\": \"pre_orchestration001\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c806\","
        "           \"package-type\": \"shared objects\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"name\": \"pre_orchestration002\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my2.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c807\","
        "           \"package-type\": \"shared objects\","
        "           \"require\": [ \"pre_orchestration001\" ]"
        "       }"
        "   ]"
        "}";

    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/my.sh",
            "a58bbab8020b0e6d08568714b5e582a3adf9c805",
            Package::ChecksumTypes::SHA1,
            "orchestration"
        )
    ).WillOnce(Return(string("/tmp/temp_file1")));
    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/my.sh",
            "a58bbab8020b0e6d08568714b5e582a3adf9c806",
            Package::ChecksumTypes::SHA1,
            "pre_orchestration001"
        )
    ).WillOnce(Return(string("/tmp/temp_file2")));
    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/my2.sh",
            "a58bbab8020b0e6d08568714b5e582a3adf9c807",
            Package::ChecksumTypes::SHA1,
            "pre_orchestration002"
        )
    ).WillOnce(Return(string("/tmp/temp_file3")));
    EXPECT_CALL(mock_status, writeStatusToFile());
    string temp_orc_file = "/etc/cp/packages/orchestration/orchestration_temp";
    EXPECT_CALL(mock_package_handler, shouldInstallPackage(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock_package_handler, preInstallPackage(orch_service_name,
        temp_orc_file)).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, installPackage(orch_service_name,
        temp_orc_file, _)).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, installPackage("pre_orchestration001",
        "/tmp/temp_file2", _)).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, installPackage("pre_orchestration002",
        "/tmp/temp_file3", _)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools,
        loadPackagesFromJson(corrupted_file_list)).WillOnce(Return(corrupted_packages));

    load(manifest, new_services);

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    string temp_manifest_path = manifest_file_path + temp_ext;
    EXPECT_CALL(mock_orchestration_tools, packagesToJsonFile(new_services, temp_manifest_path)).WillOnce(Return(true));

    string path = packages_dir + "/" + orch_service_name + "/" +
        orch_service_name;
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(path)).Times(2).WillOnce(Return(false));
    EXPECT_CALL(
        mock_orchestration_tools,
        doesFileExist("/etc/cp/packages/pre_orchestration001/pre_orchestration001")
    ).Times(2).WillOnce(Return(false));
    EXPECT_CALL(
        mock_orchestration_tools,
        doesFileExist("/etc/cp/packages/pre_orchestration002/pre_orchestration002")
    ).Times(2).WillOnce(Return(false));

    EXPECT_CALL(mock_orchestration_tools, copyFile("/tmp/temp_file1", path +
        temp_ext)).WillOnce(Return(true));
    EXPECT_TRUE(i_manifest_controller->updateManifest(file_name));
}

TEST_F(ManifestControllerTest, createNewManifestWithUninstallablePackage)
{
    new_services.clear();
    old_services.clear();

    string manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"my\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "           \"require\": []"
        "       },"
        "       {"
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "           \"require\": []"
        "       },"
        "       {"
        "           \"download-path\": \"\","
        "           \"relative-path\": \"\","
        "           \"name\": \"waap\","
        "           \"version\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"\","
        "           \"package-type\": \"service\","
        "           \"status\": false,\n"
        "           \"message\": \"This security app isn't valid for this agent\"\n"
        "       }"
        "   ]"
        "}";

    //mock_downloader
    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/my.sh",
            "a58bbab8020b0e6d08568714b5e582a3adf9c805",
            Package::ChecksumTypes::SHA1,
            "my"
        )
    ).WillOnce(Return(string("/tmp/temp_file")));

    //mock_package_handler
    EXPECT_CALL(mock_package_handler, shouldInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, preInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, installPackage("my", "/tmp/temp_file", _)).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, postInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, updateSavedPackage("my", "/tmp/temp_file")).WillOnce(Return(true));

    load(manifest, new_services);
    load(old_manifest, old_services);

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(corrupted_file_list))
        .WillOnce(Return(corrupted_packages));

    EXPECT_CALL(mock_orchestration_tools, doesFileExist(manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist("/etc/cp/packages/my/my")).Times(2).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, copyFile(manifest_file_path, "/etc/cp/conf/manifest.json.bk"))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, isNonEmptyFile(manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, removeFile(file_name)).WillOnce(Return(true));

    EXPECT_TRUE(i_manifest_controller->updateManifest(file_name));
}

TEST_F(ManifestControllerTest, updateUninstallPackage)
{
    new_services.clear();
    old_services.clear();
    string manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"download-path\": \"\","
        "           \"relative-path\": \"\","
        "           \"name\": \"my\","
        "           \"version\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"\","
        "           \"package-type\": \"service\","
        "           \"status\": false,\n"
        "           \"message\": \"This security app isn't valid for this agent\"\n"
        "       },"
        "       {"
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    load(manifest, new_services);
    load(old_manifest, old_services);

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    EXPECT_CALL(mock_orchestration_tools,
        loadPackagesFromJson(corrupted_file_list)).Times(2).WillRepeatedly(Return(corrupted_packages));

    EXPECT_CALL(mock_orchestration_tools, doesFileExist(manifest_file_path)).Times(2).WillRepeatedly(Return(true));
    EXPECT_CALL(mock_orchestration_tools,
        copyFile(manifest_file_path, "/etc/cp/conf/manifest.json.bk")).Times(2).WillRepeatedly(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, manifest_file_path))
        .Times(2).WillRepeatedly(Return(true));
    EXPECT_CALL(mock_orchestration_tools, isNonEmptyFile(manifest_file_path)).Times(2).WillRepeatedly(Return(true));
    EXPECT_CALL(mock_orchestration_tools, removeFile(file_name)).Times(2).WillRepeatedly(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist("/etc/cp/packages/my/my")).Times(2).WillOnce(Return(true));
    string hostname = "hostname";

    EXPECT_TRUE(i_manifest_controller->updateManifest(file_name));

    manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"name\": \"my\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"77ecfeb6d5ec73a596ff406713f4f5d1f233adb6\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/my.sh",
            "77ecfeb6d5ec73a596ff406713f4f5d1f233adb6",
            Package::ChecksumTypes::SHA1,
            "my"
        )
    ).WillOnce(Return(string("/tmp/temp_file")));

    //mock_package_handler
    EXPECT_CALL(mock_package_handler, shouldInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, preInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, installPackage("my", "/tmp/temp_file", _)).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, postInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, updateSavedPackage("my", "/tmp/temp_file")).WillOnce(Return(true));

    //mock_orchestration_tools
    load(manifest, new_services);

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools,
                loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    EXPECT_TRUE(i_manifest_controller->updateManifest(file_name));
}

class ManifestControllerIgnorePakckgeTest : public Test
{
public:
    ManifestControllerIgnorePakckgeTest()
    {
        env.preload();
        env.init();
        i_env = Singleton::Consume<I_Environment>::from(env);
        i_env->startNewTrace();
        new_services.clear();
        old_services.clear();
    }

    void
    init(const string &ignore_services = "dummy_service")
    {
        const string ignore_packages_file = "/tmp/ignore-packages.txt";
        setConfiguration<string>(ignore_packages_file, "orchestration", "Ignore packages list file path");
        writeIgnoreList(ignore_packages_file, ignore_services);
        EXPECT_CALL(mock_orchestration_tools, doesFileExist(ignore_packages_file)).WillOnce(Return(true));
        manifest_controller.init();
        manifest_file_path = getConfigurationWithDefault<string>(
            "/etc/cp/conf/manifest.json",
            "orchestration",
            "Manifest file path"
        );
        corrupted_file_list = getConfigurationWithDefault<string>(
            "/etc/cp/conf/corrupted_packages.json",
            "orchestration",
            "Manifest corrupted files path"
        );
        temp_ext = getConfigurationWithDefault<string>("_temp", "orchestration", "Temp file extension");
        backup_ext = getConfigurationWithDefault<string>(".bk", "orchestration", "Backup file extension");
        file_name = "new_manifest.json";
        packages_dir = getConfigurationWithDefault<string>("/etc/cp/packages", "orchestration", "Packages directory");
        orch_service_name = getConfigurationWithDefault<string>("orchestration", "orchestration", "Service name");
        EXPECT_CALL(
            mock_shell_cmd,
            getExecOutput("cpprod_util CPPROD_IsConfigured CPwaap", _, _)
        ).WillRepeatedly(Return(string("1")));
    }

    ~ManifestControllerIgnorePakckgeTest()
    {
        remove("/tmp/ignore-packages.txt");
        i_env->finishSpan();
        i_env->finishTrace();
        env.fini();
    }

    void load(string &manifest, map<string, Package> &ret)
    {
        std::stringstream os(manifest);
        cereal::JSONInputArchive archive_in(os);
        archive_in(ret);
    }

    string manifest_file_path;
    string corrupted_file_list;
    string temp_ext;
    string backup_ext;
    string file_name = "new_manifest.json";
    string packages_dir;
    string orch_service_name;
    string old_manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"download-path\": \"http://172.23.92.135/orchestration.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"my\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    NiceMock<MockMainLoop> mock_mainloop;
    NiceMock<MockTimeGet> mock_timer;
    ::Environment env;
    I_Environment *i_env;
    ConfigComponent config;
    AgentDetails agent_details;

    map<string, Package> new_services;
    map<string, Package> old_services;
    map<string, Package> corrupted_packages;

    StrictMock<MockPackageHandler> mock_package_handler;
    StrictMock<MockOrchestrationStatus> mock_status;
    StrictMock<MockDownloader> mock_downloader;
    StrictMock<MockOrchestrationTools> mock_orchestration_tools;
    NiceMock<MockShellCmd> mock_shell_cmd;

    ManifestController manifest_controller;
    I_ManifestController *i_manifest_controller = Singleton::Consume<I_ManifestController>::from(manifest_controller);

private:
    void
    writeIgnoreList(const string &path, const string &packages)
    {
        ofstream ignore_list_file;
        ignore_list_file.open (path);
        ignore_list_file << packages;
        ignore_list_file.close();
    }
};

TEST_F(ManifestControllerIgnorePakckgeTest, constructorTest)
{
}

TEST_F(ManifestControllerIgnorePakckgeTest, initOnly)
{
    init();
}

TEST_F(ManifestControllerIgnorePakckgeTest, addAndUpdateIgnorePackage)
{
    init();

    // Add an ignored package
    string manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"download-path\": \"http://172.23.92.135/orchestration.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"my\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"download-path\": \"http://172.23.92.135/dummy_service.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"dummy_service\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    load(manifest, new_services);
    load(old_manifest, old_services);

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(corrupted_file_list))
                .WillOnce(Return(corrupted_packages));

    EXPECT_CALL(mock_orchestration_tools, doesFileExist(manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(manifest_file_path, "/etc/cp/conf/manifest.json.bk"))
                .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, isNonEmptyFile(manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, removeFile(file_name)).WillOnce(Return(true));

    EXPECT_TRUE(i_manifest_controller->updateManifest(file_name));

    // Upate the ignored package
    manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"download-path\": \"http://172.23.92.135/orchestration.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"my\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"download-path\": \"http://172.23.92.135/dummy_service.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"dummy_service\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"b58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    //mock_orchestration_tools
    load(manifest, new_services);

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(corrupted_file_list))
                .WillOnce(Return(corrupted_packages));

    EXPECT_CALL(mock_orchestration_tools, doesFileExist(manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(manifest_file_path, "/etc/cp/conf/manifest.json.bk"))
                .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, isNonEmptyFile(manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, removeFile(file_name)).WillOnce(Return(true));

    EXPECT_TRUE(i_manifest_controller->updateManifest(file_name));
}


TEST_F(ManifestControllerIgnorePakckgeTest, addIgnorePackageAndUpdateNormal)
{
    init();

    // Add an ignored package
    string manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"download-path\": \"http://172.23.92.135/orchestration.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"my\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"download-path\": \"http://172.23.92.135/dummy_service.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"dummy_service\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    load(manifest, new_services);
    load(old_manifest, old_services);

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(corrupted_file_list))
                .WillOnce(Return(corrupted_packages));

    EXPECT_CALL(mock_orchestration_tools, doesFileExist(manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist("/etc/cp/packages/my/my")).Times(2).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, copyFile(manifest_file_path, "/etc/cp/conf/manifest.json.bk"))
                .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, isNonEmptyFile(manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, removeFile(file_name)).WillOnce(Return(true));

    EXPECT_TRUE(i_manifest_controller->updateManifest(file_name));

    // Upate the normal package
    manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"download-path\": \"http://172.23.92.135/orchestration.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"my\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"b58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"download-path\": \"http://172.23.92.135/dummy_service.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"dummy_service\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    //mock_orchestration_tools
    load(manifest, new_services);

    //mock_downloader
    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/my.sh",
            "b58bbab8020b0e6d08568714b5e582a3adf9c805",
            Package::ChecksumTypes::SHA1,
            "my"
        )
    ).WillOnce(Return(string("/tmp/temp_file")));

    //mock_package_handler
    EXPECT_CALL(mock_package_handler, shouldInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, preInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, installPackage("my", "/tmp/temp_file", _)).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, postInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, updateSavedPackage("my", "/tmp/temp_file")).WillOnce(Return(true));

    load(manifest, new_services);
    load(old_manifest, old_services);

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(corrupted_file_list))
                .WillOnce(Return(corrupted_packages));

    EXPECT_CALL(mock_orchestration_tools, doesFileExist(manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(manifest_file_path, "/etc/cp/conf/manifest.json.bk"))
                .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, isNonEmptyFile(manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, removeFile(file_name)).WillOnce(Return(true));

    EXPECT_TRUE(i_manifest_controller->updateManifest(file_name));
}

TEST_F(ManifestControllerIgnorePakckgeTest, removeIgnoredPackage)
{
    init();

    // Add an ignored package
    string manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"download-path\": \"http://172.23.92.135/orchestration.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"my\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"download-path\": \"http://172.23.92.135/dummy_service.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"dummy_service\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    load(manifest, new_services);
    load(old_manifest, old_services);

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(corrupted_file_list))
                .WillOnce(Return(corrupted_packages));

    EXPECT_CALL(mock_orchestration_tools, doesFileExist(manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(manifest_file_path, "/etc/cp/conf/manifest.json.bk"))
                .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, isNonEmptyFile(manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, removeFile(file_name)).WillOnce(Return(true));

    EXPECT_TRUE(i_manifest_controller->updateManifest(file_name));

    // Remove the ignored package
    manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"download-path\": \"http://172.23.92.135/orchestration.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"my\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    //mock_orchestration_tools
    load(manifest, new_services);

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(corrupted_file_list))
                .WillOnce(Return(corrupted_packages));

    EXPECT_CALL(mock_orchestration_tools, doesFileExist(manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(manifest_file_path, "/etc/cp/conf/manifest.json.bk"))
                .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, isNonEmptyFile(manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, removeFile(file_name)).WillOnce(Return(true));

    EXPECT_TRUE(i_manifest_controller->updateManifest(file_name));
}

TEST_F(ManifestControllerIgnorePakckgeTest, freezeIgnoredPackage)
{
    init("dummy_service\nmy");

    Debug::setUnitTestFlag(D_CONFIG, Debug::DebugLevel::TRACE);
    ostringstream capture_debug;
    Debug::setNewDefaultStdout(&capture_debug);

    // Update an ignored package
    string manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"download-path\": \"http://172.23.92.135/orchestration.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"my\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"b58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    load(manifest, new_services);
    load(old_manifest, old_services);

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(corrupted_file_list))
                .WillOnce(Return(corrupted_packages));

    EXPECT_CALL(mock_orchestration_tools, doesFileExist(manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(manifest_file_path, "/etc/cp/conf/manifest.json.bk"))
                .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, isNonEmptyFile(manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, removeFile(file_name)).WillOnce(Return(true));

    EXPECT_TRUE(i_manifest_controller->updateManifest(file_name));

    EXPECT_THAT(capture_debug.str(), HasSubstr("Ignoring a package from the manifest. Package name: my"));
    EXPECT_THAT(capture_debug.str(), HasSubstr("Ignoring a package from the manifest. Package name: dummy_service"));
    EXPECT_THAT(
        capture_debug.str(),
        Not(HasSubstr("Ignoring a package from the manifest. Package name: orchestration"))
    );
    Debug::setNewDefaultStdout(&cout);
}

TEST_F(ManifestControllerIgnorePakckgeTest, overrideIgnoredPackageFromProfileSettings)
{
    init("dummy_service\nmy");
    config.preload();

    static const string profile_settings(
        "{\n"
            "\"agentSettings\": [\n"
                "{\n"
                    "\"key\": \"orchestration.IgnoredPackagesList\",\n"
                    "\"value\": \"a,orchestration,c,notmy\",\n"
                    "\"id\": \"123\"\n"
                "}\n"
            "]\n"
        "}\n"
    );

    istringstream ss(profile_settings);
    EXPECT_TRUE(Singleton::Consume<Config::I_Config>::from(config)->loadConfiguration(ss));

    Debug::setUnitTestFlag(D_CONFIG, Debug::DebugLevel::TRACE);
    ostringstream capture_debug;
    Debug::setNewDefaultStdout(&capture_debug);

    // Update an ignored package
    string manifest =
        "{"
        "   \"packages\": ["
        "       {"
        "           \"download-path\": \"http://172.23.92.135/orchestration.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"orchestration\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c8051\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       },"
        "       {"
        "           \"download-path\": \"http://172.23.92.135/my.sh\","
        "           \"relative-path\": \"\","
        "           \"name\": \"my\","
        "           \"version\": \"c\","
        "           \"checksum-type\": \"sha1sum\","
        "           \"checksum\": \"b58bbab8020b0e6d08568714b5e582a3adf9c805\","
        "           \"package-type\": \"service\","
        "            \"require\": []"
        "       }"
        "   ]"
        "}";

    //mock_downloader
    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/my.sh",
            "b58bbab8020b0e6d08568714b5e582a3adf9c805",
            Package::ChecksumTypes::SHA1,
            "my"
        )
    ).WillOnce(Return(string("/tmp/temp_file")));

    //mock_package_handler
    EXPECT_CALL(mock_package_handler, shouldInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, preInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, installPackage("my", "/tmp/temp_file", _)).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, postInstallPackage("my", "/tmp/temp_file")).WillOnce(Return(true));
    EXPECT_CALL(mock_package_handler, updateSavedPackage("my", "/tmp/temp_file")).WillOnce(Return(true));

    load(manifest, new_services);
    load(old_manifest, old_services);

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(file_name)).WillOnce(Return(new_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file_path)).WillOnce(Return(old_services));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(corrupted_file_list))
                .WillOnce(Return(corrupted_packages));

    EXPECT_CALL(mock_orchestration_tools, doesFileExist(manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist("/etc/cp/packages/my/my")).Times(2).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, copyFile(manifest_file_path, "/etc/cp/conf/manifest.json.bk"))
                .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, isNonEmptyFile(manifest_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, removeFile(file_name)).WillOnce(Return(true));

    EXPECT_TRUE(i_manifest_controller->updateManifest(file_name));

    EXPECT_THAT(capture_debug.str(), Not(HasSubstr("Ignoring a package from the manifest. Package name: my")));
    EXPECT_THAT(
        capture_debug.str(),
        Not(HasSubstr("Ignoring a package from the manifest. Package name: dummy_service"))
    );
    EXPECT_THAT(capture_debug.str(), HasSubstr("Ignoring a package from the manifest. Package name: orchestration"));
    EXPECT_THAT(capture_debug.str(), HasSubstr("Ignoring a package from the manifest. Package name: notmy"));
    EXPECT_THAT(capture_debug.str(), HasSubstr("Ignoring a package from the manifest. Package name: a"));
    EXPECT_THAT(capture_debug.str(), HasSubstr("Ignoring a package from the manifest. Package name: c"));
    Debug::setNewDefaultStdout(&cout);
}

class ManifestDownloadTest : public Test
{
public:
    ManifestDownloadTest()
    {
        EXPECT_CALL(
            mock_orchestration_tools,
            doesFileExist("/etc/cp/conf/ignore-packages.txt")
        ).WillOnce(Return(false));

        manifest_controller.init();
    }
    ::Environment env;
    ConfigComponent config;

    StrictMock<MockAgentDetails> agent_details;
    StrictMock<MockOrchestrationTools> mock_orchestration_tools;
    StrictMock<MockPackageHandler> mock_package_handler;
    StrictMock<MockDownloader> mock_downloader;
    StrictMock<MockOrchestrationStatus> mock_status;
    StrictMock<MockDetailsResolver> mock_details_resolver;
    NiceMock<MockShellCmd> mock_shell_cmd;

    NiceMock<MockMainLoop> mock_mainloop;
    NiceMock<MockTimeGet> mock_timer;

    ManifestController manifest_controller;
    I_ManifestController *i_manifest_controller = Singleton::Consume<I_ManifestController>::from(manifest_controller);

    void
    load(const string &manifest, map<string, Package> &ret)
    {
        std::stringstream os(manifest);
        cereal::JSONInputArchive archive_in(os);
        archive_in(ret);
    }

private:
};

TEST_F(ManifestDownloadTest, download_relative_path)
{
    vector<string> manifest_data = {
        "{",
        "   \"packages\": [",
        "       {",
        "           \"download-path\": \"http://172.23.92.135/orchestration.sh\",",
        "           \"relative-path\": \"/orchestration.sh\",",
        "           \"name\": \"orchestration\",",
        "           \"version\": \"c\",",
        "           \"checksum-type\": \"sha1sum\",",
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\",",
        "           \"package-type\": \"service\",",
        "           \"require\": []",
        "       }",
        "   ]",
        "}"
    };

    Maybe<string> fog_domain(string("fake.checkpoint.com"));
    Maybe<string> downloaded_package(genError("Failed to download"));

    map<string, Package> new_packages;
    map<string, Package> manifest_packages;
    map<string, Package> corrupted_packages;

    CPTestTempfile manifest_file(manifest_data);
    string x = manifest_file.readFile();

    load(x, new_packages);

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file.fname)).WillOnce(Return(new_packages));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson("/etc/cp/conf/manifest.json"))
        .WillOnce(Return(manifest_packages));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson("/etc/cp/conf/corrupted_packages.json"))
        .WillOnce(Return(corrupted_packages));
    EXPECT_CALL(agent_details, getFogDomain()).WillOnce(Return(fog_domain));
    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "<JWT>https://fake.checkpoint.com/download/orchestration.sh",
            "a58bbab8020b0e6d08568714b5e582a3adf9c805",
            _,
            "orchestration"
        )
    ).WillOnce(Return(downloaded_package));

    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/orchestration.sh",
            "a58bbab8020b0e6d08568714b5e582a3adf9c805",
            _,
            "orchestration"
        )
    ).WillOnce(Return(downloaded_package));
    EXPECT_CALL(
        mock_orchestration_tools,
        doesFileExist("/etc/cp/packages/orchestration/orchestration")
    ).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, getHostname()).WillOnce(Return(string("hostname")));
    EXPECT_CALL(
        mock_status,
        setFieldStatus(OrchestrationStatusFieldType::MANIFEST, OrchestrationStatusResult::FAILED, _)
    );
    string not_error;
    EXPECT_CALL(mock_status, getManifestError()).WillOnce(ReturnRef(not_error));

    EXPECT_FALSE(i_manifest_controller->updateManifest(manifest_file.fname));
}

TEST_F(ManifestDownloadTest, download_relative_path_no_fog_domain)
{
    vector<string> manifest_data = {
        "{",
        "   \"packages\": [",
        "       {",
        "           \"download-path\": \"http://172.23.92.135/orchestration.sh\",",
        "           \"relative-path\": \"/orchestration.sh\",",
        "           \"name\": \"orchestration\",",
        "           \"version\": \"c\",",
        "           \"checksum-type\": \"sha1sum\",",
        "           \"checksum\": \"a58bbab8020b0e6d08568714b5e582a3adf9c805\",",
        "           \"package-type\": \"service\",",
        "           \"require\": []",
        "       }",
        "   ]",
        "}"
    };

    Maybe<string> fog_domain(genError("No fog domain"));
    Maybe<string> downloaded_package(genError("Failed to download"));

    map<string, Package> new_packages;
    map<string, Package> manifest_packages;
    map<string, Package> corrupted_packages;

    CPTestTempfile manifest_file(manifest_data);
    string x = manifest_file.readFile();

    load(x, new_packages);

    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson(manifest_file.fname)).WillOnce(Return(new_packages));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson("/etc/cp/conf/manifest.json"))
        .WillOnce(Return(manifest_packages));
    EXPECT_CALL(mock_orchestration_tools, loadPackagesFromJson("/etc/cp/conf/corrupted_packages.json"))
        .WillOnce(Return(corrupted_packages));
    EXPECT_CALL(agent_details, getFogDomain()).WillOnce(Return(fog_domain));
    EXPECT_CALL(
        mock_orchestration_tools,
        doesFileExist("/etc/cp/packages/orchestration/orchestration")
    ).WillOnce(Return(false));
    string not_error;
    EXPECT_CALL(mock_status, getManifestError()).WillOnce(ReturnRef(not_error));

    EXPECT_CALL(
        mock_downloader,
        downloadFileFromURL(
            "http://172.23.92.135/orchestration.sh",
            "a58bbab8020b0e6d08568714b5e582a3adf9c805",
            _,
            "orchestration"
        )
    ).WillOnce(Return(downloaded_package));
    EXPECT_CALL(mock_details_resolver, getHostname()).WillOnce(Return(string("hostname")));
    EXPECT_CALL(
        mock_status,
        setFieldStatus(OrchestrationStatusFieldType::MANIFEST, OrchestrationStatusResult::FAILED, _)
    );

    EXPECT_FALSE(i_manifest_controller->updateManifest(manifest_file.fname));
}
