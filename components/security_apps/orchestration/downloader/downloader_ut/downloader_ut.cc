#include "cptest.h"
#include "config.h"
#include "config_component.h"
#include "downloader.h"
#include "enum_range.h"
#include "environment.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_time_get.h"

#include "mock/mock_update_communication.h"
#include "mock/mock_orchestration_tools.h"

using namespace std;
using namespace testing;

class DownloaderTest : public Test
{
public:
    DownloaderTest()
    {
        setConfiguration<string>("/tmp", "orchestration", "Default file download path");
        EXPECT_CALL(mock_orchestration_tools, createDirectory("/tmp")).WillOnce(Return(true));
        downloader.init();
    }

    NiceMock<MockMainLoop> mock_mainloop;
    NiceMock<MockTimeGet> mock_timer;
    ::Environment env;
    ConfigComponent config_component;
    StrictMock<MockUpdateCommunication> mock_communication;
    StrictMock<MockOrchestrationTools> mock_orchestration_tools;
    Downloader downloader;
    I_Downloader *i_downloader = Singleton::Consume<I_Downloader>::from(downloader);
};

TEST_F(DownloaderTest, doNothing)
{
}

TEST_F(DownloaderTest, downloadFileFromFog)
{
    string fog_response = "bla bla";
    string checksum = "123";

    GetResourceFile resourse_file(GetResourceFile::ResourceFileType::VIRTUAL_SETTINGS);

    EXPECT_CALL(mock_communication, downloadAttributeFile(resourse_file)).WillOnce(Return(fog_response));

    EXPECT_CALL(
        mock_orchestration_tools,
        calculateChecksum(Package::ChecksumTypes::SHA256, "/tmp/virtualSettings.download")
    ).WillOnce(Return(string("123")));

    EXPECT_CALL(mock_orchestration_tools, writeFile(fog_response, "/tmp/virtualSettings.download", false))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, isNonEmptyFile("/tmp/virtualSettings.download")).WillOnce(Return(true));

    Maybe<string> downloaded_file = i_downloader->downloadFileFromFog(
        checksum,
        Package::ChecksumTypes::SHA256,
        resourse_file
    );

    EXPECT_THAT(downloaded_file, IsValue("/tmp/virtualSettings.download"));
}

TEST_F(DownloaderTest, downloadFileFromFogFailure)
{
    string checksum = "123";

    Maybe<string> fog_response(genError("Failed to download"));
    GetResourceFile resourse_file(GetResourceFile::ResourceFileType::SETTINGS);

    EXPECT_CALL(mock_communication, downloadAttributeFile(resourse_file)).WillOnce(Return(fog_response));

    Maybe<string> downloaded_file = i_downloader->downloadFileFromFog(
        checksum,
        Package::ChecksumTypes::SHA256,
        resourse_file
    );

    EXPECT_FALSE(downloaded_file.ok());
    EXPECT_THAT(downloaded_file, IsError("Failed to download"));
}

TEST_F(DownloaderTest, registerConfig)
{
    string file_path_value = "/tmp";
    string signed_certificates_value = "bla";
    string config_json =
        "{\n"
        "    \"orchestration\": {\n"
        "        \"Default file download path\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"" + file_path_value + "\"\n"
        "            }\n"
        "        ],\n"
        "        \"Self signed certificates acceptable\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"" + signed_certificates_value + "\"\n"
        "            }\n"
        "        ]\n"
        "    }\n"
        "}\n";

    env.preload();
    env.init();
    downloader.preload();
    istringstream stringstream(config_json);
    Singleton::Consume<Config::I_Config>::from(config_component)->loadConfiguration(stringstream);

    EXPECT_THAT(
        getConfiguration<string>("orchestration", "Default file download path"),
        IsValue(file_path_value)
    );

    EXPECT_THAT(
        getConfiguration<string>("orchestration", "Self signed certificates acceptable"),
        IsValue(signed_certificates_value)
    );

    env.fini();
}

TEST_F(DownloaderTest, downloadWithBadChecksum)
{
    string local_file_path = "/tmp/test_file.sh";
    string url = "file://" + local_file_path;
    string dir_path = getConfigurationWithDefault<string>(
        "/tmp/orchestration_downloads",
        "orchestration",
        "Default file download path"
    );
    string service_name = "test";
    string file_name = service_name + ".download";
    string file_path = dir_path + "/" + file_name;
    string checksum = "1234";
    Package::ChecksumTypes checksum_type = Package::ChecksumTypes::MD5;

    EXPECT_CALL(
        mock_orchestration_tools,
        calculateChecksum(checksum_type, file_path)
    ).WillOnce(Return(checksum + "5"));
    EXPECT_CALL(mock_orchestration_tools, copyFile(local_file_path, file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, removeFile("/tmp/test.download")).WillOnce(Return(true));
    EXPECT_THAT(
        i_downloader->downloadFileFromURL(url, checksum, checksum_type, service_name),
        IsError("The checksum calculation is not as the expected, 1234 != 12345")
    );
}

TEST_F(DownloaderTest, downloadFromLocal)
{
    string local_file_path = "/tmp/test_file.sh";
    string url = "file://" + local_file_path;
    string dir_path = getConfigurationWithDefault<string>(
        "/tmp/orchestration_downloads",
        "orchestration",
        "Default file download path"
    );
    string service_name = "test";
    string file_name = service_name + ".download";
    string file_path = dir_path + "/" + file_name;
    string checksum = "1234";
    Package::ChecksumTypes checksum_type = Package::ChecksumTypes::MD5;

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(checksum_type, file_path)).WillOnce(Return(checksum));
    EXPECT_CALL(mock_orchestration_tools, copyFile(local_file_path, file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, isNonEmptyFile(file_path)).WillOnce(Return(true));
    i_downloader->downloadFileFromURL(url, checksum, checksum_type, service_name);
}

TEST_F(DownloaderTest, downloadEmptyFileFromFog)
{
    string fog_response = "bla bla";
    string checksum = "123";
    string service_name = "manifest";
    string empty_str = "";

    GetResourceFile resourse_file(GetResourceFile::ResourceFileType::MANIFEST);

    EXPECT_CALL(mock_communication, downloadAttributeFile(resourse_file)).WillOnce(Return(fog_response));

    EXPECT_CALL(mock_orchestration_tools, writeFile(fog_response, "/tmp/manifest.download", false))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, isNonEmptyFile("/tmp/manifest.download")).WillOnce(Return(false));

    EXPECT_CALL(
        mock_orchestration_tools,
        calculateChecksum(Package::ChecksumTypes::SHA256, "/tmp/manifest.download")
    ).WillOnce(Return(checksum));

    Maybe<string> downloaded_file = i_downloader->downloadFileFromFog(
        checksum,
        Package::ChecksumTypes::SHA256,
        resourse_file
    );

    EXPECT_FALSE(downloaded_file.ok());
    EXPECT_THAT(downloaded_file, IsError("Failed to download file manifest"));
}

TEST_F(DownloaderTest, downloadFromCustomURL)
{
    string file_prefix = "file://";
    string file_name = "/test_file.sh";
    string local_file_path = "/tmp" + file_name;
    string url = file_prefix + local_file_path;
    string custom_URL = "/custom";
    setConfiguration<string>(
        string(file_prefix + custom_URL),
        "orchestration",
        "Custom download url"
    );
    string dir_path = getConfigurationWithDefault<string>(
        "/tmp/orchestration_downloads",
        "orchestration",
        "Default file download path"
    );
    string service_name = "test";
    string download_file_name = service_name + ".download";
    string download_file_path = dir_path + "/" + download_file_name;
    string checksum = "1234";
    Package::ChecksumTypes checksum_type = Package::ChecksumTypes::MD5;
    EXPECT_CALL(mock_orchestration_tools, copyFile(custom_URL + file_name, download_file_path))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, isNonEmptyFile(download_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(checksum_type, download_file_path))
        .WillOnce(Return(checksum));

    i_downloader->downloadFileFromURL(url, checksum, checksum_type, service_name);
}

TEST_F(DownloaderTest, CustomURLBackBackslash)
{
    string file_prefix = "file://";
    string file_name = "test_file.sh";
    string local_file_path = "/tmp/" + file_name;
    string url = file_prefix + local_file_path;
    string custom_URL = "/custom/";
    setConfiguration<string>(
        string(file_prefix + custom_URL),
        "orchestration",
        "Custom download url"
    );
    string dir_path = getConfigurationWithDefault<string>(
        "/tmp/orchestration_downloads",
        "orchestration",
        "Default file download path"
    );
    string service_name = "test";
    string download_file_name = service_name + ".download";
    string download_file_path = dir_path + "/" + download_file_name;
    string checksum = "1234";
    Package::ChecksumTypes checksum_type = Package::ChecksumTypes::MD5;
    EXPECT_CALL(mock_orchestration_tools, copyFile(custom_URL + file_name, download_file_path))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, isNonEmptyFile(download_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(checksum_type, download_file_path))
        .WillOnce(Return(checksum));
    i_downloader->downloadFileFromURL(url, checksum, checksum_type, service_name);
}

TEST_F(DownloaderTest, EmptyCustomURL)
{
    string file_prefix = "file://";
    string file_name = "/test_file.sh";
    string local_file_path = "/tmp" + file_name;
    string url = file_prefix + local_file_path;
    string custom_URL = "";
    setConfiguration<string>(
        string(custom_URL),
        "orchestration",
        "Custom download url"
    );
    string dir_path = getConfigurationWithDefault<string>(
        "/tmp/orchestration_downloads",
        "orchestration",
        "Default file download path"
    );
    string service_name = "test";
    string download_file_name = service_name + ".download";
    string download_file_path = dir_path + "/" + download_file_name;
    string checksum = "1234";
    Package::ChecksumTypes checksum_type = Package::ChecksumTypes::MD5;
    EXPECT_THAT(
        i_downloader->downloadFileFromURL(url, checksum, checksum_type, service_name),
        IsError("Failed to parse custom URL. URL is empty")
    );
}

TEST_F(DownloaderTest, download_virtual_policy)
{
    GetResourceFile resourse_file(GetResourceFile::ResourceFileType::VIRTUAL_POLICY);

    resourse_file.addTenant("0000", "1234", "1", "checksum0000");
    resourse_file.addTenant("1111", "1235", "2", "checksum1111");

    string tenant_0000_file =
        "{"
            "\"waap\":\"108-005\","
            "\"accessControl\":\"Internal error, check logs\","
            "\"idk\":\"ed5ac9a6-6924-4ebc-9ace-971896ca33c5\","
            "\"something\":\"Low\""
        "}";

    string tenant_1111_file =
        "{"
            "\"messageId\":\"108-005\","
            "\"message\":\"Internal error, check logs\","
            "\"referenceId\":\"ed5ac9a6-6924-4ebc-9ace-971896ca33c5\","
            "\"severity\":\"Low\""
        "}";

    string fog_response =
        "{\n"
        "    \"tenants\": [\n"
        "        {\n"
        "            \"tenantId\": \"0000\",\n"
        "            \"profileId\": \"1234\",\n"
        "            \"policy\": {\n"
        "                \"waap\": \"108-005\",\n"
        "                \"accessControl\": \"Internal error, check logs\",\n"
        "                \"idk\": \"ed5ac9a6-6924-4ebc-9ace-971896ca33c5\",\n"
        "                \"something\": \"Low\"\n"
        "            }\n"
        "        },\n"
        "        {\n"
        "            \"tenantId\": \"1111\",\n"
        "            \"profileId\": \"1235\",\n"
        "            \"policy\": {\n"
        "                \"messageId\": \"108-005\",\n"
        "                \"message\": \"Internal error, check logs\",\n"
        "                \"referenceId\": \"ed5ac9a6-6924-4ebc-9ace-971896ca33c5\",\n"
        "                \"severity\": \"Low\"\n"
        "            }\n"
        "        }\n"
        "    ]\n"
        "}";

    EXPECT_CALL(mock_communication, downloadAttributeFile(resourse_file)).WillOnce(Return(fog_response));

    EXPECT_CALL(
        mock_orchestration_tools,
        writeFile(
            tenant_0000_file,
            "/tmp/virtualPolicy_0000_profile_1234.download",
            false)
    ).WillOnce(Return(true));

    EXPECT_CALL(mock_orchestration_tools, fillKeyInJson(_, _, _)).WillRepeatedly(Return());

    EXPECT_CALL(
        mock_orchestration_tools,
        writeFile(
            tenant_1111_file,
            "/tmp/virtualPolicy_1111_profile_1235.download",
            false)
    ).WillOnce(Return(true));

    map<pair<string, string>, string> expected_downloaded_files =
        {
            { {"0000", "1234" }, "/tmp/virtualPolicy_0000_profile_1234.download" },
            { {"1111", "1235" }, "/tmp/virtualPolicy_1111_profile_1235.download" }
        };

    EXPECT_EQ(
        i_downloader->downloadVirtualFileFromFog(
            resourse_file,
            Package::ChecksumTypes::SHA256
        ),
        expected_downloaded_files
    );
}

TEST_F(DownloaderTest, download_virtual_settings)
{
    GetResourceFile resourse_file(GetResourceFile::ResourceFileType::VIRTUAL_SETTINGS);

    resourse_file.addTenant(
        "4c721b40-85df-4364-be3d-303a10ee9789",
        "4c721b40-85df-4364-be3d-303a10ee9780",
        "1",
        "checksum0000"
    );

    string tenant_0000_file =
        "{"
            "\"agentSettings\":["
                "{"
                    "\"id\":\"f0bd081b-175a-2fb6-c6de-d05d62fdcadf\","
                    "\"key\":\"\","
                    "\"value\":\"\""
                "}"
            "],"
            "\"allowOnlyDefinedApplications\":false,"
            "\"anyFog\":true,"
            "\"reverseProxy\":{"
                "\"assets\":[]"
            "},"
            "\"upgradeMode\":\"automatic\""
        "}";

    string fog_response =
        "{\n"
        "    \"tenants\": [\n"
        "        {\n"
        "            \"tenantId\": \"4c721b40-85df-4364-be3d-303a10ee9789\",\n"
        "            \"profileId\": \"4c721b40-85df-4364-be3d-303a10ee9780\",\n"
        "            \"settings\": {\n"
        "                \"agentSettings\": [\n"
        "                    {\n"
        "                        \"id\": \"f0bd081b-175a-2fb6-c6de-d05d62fdcadf\",\n"
        "                        \"key\": \"\",\n"
        "                        \"value\": \"\"\n"
        "                    }\n"
        "                ],\n"
        "                \"allowOnlyDefinedApplications\": false,\n"
        "                \"anyFog\": true,\n"
        "                \"reverseProxy\": {\n"
        "                    \"assets\": []\n"
        "                },\n"
        "                \"upgradeMode\": \"automatic\"\n"
        "            }\n"
        "        }\n"
        "    ]\n"
        "}";

    EXPECT_CALL(mock_communication, downloadAttributeFile(resourse_file)).WillOnce(Return(fog_response));

    stringstream tenant_0000_path;
    tenant_0000_path << "/tmp/virtualSettings_4c721b40-85df-4364-be3d-303a10ee9789"
                    "_profile_4c721b40-85df-4364-be3d-303a10ee9780.download";
    EXPECT_CALL(
        mock_orchestration_tools,
        writeFile(
            tenant_0000_file,
            tenant_0000_path.str(),
            false
        )
    ).WillOnce(Return(true));

    EXPECT_CALL(mock_orchestration_tools, fillKeyInJson(_, _, _)).WillRepeatedly(Return());

    stringstream file_path;
    file_path << "/tmp/virtualSettings_4c721b40-85df-4364-be3d-303a10ee9789"
                "_profile_4c721b40-85df-4364-be3d-303a10ee9780.download";

    map<pair<string, string>, string> expected_downloaded_files = {
        {   {"4c721b40-85df-4364-be3d-303a10ee9789", "4c721b40-85df-4364-be3d-303a10ee9780"},
            file_path.str()
        }
    };

    EXPECT_EQ(
        i_downloader->downloadVirtualFileFromFog(
            resourse_file,
            Package::ChecksumTypes::SHA256
        ),
        expected_downloaded_files
    );
}
