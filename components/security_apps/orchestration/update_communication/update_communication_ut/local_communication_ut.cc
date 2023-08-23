#include <string>

#include "local_communication.h"
#include "cptest.h"
#include "mock/mock_orchestration_tools.h"
#include "config.h"
#include "config_component.h"
#include "orchestration_status.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_time_get.h"

using namespace std;
using namespace testing;

ostream &
operator<<(ostream &os, const tuple<OrchManifest, OrchPolicy, OrchSettings> &)
{
    return os;
}

class LocalCommunicationTest: public Test
{
public:
    LocalCommunicationTest()
    {
        local_communication.init();
    }

    void
    preload()
    {
        local_communication.preload();
    }

    Maybe<void>
    authenticateAgent()
    {
        return local_communication.authenticateAgent();
    }

    Maybe<void>
    sendPolicyVersion(const string &version, const string &policy_versions)
    {
        return local_communication.sendPolicyVersion(version, policy_versions);
    }

    Maybe<string>
    downloadAttributeFile(const GetResourceFile &resourse_file)
    {
        return local_communication.downloadAttributeFile(resourse_file);
    }

    void
    setAddressExtenesion(const string &ext)
    {
        local_communication.setAddressExtenesion(ext);
    }

    Maybe<void>
    checkUpdate(CheckUpdateRequest &request)
    {
        return local_communication.getUpdate(request);
    }

    NiceMock<MockMainLoop> mock_mainloop;
    NiceMock<MockTimeGet> mock_timer;
    ::Environment env;
    ConfigComponent config_comp;
    StrictMock<MockOrchestrationTools> mock_orc_tools;
    OrchestrationStatus orc_status;

private:
    LocalCommunication local_communication;
};

TEST_F(LocalCommunicationTest, doNothing)
{
}

TEST_F(LocalCommunicationTest, registerConfig)
{
    env.preload();
    env.init();

    preload();
    string config_json =
        "{\n"
        "    \"orchestration\": {\n"
        "        \"Offline manifest file path\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"ABC\"\n"
        "            }\n"
        "        ],\n"
        "        \"Offline policy file path\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"qwe\"\n"
        "            }\n"
        "        ],\n"
        "        \"Offline settings file path\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"CCCC\"\n"
        "            }\n"
        "        ]\n"
        "    }\n"
        "}";
    istringstream ss(config_json);
    Singleton::Consume<Config::I_Config>::from(config_comp)->loadConfiguration(ss);

    EXPECT_THAT(getConfiguration<string>("orchestration", "Offline manifest file path"),        IsValue("ABC"));
    EXPECT_THAT(getConfiguration<string>("orchestration", "Offline policy file path"), IsValue("qwe"));
    EXPECT_THAT(getConfiguration<string>("orchestration", "Offline settings file path"),            IsValue("CCCC"));

    env.fini();
}

TEST_F(LocalCommunicationTest, authenticateAgent)
{
    auto authenticat_res = authenticateAgent();
    EXPECT_TRUE(authenticat_res.ok());
}

TEST_F(LocalCommunicationTest, downloadManifest)
{
    string new_manifest_string = "new manifest";
    EXPECT_CALL(mock_orc_tools, readFile("/etc/cp/conf/offline_manifest.json")).WillOnce(Return(new_manifest_string));
    GetResourceFile resourse_file(GetResourceFile::ResourceFileType::MANIFEST);
    auto downloaded_string =  downloadAttributeFile(resourse_file);
    EXPECT_TRUE(downloaded_string.ok());
    EXPECT_EQ(downloaded_string.unpack(), new_manifest_string);
}

TEST_F(LocalCommunicationTest, checkUpdateWithNoUpdate)
{
    Maybe<string> manifest_checksum(string("1"));
    Maybe<string> policy_checksum(string("2"));
    Maybe<string> settings_checksum(string("3"));
    Maybe<string> data_checksum(string("4"));
    EXPECT_CALL(mock_orc_tools, calculateChecksum(
        Package::ChecksumTypes::SHA256, "/etc/cp/conf/offline_manifest.json")).WillOnce(Return(manifest_checksum));
    EXPECT_CALL(mock_orc_tools, calculateChecksum(
        Package::ChecksumTypes::SHA256, "/etc/cp/conf/offline_policy.json")).WillOnce(Return(policy_checksum));
    EXPECT_CALL(mock_orc_tools, calculateChecksum(
        Package::ChecksumTypes::SHA256, "/etc/cp/conf/offline_settings.json")).WillOnce(Return(settings_checksum));
    EXPECT_CALL(mock_orc_tools, calculateChecksum(
        Package::ChecksumTypes::SHA256, "/etc/cp/conf/data/offline_data.json")).WillOnce(Return(data_checksum));

    CheckUpdateRequest request(
            *manifest_checksum,
            *policy_checksum,
            *settings_checksum,
            *data_checksum,
            I_OrchestrationTools::SELECTED_CHECKSUM_TYPE_STR,
            "123"
        );

    auto update_response = checkUpdate(request);
    EXPECT_TRUE(update_response.ok());

    Maybe<string> manifest = request.getManifest();
    EXPECT_FALSE(manifest.ok());

    Maybe<string> policy = request.getPolicy();
    EXPECT_FALSE(policy.ok());

    Maybe<string> settings = request.getSettings();
    EXPECT_FALSE(settings.ok());

    Maybe<string> data = request.getData();
    EXPECT_FALSE(data.ok());
}

TEST_F(LocalCommunicationTest, checkUpdateWithPolicyUpdate)
{
    Maybe<string> manifest_checksum(string("1"));
    Maybe<string> policy_checksum(string("2"));
    Maybe<string> new_policy_checksum(string("22"));
    Maybe<string> settings_checksum(string("3"));
    Maybe<string> data_checksum(string("4"));

    EXPECT_CALL(
        mock_orc_tools,
        calculateChecksum(Package::ChecksumTypes::SHA256, "/etc/cp/conf/offline_manifest.json")
    ).WillOnce(Return(manifest_checksum));
    EXPECT_CALL(
        mock_orc_tools,
        calculateChecksum(Package::ChecksumTypes::SHA256, "/etc/cp/conf/offline_policy.json")
    ).WillOnce(Return(new_policy_checksum));
    EXPECT_CALL(
        mock_orc_tools,
        calculateChecksum(Package::ChecksumTypes::SHA256, "/etc/cp/conf/offline_settings.json")
    ).WillOnce(Return(settings_checksum));
    EXPECT_CALL(
        mock_orc_tools,
        calculateChecksum(Package::ChecksumTypes::SHA256, "/etc/cp/conf/data/offline_data.json")
    ).WillOnce(Return(data_checksum));

    CheckUpdateRequest request(
        *manifest_checksum,
        *policy_checksum,
        *settings_checksum,
        *data_checksum,
        I_OrchestrationTools::SELECTED_CHECKSUM_TYPE_STR,
        "123"
    );

    auto update_response = checkUpdate(request);
    EXPECT_TRUE(update_response.ok());

    Maybe<string> manifest = request.getManifest();
    EXPECT_FALSE(manifest.ok());

    EXPECT_THAT(request.getPolicy(), IsValue("22"));

    Maybe<string> settings = request.getSettings();
    EXPECT_FALSE(settings.ok());

    Maybe<string> data = request.getData();
    EXPECT_FALSE(data.ok());
}

TEST_F(LocalCommunicationTest, setAddressExtenesion)
{
    setAddressExtenesion("Test");
}

TEST_F(LocalCommunicationTest, sendPolicyVersion)
{
    auto res = sendPolicyVersion("12", "");
    EXPECT_TRUE(res.ok());
}
