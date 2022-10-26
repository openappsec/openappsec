#include "orchestration_status.h"

#include <string>
#include <chrono>
#include <fstream>
#include <map>

#include "cptest.h"
#include "config.h"
#include "config_component.h"
#include "mock/mock_time_get.h"
#include "mock/mock_orchestration_tools.h"
#include "mock/mock_agent_details.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_rest_api.h"

using namespace testing;
using namespace std;
using namespace chrono;

class OrchestrationStatusTest : public Test
{
public:
    ~OrchestrationStatusTest() { Debug::setNewDefaultStdout(&cout); }

    void
    init()
    {
        Debug::setUnitTestFlag(D_ORCHESTRATOR, Debug::DebugLevel::TRACE);
        Debug::setNewDefaultStdout(&capture_debug);
        CPTestTempfile status_file;
        file_path = status_file.fname;
        setConfiguration(file_path, "orchestration", "Orchestration status path");
        // Write orchestration status to file routine
        EXPECT_CALL(
            mock_mainloop,
            addRecurringRoutine(I_MainLoop::RoutineType::Timer, chrono::microseconds(5000000), _, _, false))
            .WillOnce(DoAll(SaveArg<2>(&routine), Return(1))
        );
        EXPECT_CALL(mock_tools, readFile(file_path)).WillOnce(Return(start_file_content));
        orchestration_status.init();
    }

    string
    orchestrationStatusFileToString()
    {
        routine();
        ifstream status_file(file_path);
        stringstream string_stream;
        if (status_file.is_open()) {
            string line;
            bool is_first_line = true;
            while (getline(status_file, line)) {
                if (is_first_line) {
                    is_first_line = false;
                } else {
                    string_stream << endl;
                }
                string_stream << line;
            }
            status_file.close();
        }
        return string_stream.str();
    }

    string
    buildOrchestrationStatusJSON(
        const string &last_update_attempt = "None",
        const string &last_update_status = "None",
        const string &last_update = "None",
        const string &last_manifest_update = "None",
        const string &policy_version = "",
        const string &last_policy_update = "None",
        const string &last_settings_update = "None",
        const string &upgrade_mode = "None",
        const string &fog_address = "None",
        const string &registration_status = "None",
        const string &manifest_status = "None",
        const string &registration_details_name = "",
        const string &registration_details_type = "",
        const string &registration_details_platform = "",
        const string &registration_details_architecture = "",
        const string &agent_id = "None",
        const string &profile_id = "None",
        const string &tenant_id = "None"
    )
    {
        return  "{\n"
                "    \"Last update attempt\": \"" + last_update_attempt + "\",\n"
                "    \"Last update status\": \"" + last_update_status + "\",\n"
                "    \"Last update\": \"" + last_update + "\",\n"
                "    \"Last manifest update\": \"" + last_manifest_update + "\",\n"
                "    \"Policy version\": \"" + policy_version + "\",\n"
                "    \"Last policy update\": \"" + last_policy_update + "\",\n"
                "    \"Last settings update\": \"" + last_settings_update + "\",\n"
                "    \"Upgrade mode\": \"" + upgrade_mode + "\",\n"
                "    \"Fog address\": \"" + fog_address + "\",\n"
                "    \"Registration status\": \"" + registration_status + "\",\n"
                "    \"Registration details\": {\n"
                "        \"Name\": \"" + registration_details_name + "\",\n"
                "        \"Type\": \"" + registration_details_type + "\",\n"
                "        \"Platform\": \"" + registration_details_platform + "\",\n"
                "        \"Architecture\": \"" + registration_details_architecture + "\"\n"
                "    },\n"
                "    \"Agent ID\": \"" + agent_id + "\",\n"
                "    \"Profile ID\": \"" + profile_id + "\",\n"
                "    \"Tenant ID\": \"" + tenant_id + "\",\n"
                "    \"Manifest status\": \"" + manifest_status + "\",\n"
                "    \"Service policy\": {},\n"
                "    \"Service settings\": {}\n"
                "}";
    }

    ::Environment env;
    ConfigComponent config;
    StrictMock<MockTimeGet> time;
    StrictMock<MockMainLoop> mock_mainloop;
    ostringstream capture_debug;
    StrictMock<MockOrchestrationTools> mock_tools;
    StrictMock<MockAgentDetails> mock_agent_details;
    OrchestrationStatus orchestration_status;
    I_OrchestrationStatus * i_orchestration_status =
        Singleton::Consume<I_OrchestrationStatus>::from(orchestration_status);
    string file_path;
    Maybe<string> start_file_content = genError("No file");
    I_MainLoop::Routine routine;
};

TEST_F(OrchestrationStatusTest, doNothing)
{
}

TEST_F(OrchestrationStatusTest, noFieldsValues)
{
    init();
    auto result = orchestrationStatusFileToString();
    EXPECT_EQ(buildOrchestrationStatusJSON(), result);
}

TEST_F(OrchestrationStatusTest, recoverFields)
{
    init();
    auto result = orchestrationStatusFileToString();
    i_orchestration_status->recoverFields();
    EXPECT_EQ(orchestrationStatusFileToString(), result);
}

TEST_F(OrchestrationStatusTest, loadFromFile)
{
    Maybe<string> status = genError("No file");;
    CPTestTempfile status_file;
    file_path = status_file.fname;
    setConfiguration(file_path, "orchestration", "Orchestration status path");
    // Write to file routine
    EXPECT_CALL(
        mock_mainloop,
        addRecurringRoutine(I_MainLoop::RoutineType::Timer, chrono::microseconds(5000000), _, _, false)
    ).Times(3).WillRepeatedly(DoAll(SaveArg<2>(&routine), Return(1)));

    EXPECT_CALL(mock_tools, readFile(file_path)).Times(3).WillRepeatedly(Return(status));
    orchestration_status.init();
    status = orchestrationStatusFileToString();

    orchestration_status.init();
    EXPECT_EQ(orchestrationStatusFileToString(), status.unpack());

    EXPECT_CALL(time, getLocalTimeStr())
        .WillOnce(Return(string("attempt time")))
        .WillOnce(Return(string("current time")));
    i_orchestration_status->setLastUpdateAttempt();
    i_orchestration_status->setFieldStatus(
        OrchestrationStatusFieldType::LAST_UPDATE,
        OrchestrationStatusResult::SUCCESS
    );

    status = orchestrationStatusFileToString();
    EXPECT_EQ(buildOrchestrationStatusJSON("attempt time", "Succeeded ", "current time"), status.unpack());

    // Write status to file
    routine();

    // Reload status from file and validate status
    orchestration_status.init();
    EXPECT_EQ(buildOrchestrationStatusJSON("attempt time", "Succeeded ", "current time"), status.unpack());
}

TEST_F(OrchestrationStatusTest, checkUpdateStatus)
{
    init();
    EXPECT_CALL(time, getLocalTimeStr())
        .WillOnce(Return(string("attempt time")))
        .WillOnce(Return(string("current time")));

    i_orchestration_status->setLastUpdateAttempt();

    i_orchestration_status->setFieldStatus(
        OrchestrationStatusFieldType::LAST_UPDATE,
        OrchestrationStatusResult::SUCCESS
    );
    auto result = orchestrationStatusFileToString();
    EXPECT_EQ(buildOrchestrationStatusJSON("attempt time", "Succeeded ", "current time"), result);
}

TEST_F(OrchestrationStatusTest, recoveryFields)
{
    init();
    CPTestTempfile status({""});
    setConfiguration(status.fname, "orchestration", "Orchestration status path");

    i_orchestration_status->setFieldStatus(
        OrchestrationStatusFieldType::REGISTRATION,
        OrchestrationStatusResult::SUCCESS
    );
    const string agent_id = "AgentId";
    const string profile_id = "ProfileId";
    const string tenant_id = "TenantId";
    auto fog_addr = Maybe<string>(string("FogDomain"));

    EXPECT_CALL(mock_agent_details, getAgentId()).WillOnce(Return(agent_id));
    EXPECT_CALL(mock_agent_details, getProfileId()).WillOnce(Return(profile_id));
    EXPECT_CALL(mock_agent_details, getTenantId()).WillOnce(Return(tenant_id));
    EXPECT_CALL(mock_agent_details, getFogDomain()).WillOnce(Return(fog_addr));
    i_orchestration_status->writeStatusToFile();
    EXPECT_THAT(capture_debug.str(), HasSubstr("Repairing status fields"));

    EXPECT_EQ(i_orchestration_status->getAgentId(), agent_id);
    EXPECT_EQ(i_orchestration_status->getProfileId(), profile_id);
    EXPECT_EQ(i_orchestration_status->getTenantId(), tenant_id);
    EXPECT_EQ(i_orchestration_status->getFogAddress(), fog_addr.unpack());
}

TEST_F(OrchestrationStatusTest, updateAllLastUpdatesTypes)
{
    init();
    EXPECT_CALL(time, getLocalTimeStr())
        .WillOnce(Return(string("attempt time")))
        .WillOnce(Return(string("current time")))
        .WillOnce(Return(string("current time001")));

    i_orchestration_status->setLastUpdateAttempt();

    i_orchestration_status->setFieldStatus(
        OrchestrationStatusFieldType::LAST_UPDATE,
        OrchestrationStatusResult::SUCCESS
    );
    i_orchestration_status->setIsConfigurationUpdated(
        EnumArray<OrchestrationStatusConfigType, bool>(true, false, false)
    );
    auto result = orchestrationStatusFileToString();
    EXPECT_EQ(buildOrchestrationStatusJSON("attempt time", "Succeeded ", "current time", "current time001"), result);

    EXPECT_CALL(time, getLocalTimeStr())
        .Times(2)
        .WillRepeatedly(Return(string("current time002")));

    i_orchestration_status->setFieldStatus(
        OrchestrationStatusFieldType::LAST_UPDATE,
        OrchestrationStatusResult::SUCCESS
    );
    i_orchestration_status->setIsConfigurationUpdated(
        EnumArray<OrchestrationStatusConfigType, bool>(true, true, false)
    );
    result = orchestrationStatusFileToString();
    EXPECT_EQ(
        buildOrchestrationStatusJSON(
            "attempt time",
            "Succeeded ",
            "current time002",
            "current time002",
            "",
            "current time002"
        ),
        result
    );

    EXPECT_CALL(time, getLocalTimeStr())
        .Times(2)
        .WillRepeatedly(Return(string("current time003")));

    i_orchestration_status->setFieldStatus(
        OrchestrationStatusFieldType::LAST_UPDATE,
        OrchestrationStatusResult::SUCCESS
    );
    i_orchestration_status->setIsConfigurationUpdated(
        EnumArray<OrchestrationStatusConfigType, bool>(true, true, true)
    );
    result = orchestrationStatusFileToString();
    EXPECT_EQ(
        buildOrchestrationStatusJSON(
            "attempt time",
            "Succeeded ",
            "current time003",
            "current time003",
            "",
            "current time003",
            "current time003"
        ),
        result
    );
}

TEST_F(OrchestrationStatusTest, errorInRegistrationAndMainfest)
{
    init();
    string fog_address = "http://fog.address";
    string registar_error = "Fail to registar";
    string manifest_error = "Fail to achieve manifest";
    string last_update_error = "Fail to update";

    EXPECT_CALL(time, getLocalTimeStr()).Times(3).WillRepeatedly(Return(string("Time")));

    i_orchestration_status->setFieldStatus(
        OrchestrationStatusFieldType::LAST_UPDATE,
        OrchestrationStatusResult::SUCCESS
    );
    i_orchestration_status->setIsConfigurationUpdated(
        EnumArray<OrchestrationStatusConfigType, bool>(true, true, true)
    );
    i_orchestration_status->setFieldStatus(
        OrchestrationStatusFieldType::LAST_UPDATE,
        OrchestrationStatusResult::FAILED,
        last_update_error
    );
    i_orchestration_status->setIsConfigurationUpdated(
        EnumArray<OrchestrationStatusConfigType, bool>(false, false, false)
    );

    i_orchestration_status->setUpgradeMode("Online upgrades");
    i_orchestration_status->setFogAddress(fog_address);

    i_orchestration_status->setUpgradeMode("Online upgrades");
    i_orchestration_status->setFogAddress(fog_address);

    i_orchestration_status->setFieldStatus(
        OrchestrationStatusFieldType::REGISTRATION,
        OrchestrationStatusResult::FAILED,
        registar_error
    );
    i_orchestration_status->setFieldStatus(
        OrchestrationStatusFieldType::MANIFEST,
        OrchestrationStatusResult::FAILED,
        manifest_error
    );
    EXPECT_EQ(i_orchestration_status->getManifestError(), manifest_error);

    auto result = orchestrationStatusFileToString();
    EXPECT_EQ(
        buildOrchestrationStatusJSON(
            "None",
            "Failed. Reason: " + last_update_error,
            "Time",
            "Time",
            "",
            "Time",
            "Time",
            "Online upgrades",
            fog_address,
            "Failed. Reason: " + registar_error,
            "Failed. Reason: " + manifest_error
        ),
        result
    );
}

TEST_F(OrchestrationStatusTest, setAllFields)
{
    init();
    string fog_address = "http://fog.address";
    EXPECT_CALL(time, getLocalTimeStr())
        .Times(3)
        .WillRepeatedly(Return(string("current time")));
    i_orchestration_status->setFieldStatus(
        OrchestrationStatusFieldType::LAST_UPDATE,
        OrchestrationStatusResult::SUCCESS
    );
    i_orchestration_status->setIsConfigurationUpdated(
        EnumArray<OrchestrationStatusConfigType, bool>(true, true, true)
    );
    i_orchestration_status->setRegistrationDetails("name", "type", "platform", "arch");
    i_orchestration_status->setAgentDetails("id", "profile", "tenant");
    i_orchestration_status->setFogAddress("http://fog.address");
    i_orchestration_status->setPolicyVersion("12");
    i_orchestration_status->setAgentType("test_type");
    i_orchestration_status->setUpgradeMode("Test Mode");
    i_orchestration_status->setRegistrationStatus("Succeeded");
    i_orchestration_status->setFieldStatus(
        OrchestrationStatusFieldType::REGISTRATION,
        OrchestrationStatusResult::SUCCESS
    );
    i_orchestration_status->setFieldStatus(
            OrchestrationStatusFieldType::MANIFEST,
            OrchestrationStatusResult::SUCCESS
    );

    string non_empty_conf = "{x:y}";
    string curr_mock_path = "path";
    EXPECT_CALL(mock_tools, readFile(curr_mock_path)).WillRepeatedly(Return(non_empty_conf));
    EXPECT_CALL(mock_tools, readFile(string("new_path"))).WillOnce(Return(string("{}")));

    i_orchestration_status->setServiceConfiguration(
        "service_a", "path", OrchestrationStatusConfigType::SETTINGS
    );
    i_orchestration_status->setServiceConfiguration(
        "service_b", "path", OrchestrationStatusConfigType::POLICY
    );
    i_orchestration_status->setServiceConfiguration(
        "service_c", "path", OrchestrationStatusConfigType::POLICY
    );
    i_orchestration_status->setServiceConfiguration(
        "service_c", "new_path", OrchestrationStatusConfigType::POLICY
    );
    i_orchestration_status->setLastUpdateAttempt();

    auto result = orchestrationStatusFileToString();

    string expected =   "{\n"
                        "    \"Last update attempt\": \"current time\",\n"
                        "    \"Last update status\": \"Succeeded \",\n"
                        "    \"Last update\": \"current time\",\n"
                        "    \"Last manifest update\": \"current time\",\n"
                        "    \"Policy version\": \"12\",\n"
                        "    \"Last policy update\": \"current time\",\n"
                        "    \"Last settings update\": \"current time\",\n"
                        "    \"Upgrade mode\": \"Test Mode\",\n"
                        "    \"Fog address\": \"http://fog.address\",\n"
                        "    \"Registration status\": \"Succeeded \",\n"
                        "    \"Registration details\": {\n"
                        "        \"Name\": \"name\",\n"
                        "        \"Type\": \"test_type\",\n"
                        "        \"Platform\": \"platform\",\n"
                        "        \"Architecture\": \"arch\"\n"
                        "    },\n"
                        "    \"Agent ID\": \"id\",\n"
                        "    \"Profile ID\": \"profile\",\n"
                        "    \"Tenant ID\": \"tenant\",\n"
                        "    \"Manifest status\": \"Succeeded \",\n"
                        "    \"Service policy\": {\n"
                        "        \"service_b\": \"path\"\n"
                        "    },\n"
                        "    \"Service settings\": {\n"
                        "        \"service_a\": \"path\"\n"
                        "    }\n"
                        "}";
    EXPECT_EQ(expected, result);

    // Now lets check load from file
    routine();
    EXPECT_EQ(expected, orchestrationStatusFileToString());

    EXPECT_CALL(
        mock_mainloop,
        addRecurringRoutine(I_MainLoop::RoutineType::Timer, chrono::microseconds(5000000), _, _, false))
        .WillOnce(DoAll(SaveArg<2>(&routine), Return(1)));
    EXPECT_CALL(mock_tools, readFile(file_path)).Times(1).WillOnce(Return(expected));
    orchestration_status.init();
    EXPECT_EQ(expected, orchestrationStatusFileToString());

    map<string, string> service_map_a = {{"service_a", "path"}};
    map<string, string> service_map_b = {{"service_b", "path"}};

    string agent_details =
            "\n    Name: name"
            "\n    Type: test_type"
            "\n    Platform: platform"
            "\n    Architecture: arch";

    EXPECT_EQ(i_orchestration_status->getLastUpdateAttempt(), "current time");
    EXPECT_EQ(i_orchestration_status->getUpdateStatus(), "Succeeded ");;
    EXPECT_EQ(i_orchestration_status->getUpdateTime(), "current time");
    EXPECT_EQ(i_orchestration_status->getLastManifestUpdate(), "current time");
    EXPECT_EQ(i_orchestration_status->getPolicyVersion(), "12");
    EXPECT_EQ(i_orchestration_status->getLastPolicyUpdate(), "current time");
    EXPECT_EQ(i_orchestration_status->getLastSettingsUpdate(), "current time");
    EXPECT_EQ(i_orchestration_status->getUpgradeMode(), "Test Mode");
    EXPECT_EQ(i_orchestration_status->getFogAddress(), "http://fog.address");
    EXPECT_EQ(i_orchestration_status->getRegistrationStatus(), "Succeeded ");
    EXPECT_EQ(i_orchestration_status->getAgentId(), "id");
    EXPECT_EQ(i_orchestration_status->getProfileId(), "profile");
    EXPECT_EQ(i_orchestration_status->getTenantId(), "tenant");
    EXPECT_EQ(i_orchestration_status->getManifestStatus(), "Succeeded ");
    EXPECT_EQ(i_orchestration_status->getServicePolicies(), service_map_b);
    EXPECT_EQ(i_orchestration_status->getServiceSettings(), service_map_a);
    EXPECT_EQ(i_orchestration_status->getRegistrationDetails(), agent_details);
}
