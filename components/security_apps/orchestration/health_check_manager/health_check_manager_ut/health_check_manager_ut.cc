#include "health_check_manager.h"

#include <sstream>
#include <string>
#include <fstream>
#include <chrono>

#include "health_check_status/health_check_status.h"
#include "environment.h"
#include "config.h"
#include "config_component.h"
#include "cptest.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_messaging.h"
#include "mock/mock_rest_api.h"
#include "updates_process_event.h"

using namespace std;
using namespace testing;

USE_DEBUG_FLAG(D_HEALTH_CHECK);

class TestEnd {};

class HealthCheckManagerTest : public Test
{
public:
    HealthCheckManagerTest()
    {
        Debug::setUnitTestFlag(D_HEALTH_CHECK, Debug::DebugLevel::NOISE);

        EXPECT_CALL(mock_ml, addRecurringRoutine(_, _, _, _, _)).WillRepeatedly(
            DoAll(SaveArg<2>(&health_check_periodic_routine), Return(1))
        );

        EXPECT_CALL(mock_rest, mockRestCall(RestAction::ADD, "declare-boolean-variable", _)).WillOnce(Return(true));

        EXPECT_CALL(mock_rest, mockRestCall(RestAction::SHOW, "health-check-on-demand", _)).WillOnce(
            WithArg<2>(Invoke(this, &HealthCheckManagerTest::setHealthCheckOnDemand))
        );

        env.preload();

        env.init();

        ScopedContext ctx;
        ctx.registerValue<bool>("Is Orchestrator", true);

        health_check_manager.init();
        i_health_check_manager = Singleton::Consume<I_Health_Check_Manager>::from(health_check_manager);
    }

    ~HealthCheckManagerTest()
    {
        env.fini();
        Debug::setNewDefaultStdout(&cout);
    }

    bool
    setHealthCheckOnDemand(const unique_ptr<RestInit> &rest_ptr)
    {
        health_check_server = rest_ptr->getRest();
        return true;
    }

    I_MainLoop::Routine             health_check_periodic_routine;
    StrictMock<MockMainLoop>        mock_ml;
    StrictMock<MockRestApi>         mock_rest;
    StrictMock<MockMessaging>       mock_message;
    ConfigComponent                 config;
    Config::I_Config                *i_config = nullptr;
    ::Environment                   env;
    HealthCheckManager              health_check_manager;
    I_Health_Check_Manager          *i_health_check_manager;
    unique_ptr<ServerRest>          health_check_server;
};

TEST_F(HealthCheckManagerTest, runPeriodicHealthCheckTest)
{
    string actual_body;
    EXPECT_CALL(mock_message, sendSyncMessage(
        HTTPMethod::PATCH,
        "/agents",
        _,
        _,
        _
    )).Times(4).WillRepeatedly(
        DoAll(
            SaveArg<2>(&actual_body),
            Return(HTTPResponse(HTTPStatusCode::HTTP_OK, ""))
        )
    );

    try {
        health_check_periodic_routine();
    } catch (const TestEnd &t) {}

    HealthCheckStatus aggregated_status = i_health_check_manager->getAggregatedStatus();
    string aggregated_status_str = HealthCheckStatusReply::convertHealthCheckStatusToStr(aggregated_status);

    string expected_healthy_body(
        "{\n"
        "    \"healthCheck\": {\n"
        "        \"status\": \"Healthy\",\n"
        "        \"errors\": []\n"
        "    }\n"
        "}"
    );
    EXPECT_EQ(actual_body, expected_healthy_body);
    EXPECT_EQ("Healthy", aggregated_status_str);

    UpdatesProcessEvent(
        UpdatesProcessResult::DEGRADED,
        UpdatesConfigType::SETTINGS,
        UpdatesFailureReason::DOWNLOAD_FILE,
        "setting.json",
        "File not found"
    ).notify();
    UpdatesProcessEvent(
        UpdatesProcessResult::DEGRADED,
        UpdatesConfigType::MANIFEST,
        UpdatesFailureReason::DOWNLOAD_FILE,
        "manifest.json",
        "File not found"
    ).notify();
    try {
        health_check_periodic_routine();
    } catch (const TestEnd &t) {}

    aggregated_status = i_health_check_manager->getAggregatedStatus();
    aggregated_status_str = HealthCheckStatusReply::convertHealthCheckStatusToStr(aggregated_status);

    string expected_degraded_body(
        "{\n"
        "    \"healthCheck\": {\n"
        "        \"status\": \"Degraded\",\n"
        "        \"errors\": [\n"
        "            {\n"
        "                \"code\": \"Orchestration Last Update\",\n"
        "                \"message\": [\n"
        "                    \"Failed to download the file setting.json. Error: File not found\"\n"
        "                ],\n"
        "                \"internal\": true\n"
        "            },\n"
        "            {\n"
        "                \"code\": \"Orchestration Manifest\",\n"
        "                \"message\": [\n"
        "                    \"Failed to download the file manifest.json. Error: File not found\"\n"
        "                ],\n"
        "                \"internal\": true\n"
        "            }\n"
        "        ]\n"
        "    }\n"
        "}"
    );
    EXPECT_EQ(actual_body, expected_degraded_body);
    EXPECT_EQ("Degraded", aggregated_status_str);
}

TEST_F(HealthCheckManagerTest, runOnDemandHealthCheckTest)
{
    const vector<string> health_check{""};
    CPTestTempfile health_check_tmp_file(health_check);

    string config_json =
        "{"
        "   \"agentSettings\": [\n"
        "   {\n"
        "       \"id\": \"yallaHapoel\",\n"
        "       \"key\": \"agent.healthCheck.outputTmpFilePath\",\n"
        "       \"value\": \"" + health_check_tmp_file.fname + "\"\n"
        "   }]\n"
        "}";

    istringstream ss(config_json);
    config.preload();
    Singleton::Consume<Config::I_Config>::from(config)->loadConfiguration(ss);

    UpdatesProcessEvent(
        UpdatesProcessResult::FAILED,
        UpdatesConfigType::MANIFEST,
        UpdatesFailureReason::DOWNLOAD_FILE,
        "manifest.json",
        "File not found"
    ).notify();

    stringstream is;
    is << "{}";
    health_check_server->performRestCall(is);

    string expected_status =
        "{\n"
        "    \"Orchestration\": {\n"
        "        \"status\": \"Unhealthy\",\n"
        "        \"extendedStatus\": {\n"
        "            \"Manifest\": \"Failed to download the file manifest.json. Error: File not found\"\n"
        "        }\n"
        "    }\n"
        "}";

    string health_check_res = health_check_tmp_file.readFile();
    EXPECT_EQ(health_check_res, expected_status);
}
