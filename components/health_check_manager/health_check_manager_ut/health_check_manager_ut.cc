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

using namespace std;
using namespace testing;

USE_DEBUG_FLAG(D_HEALTH_CHECK);

class TestHealthCheckStatusListener : public Listener<HealthCheckStatusEvent>
{
public:
    void upon(const HealthCheckStatusEvent &) override {}

    HealthCheckStatusReply
    respond(const HealthCheckStatusEvent &) override
    {
        map<string, string> extended_status;
        extended_status["team"] = team;
        extended_status["city"] = city;
        HealthCheckStatusReply reply(comp_name, status, extended_status);
        return reply;
    }

    void setStatus(HealthCheckStatus new_status) { status = new_status; }

    string getListenerName() const { return "TestHealthCheckStatusListener"; }

private:
    static const string comp_name;
    HealthCheckStatus status = HealthCheckStatus::HEALTHY;
    static const string team;
    static const string city;
};

const string TestHealthCheckStatusListener::comp_name = "Test";
const string TestHealthCheckStatusListener::team = "Hapoel";
const string TestHealthCheckStatusListener::city = "Tel-Aviv";

class TestEnd {};

class HealthCheckManagerTest : public Test
{
public:
    HealthCheckManagerTest()
    {
        Debug::setNewDefaultStdout(&debug_output);
        Debug::setUnitTestFlag(D_HEALTH_CHECK, Debug::DebugLevel::INFO);

        EXPECT_CALL(mock_ml, addRecurringRoutine(_, _, _, _, _)).WillRepeatedly(
            DoAll(SaveArg<2>(&health_check_periodic_routine), Return(1))
        );

        EXPECT_CALL(mock_rest, mockRestCall(RestAction::ADD, "declare-boolean-variable", _)).WillOnce(Return(true));

        EXPECT_CALL(mock_rest, mockRestCall(RestAction::SHOW, "health-check-on-demand", _)).WillOnce(
            WithArg<2>(Invoke(this, &HealthCheckManagerTest::setHealthCheckOnDemand))
        );

        env.preload();
        event_listener.registerListener();

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
    stringstream                    debug_output;
    ConfigComponent                 config;
    Config::I_Config                *i_config = nullptr;
    ::Environment                   env;
    HealthCheckManager              health_check_manager;
    I_Health_Check_Manager          *i_health_check_manager;
    unique_ptr<ServerRest>          health_check_server;
    TestHealthCheckStatusListener   event_listener;
};

TEST_F(HealthCheckManagerTest, runPeriodicHealthCheckTest)
{
    string actual_body;
    EXPECT_CALL(
        mock_message,
        sendMessage(
            false,
            _,
            I_Messaging::Method::PATCH,
            "/agents",
            "",
            _,
            _,
            MessageTypeTag::GENERIC
        )
    ).Times(4).WillRepeatedly(DoAll(SaveArg<1>(&actual_body), Return(string())));

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

    event_listener.setStatus(HealthCheckStatus::DEGRADED);
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
        "                \"code\": \"Test city\",\n"
        "                \"message\": [\n"
        "                    \"Tel-Aviv\"\n"
        "                ],\n"
        "                \"internal\": true\n"
        "            },\n"
        "            {\n"
        "                \"code\": \"Test team\",\n"
        "                \"message\": [\n"
        "                    \"Hapoel\"\n"
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

    stringstream is;
    is << "{}";
    health_check_server->performRestCall(is);

    string expected_status =
        "{\n"
        "    \"allComponentsHealthCheckReplies\": {\n"
        "        \"Test\": {\n"
        "            \"status\": \"Healthy\",\n"
        "            \"extendedStatus\": {\n"
        "                \"city\": \"Tel-Aviv\",\n"
        "                \"team\": \"Hapoel\"\n"
        "            }\n"
        "        }\n"
        "    }\n"
        "}";

    string health_check_res = health_check_tmp_file.readFile();
    EXPECT_EQ(health_check_res, expected_status);
}
