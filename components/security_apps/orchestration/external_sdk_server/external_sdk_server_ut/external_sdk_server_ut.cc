#include <stdio.h>
#include <stdarg.h>

#include "external_sdk_server.h"

#include "cptest.h"
#include "mock/mock_rest_api.h"
#include "mock/mock_messaging.h"
#include "mock/mock_logging.h"
#include "mock/mock_time_get.h"
#include "config.h"
#include "config_component.h"
#include "agent_details.h"

using namespace std;
using namespace testing;

class ExternalSdkServerTest : public Test
{
public:
    ExternalSdkServerTest()
    {
        EXPECT_CALL(rest_mocker, mockRestCall(RestAction::ADD, "sdk-call", _)).WillOnce(
            WithArg<2>(
                Invoke(
                    [this](const unique_ptr<RestInit> &rest_ptr)
                    {
                        mock_sdk_rest = rest_ptr->getRest();
                        return true;
                    }
                )
            )
        );

        sdk_server.preload();
        sdk_server.init();
        i_sdk = Singleton::Consume<I_ExternalSdkServer>::from(sdk_server);
    }

    ~ExternalSdkServerTest()
    {
        sdk_server.fini();
    }

    ExternalSdkServer sdk_server;
    NiceMock<MockTimeGet> mock_timer;
    StrictMock<MockMessaging> messaging_mocker;
    StrictMock<MockRestApi> rest_mocker;
    StrictMock<MockLogging> log_mocker;
    unique_ptr<ServerRest> mock_sdk_rest;
    I_ExternalSdkServer *i_sdk;
    ConfigComponent conf;
    AgentDetails agent_details;
    ::Environment env;
};

TEST_F(ExternalSdkServerTest, initTest)
{
}

TEST_F(ExternalSdkServerTest, configCall)
{
    Maybe<string> no_conf = i_sdk->getConfigValue("key1");
    EXPECT_FALSE(no_conf.ok());
    string config_json =
        "{\n"
            "\"agentSettings\": [\n"
                "{\n"
                    "\"id\": \"id1\",\n"
                    "\"key\": \"key1\",\n"
                    "\"value\": \"value1\"\n"
                "},\n"
                "{\n"
                    "\"id\": \"id1\",\n"
                    "\"key\": \"key2\",\n"
                    "\"value\": \"value2\"\n"
                "}\n"
            "]\n"
        "}\n";
    conf.preload();
    istringstream conf_stream(config_json);
    ASSERT_TRUE(Singleton::Consume<Config::I_Config>::from(conf)->loadConfiguration(conf_stream));

    Maybe<string> conf_found = i_sdk->getConfigValue("key1");
    ASSERT_TRUE(conf_found.ok());
    EXPECT_EQ(conf_found.unpack(), "value1");

    conf_found = i_sdk->getConfigValue("key2");
    ASSERT_TRUE(conf_found.ok());
    EXPECT_EQ(conf_found.unpack(), "value2");

    stringstream config_call_body;
    config_call_body << "{ \"eventType\": 3, \"configPath\": \"key1\" }";

    Maybe<string> sdk_conf = mock_sdk_rest->performRestCall(config_call_body);
    ASSERT_TRUE(sdk_conf.ok());
    EXPECT_EQ(
        sdk_conf.unpack(),
        "{\n"
        "    \"configValue\": \"value1\"\n"
        "}"
    );
}

template <typename T>
string
toJson(const T &obj)
{
    stringstream ss;
    {
        cereal::JSONOutputArchive ar(ss);
        obj.serialize(ar);
    }
    return ss.str();
}

TEST_F(ExternalSdkServerTest, eventDrivenCall)
{
    string generated_log;
    EXPECT_CALL(log_mocker, getCurrentLogId()).Times(2).WillRepeatedly(Return(0));
    EXPECT_CALL(log_mocker, sendLog(_)).Times(2).WillRepeatedly(
        WithArg<0>(
            Invoke(
                [&] (const Report &msg)
                {
                    generated_log = toJson(msg);
                }
            )
        )
    );

    i_sdk->sendLog(
        "my log",
        ReportIS::Audience::INTERNAL,
        ReportIS::Severity::LOW,
        ReportIS::Priority::HIGH,
        "IPS",
        {{"key1", "value1"}, {"key2", "value2"}}
    );
    static const string expected_log =
        "{\n"
        "    \"eventTime\": \"\",\n"
        "    \"eventName\": \"my log\",\n"
        "    \"eventSeverity\": \"Low\",\n"
        "    \"eventPriority\": \"High\",\n"
        "    \"eventType\": \"Event Driven\",\n"
        "    \"eventLevel\": \"Log\",\n"
        "    \"eventLogLevel\": \"info\",\n"
        "    \"eventAudience\": \"Internal\",\n"
        "    \"eventAudienceTeam\": \"\",\n"
        "    \"eventFrequency\": 0,\n"
        "    \"eventTags\": [\n"
        "        \"IPS\"\n"
        "    ],\n"
        "    \"eventSource\": {\n"
        "        \"agentId\": \"Unknown\",\n"
        "        \"eventTraceId\": \"\",\n"
        "        \"eventSpanId\": \"\",\n"
        "        \"issuingEngineVersion\": \"\",\n"
        "        \"serviceName\": \"Unnamed Nano Service\"\n"
        "    },\n"
        "    \"eventData\": {\n"
        "        \"logIndex\": 0,\n"
        "        \"key1\": \"value1\",\n"
        "        \"key2\": \"value2\"\n"
        "    }\n"
        "}";

    EXPECT_EQ(generated_log, expected_log);

    string event_call_body =
        "{\n"
        "    \"eventType\": 2,\n"
        "    \"eventName\": \"my log\",\n"
        "    \"audience\": 1,\n"
        "    \"severity\": 3,\n"
        "    \"priority\": 1,\n"
        "    \"tag\": \"IPS\",\n"
        "    \"team\": 3,\n"
        "    \"additionalFields\": {\n"
        "        \"key1\": \"value1\",\n"
        "        \"key2\": \"value2\"\n"
        "    }\n"
        "}";

    generated_log = "";
    stringstream event_call_stream;
    event_call_stream << event_call_body;
    EXPECT_TRUE(mock_sdk_rest->performRestCall(event_call_stream).ok());
    EXPECT_EQ(generated_log, expected_log);
}

TEST_F(ExternalSdkServerTest, periodicEventCall)
{
    string message_body;
    EXPECT_CALL(
        messaging_mocker,
        sendAsyncMessage(
            HTTPMethod::POST,
            "/api/v1/agents/events",
            _,
            MessageCategory::METRIC,
            _,
            false
        )
    ).Times(2).WillRepeatedly(SaveArg<2>(&message_body));

    i_sdk->sendMetric(
        "my metric",
        "matrix",
        ReportIS::AudienceTeam::AGENT_INTELLIGENCE,
        ReportIS::IssuingEngine::AGENT_CORE,
        {{"key", "value"}}
    );

    static const string expected_message =
        "{\n"
        "    \"log\": {\n"
        "        \"eventTime\": \"\",\n"
        "        \"eventName\": \"my metric\",\n"
        "        \"eventSeverity\": \"Info\",\n"
        "        \"eventPriority\": \"Low\",\n"
        "        \"eventType\": \"Periodic\",\n"
        "        \"eventLevel\": \"Log\",\n"
        "        \"eventLogLevel\": \"info\",\n"
        "        \"eventAudience\": \"Internal\",\n"
        "        \"eventAudienceTeam\": \"Agent Intelligence\",\n"
        "        \"eventFrequency\": 0,\n"
        "        \"eventTags\": [\n"
        "            \"Informational\"\n"
        "        ],\n"
        "        \"eventSource\": {\n"
        "            \"agentId\": \"Unknown\",\n"
        "            \"issuingEngine\": \"Agent Core\",\n"
        "            \"eventTraceId\": \"\",\n"
        "            \"eventSpanId\": \"\",\n"
        "            \"issuingEngineVersion\": \"\",\n"
        "            \"serviceName\": \"matrix\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"key\": \"value\"\n"
        "        }\n"
        "    }\n"
        "}";

    EXPECT_EQ(message_body, expected_message);

    string event_call_body =
        "{\n"
        "    \"eventType\": 1,\n"
        "    \"eventName\": \"my metric\",\n"
        "    \"serviceName\": \"matrix\",\n"
        "    \"team\": 3,\n"
        "    \"additionalFields\": {\n"
        "        \"key\": \"value\"\n"
        "    }\n"
        "}";

    stringstream event_call_stream;
    event_call_stream << event_call_body;

    message_body = "";
    EXPECT_TRUE(mock_sdk_rest->performRestCall(event_call_stream).ok());
    EXPECT_EQ(message_body, expected_message);
}

USE_DEBUG_FLAG(D_EXTERNAL_SDK_USER);
USE_DEBUG_FLAG(D_EXTERNAL_SDK_SERVER);

TEST_F(ExternalSdkServerTest, codeEventCall)
{
    ostringstream capture_debug;
    Debug::setUnitTestFlag(D_EXTERNAL_SDK_SERVER, Debug::DebugLevel::TRACE);
    Debug::setUnitTestFlag(D_EXTERNAL_SDK_USER, Debug::DebugLevel::TRACE);
    Debug::setNewDefaultStdout(&capture_debug);

    i_sdk->sendDebug(
        "file.cc",
        "myFunc2",
        42,
        Debug::DebugLevel::TRACE,
        "123",
        "abc",
        "h#l1ow w0r!d",
        {{"hi", "universe"}}
    );

    EXPECT_THAT(
        capture_debug.str(),
        HasSubstr(
            "[myFunc2@file.cc:42                                           | >>>] "
            "h#l1ow w0r!d. \"hi\": \"universe\"\n"
        )
    );


    string debug_event =
        "{\n"
        "    \"eventType\": 0,\n"
        "    \"file\": \"my file\",\n"
        "    \"func\": \"function_name\",\n"
        "    \"line\": 42,\n"
        "    \"debugLevel\": 0,\n"
        "    \"traceId\": \"\",\n"
        "    \"spanId\": \"span2323\",\n"
        "    \"message\": \"some short debug\",\n"
        "    \"team\": 1,\n"
        "    \"additionalFields\": {\n"
        "        \"name\": \"moshe\",\n"
        "        \"food\": \"bamba\"\n"
        "    }\n"
        "}";

    stringstream event_call_stream;
    event_call_stream << debug_event;

    EXPECT_TRUE(mock_sdk_rest->performRestCall(event_call_stream).ok());

    EXPECT_THAT(
        capture_debug.str(),
        HasSubstr(
            "[function_name@my file:42                                     | >>>] "
            "some short debug. \"food\": \"bamba\", \"name\": \"moshe\"\n"
        )
    );

    Debug::setNewDefaultStdout(&cout);
}

TEST_F(ExternalSdkServerTest, ilegalEventCall)
{
    string event_call_body =
        "{\n"
        "    \"eventType\": 7,\n"
        "    \"eventName\": \"my metric\",\n"
        "    \"serviceName\": \"matrix\",\n"
        "    \"team\": 3,\n"
        "    \"additionalFields\": {\n"
        "        \"key\": \"value\"\n"
        "    }\n"
        "}";

    stringstream event_call_stream;
    event_call_stream << event_call_body;

    Maybe<string> failed_respond = mock_sdk_rest->performRestCall(event_call_stream);
    EXPECT_FALSE(failed_respond.ok());
    EXPECT_EQ(failed_respond.getErr(), "Illegal event type provided");
}
