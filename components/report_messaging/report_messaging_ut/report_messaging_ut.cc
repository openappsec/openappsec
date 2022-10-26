#include "report_messaging.h"

#include <chrono>
#include <string>
#include <sstream>
#include <vector>

#include "config.h"
#include "config_component.h"
#include "cptest.h"
#include "mock/mock_messaging.h"
#include "mock/mock_time_get.h"
#include "mock/mock_environment.h"
#include "cereal/archives/json.hpp"
#include "cereal/types/string.hpp"
#include "cereal/types/common.hpp"

using namespace std;
using namespace testing;

class ReportObject
{
public:
    ReportObject(int _integer_val, string _string_val, vector<int> _vec_val)
            :
        integer_val(_integer_val),
        string_val(_string_val),
        vec_val(_vec_val)
    {
    }

    void
    serialize(cereal::JSONOutputArchive &ar) const
    {
        ar(cereal::make_nvp("integerVal", integer_val));
        ar(cereal::make_nvp("stringVal", string_val));
        ar(cereal::make_nvp("vecVal", vec_val));
    }

    friend ostream &
    operator<<(ostream &os, const ReportObject &)
    {
        return os;
    }

private:
    int integer_val;
    string string_val;
    vector<int> vec_val;
};

class ReportMessagingTest : public Test
{
public:
    ReportMessagingTest()
    {
        EXPECT_CALL(mock_time_get, getWalltime()).WillRepeatedly(Return(chrono::microseconds(0)));
        EXPECT_CALL(mock_time_get, getWalltimeStr(_)).WillRepeatedly(Return("Best Time ever"));
    }

    StrictMock<MockMessaging> mock_messaging;
    StrictMock<MockTimeGet> mock_time_get;

private:
    ConfigComponent config;
};

TEST_F(ReportMessagingTest, title_only)
{
    EXPECT_CALL(
        mock_messaging,
        mockSendPersistentMessage(
            _,
            "{\n"
            "    \"log\": {\n"
            "        \"eventTime\": \"Best Time ever\",\n"
            "        \"eventName\": \"test\",\n"
            "        \"eventSeverity\": \"Info\",\n"
            "        \"eventPriority\": \"Low\",\n"
            "        \"eventType\": \"Event Driven\",\n"
            "        \"eventLevel\": \"Log\",\n"
            "        \"eventLogLevel\": \"info\",\n"
            "        \"eventAudience\": \"Internal\",\n"
            "        \"eventAudienceTeam\": \"Agent Core\",\n"
            "        \"eventFrequency\": 0,\n"
            "        \"eventTags\": [\n"
            "            \"Access Control\"\n"
            "        ],\n"
            "        \"eventSource\": {\n"
            "            \"eventTraceId\": \"\",\n"
            "            \"eventSpanId\": \"\",\n"
            "            \"issuingEngineVersion\": \"\",\n"
            "            \"serviceName\": \"Unnamed Nano Service\"\n"
            "        },\n"
            "        \"eventData\": {\n"
            "            \"eventObject\": 1\n"
            "        }\n"
            "    }\n"
            "}",
            _,
            _,
            _,
            _,
            _
        )
    ).WillOnce(Return(string()));
    ReportMessaging("test", ReportIS::AudienceTeam::AGENT_CORE, 1, ReportIS::Tags::ACCESS_CONTROL);
}

TEST_F(ReportMessagingTest, with_dynamic_fields)
{
    EXPECT_CALL(
        mock_messaging,
        mockSendPersistentMessage(
            _,
            "{\n"
            "    \"log\": {\n"
            "        \"eventTime\": \"Best Time ever\",\n"
            "        \"eventName\": \"test\",\n"
            "        \"eventSeverity\": \"Info\",\n"
            "        \"eventPriority\": \"Low\",\n"
            "        \"eventType\": \"Event Driven\",\n"
            "        \"eventLevel\": \"Log\",\n"
            "        \"eventLogLevel\": \"info\",\n"
            "        \"eventAudience\": \"Internal\",\n"
            "        \"eventAudienceTeam\": \"Agent Core\",\n"
            "        \"eventFrequency\": 0,\n"
            "        \"eventTags\": [\n"
            "            \"Access Control\"\n"
            "        ],\n"
            "        \"eventSource\": {\n"
            "            \"eventTraceId\": \"\",\n"
            "            \"eventSpanId\": \"\",\n"
            "            \"issuingEngineVersion\": \"\",\n"
            "            \"serviceName\": \"Unnamed Nano Service\"\n"
            "        },\n"
            "        \"eventData\": {\n"
            "            \"eventObject\": 1,\n"
            "            \"ASD\": \"QWE\"\n"
            "        }\n"
            "    }\n"
            "}",
            _,
            _,
            _,
            _,
            _
        )
    ).WillOnce(Return(string()));
    ReportMessaging("test", ReportIS::AudienceTeam::AGENT_CORE, 1, ReportIS::Tags::ACCESS_CONTROL)
        << LogField("ASD", "QWE");
}

TEST_F(ReportMessagingTest, custom_event_object)
{
    EXPECT_CALL(
        mock_messaging,
        mockSendPersistentMessage(
            _,
            "{\n"
            "    \"log\": {\n"
            "        \"eventTime\": \"Best Time ever\",\n"
            "        \"eventName\": \"test\",\n"
            "        \"eventSeverity\": \"Info\",\n"
            "        \"eventPriority\": \"Low\",\n"
            "        \"eventType\": \"Event Driven\",\n"
            "        \"eventLevel\": \"Log\",\n"
            "        \"eventLogLevel\": \"info\",\n"
            "        \"eventAudience\": \"Internal\",\n"
            "        \"eventAudienceTeam\": \"Agent Core\",\n"
            "        \"eventFrequency\": 0,\n"
            "        \"eventTags\": [\n"
            "            \"Access Control\"\n"
            "        ],\n"
            "        \"eventSource\": {\n"
            "            \"eventTraceId\": \"\",\n"
            "            \"eventSpanId\": \"\",\n"
            "            \"issuingEngineVersion\": \"\",\n"
            "            \"serviceName\": \"Unnamed Nano Service\"\n"
            "        },\n"
            "        \"eventData\": {\n"
            "            \"eventObject\": {\n"
            "                \"integerVal\": 1,\n"
            "                \"stringVal\": \"2\",\n"
            "                \"vecVal\": [\n"
            "                    1,\n"
            "                    2,\n"
            "                    3\n"
            "                ]\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}",
            _,
            _,
            _,
            _,
            _
        )
    ).WillOnce(Return(string()));

    ReportMessaging(
        "test",
        ReportIS::AudienceTeam::AGENT_CORE,
        ReportObject(1, "2", { 1, 2, 3}),
        ReportIS::Tags::ACCESS_CONTROL
    );
}

TEST_F(ReportMessagingTest, custom_priority)
{
    EXPECT_CALL(
        mock_messaging,
        mockSendPersistentMessage(
            _,
            "{\n"
            "    \"log\": {\n"
            "        \"eventTime\": \"Best Time ever\",\n"
            "        \"eventName\": \"test\",\n"
            "        \"eventSeverity\": \"High\",\n"
            "        \"eventPriority\": \"Medium\",\n"
            "        \"eventType\": \"Event Driven\",\n"
            "        \"eventLevel\": \"Log\",\n"
            "        \"eventLogLevel\": \"info\",\n"
            "        \"eventAudience\": \"Internal\",\n"
            "        \"eventAudienceTeam\": \"Agent Core\",\n"
            "        \"eventFrequency\": 0,\n"
            "        \"eventTags\": [\n"
            "            \"Access Control\"\n"
            "        ],\n"
            "        \"eventSource\": {\n"
            "            \"eventTraceId\": \"\",\n"
            "            \"eventSpanId\": \"\",\n"
            "            \"issuingEngineVersion\": \"\",\n"
            "            \"serviceName\": \"Unnamed Nano Service\"\n"
            "        },\n"
            "        \"eventData\": {\n"
            "            \"eventObject\": {\n"
            "                \"integerVal\": 1,\n"
            "                \"stringVal\": \"2\",\n"
            "                \"vecVal\": [\n"
            "                    1,\n"
            "                    2,\n"
            "                    3\n"
            "                ]\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}",
            _,
            _,
            _,
            _,
            _
        )
    ).WillOnce(Return(string()));

    ReportMessaging(
        "test",
        ReportIS::AudienceTeam::AGENT_CORE,
        ReportIS::Severity::HIGH,
        ReportIS::Priority::MEDIUM,
        ReportObject(1, "2", {1, 2, 3}),
        ReportIS::Tags::ACCESS_CONTROL
    );
}

TEST_F(ReportMessagingTest, with_env_details)
{
    StrictMock<MockEnvironment> mock_env;

    Context context;
    context.registerValue<string>("Service Name", "Access Control App");
    context.registerValue<string>("Service Version", "1.2.3.0.0");
    I_Environment::ActiveContexts active_context({&context}, true);
    EXPECT_CALL(mock_env, getActiveContexts()).WillRepeatedly(ReturnRef(active_context));
    EXPECT_CALL(mock_env, getCurrentTrace()).WillOnce(Return(string("best trace")));
    EXPECT_CALL(mock_env, getCurrentSpan()).WillOnce(Return(string("best span")));

    EXPECT_CALL(
        mock_messaging,
        mockSendPersistentMessage(
            _,
            "{\n"
            "    \"log\": {\n"
            "        \"eventTime\": \"Best Time ever\",\n"
            "        \"eventName\": \"test\",\n"
            "        \"eventSeverity\": \"High\",\n"
            "        \"eventPriority\": \"Medium\",\n"
            "        \"eventType\": \"Event Driven\",\n"
            "        \"eventLevel\": \"Log\",\n"
            "        \"eventLogLevel\": \"info\",\n"
            "        \"eventAudience\": \"Internal\",\n"
            "        \"eventAudienceTeam\": \"Agent Core\",\n"
            "        \"eventFrequency\": 0,\n"
            "        \"eventTags\": [\n"
            "            \"Access Control\"\n"
            "        ],\n"
            "        \"eventSource\": {\n"
            "            \"eventTraceId\": \"best trace\",\n"
            "            \"eventSpanId\": \"best span\",\n"
            "            \"issuingEngineVersion\": \"1.2.3.0.0\",\n"
            "            \"serviceName\": \"Access Control App\"\n"
            "        },\n"
            "        \"eventData\": {\n"
            "            \"eventObject\": {\n"
            "                \"integerVal\": 1,\n"
            "                \"stringVal\": \"2\",\n"
            "                \"vecVal\": [\n"
            "                    1,\n"
            "                    2,\n"
            "                    3\n"
            "                ]\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}",
            _,
            _,
            _,
            _,
            _
        )
    ).WillOnce(Return(string()));

    ReportMessaging(
        "test",
        ReportIS::AudienceTeam::AGENT_CORE,
        ReportIS::Severity::HIGH,
        ReportIS::Priority::MEDIUM,
        ReportObject(1, "2", {1, 2, 3}),
        ReportIS::Tags::ACCESS_CONTROL
    );
}
