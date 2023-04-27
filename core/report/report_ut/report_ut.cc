#include "report/report.h"
#include "tag_and_enum_management.h"

#include <sstream>
#include <set>

#include "cptest.h"
#include "encryptor.h"
#include "config.h"
#include "config_component.h"
#include "mock/mock_time_get.h"
#include "mock/mock_environment.h"
#include "mock/mock_agent_details.h"
#include "mock/mock_instance_awareness.h"

using namespace testing;
using namespace std;
using namespace ReportIS;

class ReportTest : public Test
{
public:
    ReportTest()
    {
        EXPECT_CALL(mock_timer, getWalltimeStr(_)).WillRepeatedly(Return("0:0:0.123456"));
        EXPECT_CALL(mock_timer, getWalltime()).WillRepeatedly(Return(chrono::seconds(0)));
        EXPECT_CALL(mock_env, getCurrentTrace()).WillRepeatedly(Return(""));
        EXPECT_CALL(mock_env, getCurrentSpan()).WillRepeatedly(Return(""));
        EXPECT_CALL(mock_env, getActiveContexts()).WillRepeatedly(ReturnRef(empty));
        EXPECT_CALL(mock_agent_details, getAgentId()).WillRepeatedly(Return("001"));
        EXPECT_CALL(mock_instance_awareness, getUniqueID()).WillRepeatedly(Return(Maybe<string>(string(""))));
        EXPECT_CALL(mock_instance_awareness, getFamilyID()).WillRepeatedly(Return(Maybe<string>(string(""))));
    }

    string
    toString(ostream& str)
    {
        ostringstream ss;
        ss << str.rdbuf();
        return ss.str();
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

    StrictMock<MockEnvironment> mock_env;
    StrictMock<MockAgentDetails> mock_agent_details;

    void registerServiceName(const string &name) { ctx.registerValue("Service Name", name); }
    void activateObfuscation() { ctx.registerValue<bool>("Obfuscate log field", true); }

private:
    StrictMock<MockTimeGet> mock_timer;
    StrictMock<MockInstanceAwareness> mock_instance_awareness;
    Encryptor encryptor;
    ConfigComponent config;
    Context ctx;
    std::pair<std::vector<Context *>, bool> empty{{&ctx}, true};
};

TEST_F(ReportTest, TagManagementTest)
{
    stringstream os;
    TagAndEnumManagement::print(Tags::NEW_APPROVE_TRANSACTION, os);
    EXPECT_EQ(toString(os), "New Approve Transaction");

    set<Tags> tagSet;
    tagSet.insert(Tags::NEW_APPROVE_TRANSACTION);
    tagSet.insert(Tags::POLICY_INSTALLATION);
    set<string> stringSet;
    stringSet.insert("New Approve Transaction");
    stringSet.insert("Policy Installation");
    EXPECT_EQ(TagAndEnumManagement::convertToString(tagSet), stringSet);
}

TEST(TagTest, TagStringTest)
{
    set<string> tags_string;
    for (Tags tag : makeRange<Tags>()) {
        tags_string = TagAndEnumManagement::convertToString({tag});
        ASSERT_EQ(tags_string.size(), 1);
        Maybe<Tags> tag_from_string = TagAndEnumManagement::convertStringToTag(*tags_string.begin());
        ASSERT_TRUE(tag_from_string.ok());
        EXPECT_EQ(tag_from_string.unpack(), tag);
    }
}

TEST_F(ReportTest, StringConvertion)
{
    EXPECT_EQ(TagAndEnumManagement::convertToString(Severity::CRITICAL), "Critical");
    EXPECT_EQ(TagAndEnumManagement::convertToString(Severity::HIGH),     "High");
    EXPECT_EQ(TagAndEnumManagement::convertToString(Severity::MEDIUM),   "Medium");
    EXPECT_EQ(TagAndEnumManagement::convertToString(Severity::LOW),      "Low");
    EXPECT_EQ(TagAndEnumManagement::convertToString(Severity::INFO),     "Info");

    EXPECT_EQ(TagAndEnumManagement::convertToString(Type::EVENT),    "Event Driven");
    EXPECT_EQ(TagAndEnumManagement::convertToString(Type::PERIODIC), "Periodic");
    EXPECT_EQ(TagAndEnumManagement::convertToString(Type::CODE),     "Code Related");

    EXPECT_EQ(TagAndEnumManagement::convertToString(Level::LOG),      "Log");
    EXPECT_EQ(TagAndEnumManagement::convertToString(Level::INCIDENT), "Incident");
    EXPECT_EQ(TagAndEnumManagement::convertToString(Level::INSIGHT),  "Insight");
    EXPECT_EQ(TagAndEnumManagement::convertToString(Level::ACTION),   "Action Item");
    EXPECT_EQ(TagAndEnumManagement::convertToString(Level::CUSTOM),   "Custom");

    EXPECT_EQ(TagAndEnumManagement::convertToString(LogLevel::TRACE),   "trace");
    EXPECT_EQ(TagAndEnumManagement::convertToString(LogLevel::DEBUG),   "debug");
    EXPECT_EQ(TagAndEnumManagement::convertToString(LogLevel::INFO),    "info");
    EXPECT_EQ(TagAndEnumManagement::convertToString(LogLevel::WARNING), "warning");
    EXPECT_EQ(TagAndEnumManagement::convertToString(LogLevel::ERROR),   "error");

    EXPECT_EQ(TagAndEnumManagement::convertToString(Audience::SECURITY), "Security");
    EXPECT_EQ(TagAndEnumManagement::convertToString(Audience::INTERNAL), "Internal");

    EXPECT_EQ(
        TagAndEnumManagement::convertToString(Notification::POLICY_UPDATE),
        "c0516360-a0b1-4246-af4c-2b6c586958e0"
    );

    EXPECT_EQ(
        TagAndEnumManagement::convertToString(IssuingEngine::AGENT_CORE),
        "Agent Core"
    );
}

TEST_F(ReportTest, TypedField)
{
    EXPECT_EQ(
        toJson(LogField("Integer", 5)),
        "{\n"
        "    \"Integer\": 5\n"
        "}"
    );

    EXPECT_EQ(
        toJson(LogField("String", "Another string")),
        "{\n"
        "    \"String\": \"Another string\"\n"
        "}"
    );
}

TEST_F(ReportTest, TypedFieldXorAndB64)
{
    EXPECT_EQ(
        toJson(LogField("String", "Another string", LogFieldOption::XORANDB64)),
        "{\n"
        "    \"String\": \"Another string\"\n"
        "}"
    );

    activateObfuscation();

    EXPECT_EQ(
        toJson(LogField("String", "Another string", LogFieldOption::XORANDB64)),
        "{\n"
        "    \"String\": \"{XORANDB64}:AgYEJAcMHFQwHBk5AQ4=\"\n"
        "}"
    );

    EXPECT_EQ(
        toJson(LogField("Integer", 5, LogFieldOption::XORANDB64)),
        "{\n"
        "    \"Integer\": 5\n"
        "}"
    );
}

TEST_F(ReportTest, TypedFieldValidation)
{
    I_Environment::ActiveContexts active_context;
    EXPECT_CALL(mock_env, getActiveContexts()).WillRepeatedly(ReturnRef(active_context));

    cptestPrepareToDie();
    EXPECT_DEATH(
        LogField("Integer", 5).addFields(LogField("Integer", 5)),
        "Trying to add a log field to a 'type'ed field"
    );
}

TEST_F(ReportTest, StringTypesToEnum)
{
    EXPECT_TRUE(TagAndEnumManagement::convertStringToSeverity("Critical") == ReportIS::Severity::CRITICAL);
    EXPECT_TRUE(TagAndEnumManagement::convertStringToSeverity("High") == ReportIS::Severity::HIGH);
    EXPECT_TRUE(TagAndEnumManagement::convertStringToSeverity("Medium") == ReportIS::Severity::MEDIUM);
    EXPECT_TRUE(TagAndEnumManagement::convertStringToSeverity("Low") == ReportIS::Severity::LOW);
    EXPECT_TRUE(TagAndEnumManagement::convertStringToSeverity("Info") == ReportIS::Severity::INFO);

    EXPECT_TRUE(TagAndEnumManagement::convertStringToPriority("Urgent") == ReportIS::Priority::URGENT);
    EXPECT_TRUE(TagAndEnumManagement::convertStringToPriority("High") == ReportIS::Priority::HIGH);
    EXPECT_TRUE(TagAndEnumManagement::convertStringToPriority("Medium") == ReportIS::Priority::MEDIUM);
    EXPECT_TRUE(TagAndEnumManagement::convertStringToPriority("Low") == ReportIS::Priority::LOW);

    EXPECT_TRUE(TagAndEnumManagement::convertStringToAudience("Security") == ReportIS::Audience::SECURITY);
    EXPECT_TRUE(TagAndEnumManagement::convertStringToAudience("Internal") == ReportIS::Audience::INTERNAL);

    EXPECT_TRUE(TagAndEnumManagement::convertStringToLevel("Action Item") == ReportIS::Level::ACTION);
    EXPECT_TRUE(TagAndEnumManagement::convertStringToLevel("Custom") == ReportIS::Level::CUSTOM);
    EXPECT_TRUE(TagAndEnumManagement::convertStringToLevel("Incident") == ReportIS::Level::INCIDENT);
    EXPECT_TRUE(TagAndEnumManagement::convertStringToLevel("Insight") == ReportIS::Level::INSIGHT);
    EXPECT_TRUE(TagAndEnumManagement::convertStringToLevel("Log") == ReportIS::Level::LOG);

    EXPECT_TRUE(TagAndEnumManagement::convertStringToLogLevel("Trace") == ReportIS::LogLevel::TRACE);
    EXPECT_TRUE(TagAndEnumManagement::convertStringToLogLevel("Debug") == ReportIS::LogLevel::DEBUG);
    EXPECT_TRUE(TagAndEnumManagement::convertStringToLogLevel("Info") == ReportIS::LogLevel::INFO);
    EXPECT_TRUE(TagAndEnumManagement::convertStringToLogLevel("Warning") == ReportIS::LogLevel::WARNING);
    EXPECT_TRUE(TagAndEnumManagement::convertStringToLogLevel("Error") == ReportIS::LogLevel::ERROR);
}

TEST_F(ReportTest, AggrField)
{
    EXPECT_EQ(
        toJson(LogField("AggField")),
        "{\n"
        "    \"AggField\": {}\n"
        "}"
    );

    EXPECT_EQ(
        toJson(LogField("AggField", LogField("key1", "val1"))),
        "{\n"
        "    \"AggField\": {\n"
        "        \"key1\": \"val1\"\n"
        "    }\n"
        "}"
    );


    auto field = LogField("AggField");
    field.addFields(LogField("key1", "val1"));
    field.addFields(LogField("key2", "val2"));
    field.addFields(LogField("key3", "val3"));

    EXPECT_EQ(
        toJson(field),
        "{\n"
        "    \"AggField\": {\n"
        "        \"key1\": \"val1\",\n"
        "        \"key2\": \"val2\",\n"
        "        \"key3\": \"val3\"\n"
        "    }\n"
        "}"
    );
}

TEST_F(ReportTest, Report)
{
    Tags tag1 = Tags::POLICY_INSTALLATION;
    Tags tag2 = Tags::ACCESS_CONTROL;
    LogField origin("agent", "Secret");

    ::Report report(
        "Log Test",
        chrono::microseconds(90000),
        Type::EVENT,
        Level::LOG,
        LogLevel::INFO,
        Audience::INTERNAL,
        AudienceTeam::AGENT_CORE,
        Severity::INFO,
        Priority::LOW,
        chrono::seconds(3600),
        origin,
        tag1,
        tag2,
        Notification::POLICY_UPDATE,
        IssuingEngine::AGENT_CORE
    );

    EXPECT_EQ(
        toJson(report),
        "{\n"
        "    \"eventTime\": \"0:0:0.123\",\n"
        "    \"eventName\": \"Log Test\",\n"
        "    \"eventSeverity\": \"Info\",\n"
        "    \"eventPriority\": \"Low\",\n"
        "    \"eventType\": \"Event Driven\",\n"
        "    \"eventLevel\": \"Log\",\n"
        "    \"eventLogLevel\": \"info\",\n"
        "    \"eventAudience\": \"Internal\",\n"
        "    \"eventAudienceTeam\": \"Agent Core\",\n"
        "    \"eventFrequency\": 3600,\n"
        "    \"eventTags\": [\n"
        "        \"Access Control\",\n"
        "        \"Policy Installation\"\n"
        "    ],\n"
        "    \"eventSource\": {\n"
        "        \"agent\": \"Secret\",\n"
        "        \"issuingEngine\": \"Agent Core\",\n"
        "        \"eventTraceId\": \"\",\n"
        "        \"eventSpanId\": \"\",\n"
        "        \"issuingEngineVersion\": \"\",\n"
        "        \"serviceName\": \"Unnamed Nano Service\",\n"
        "        \"serviceId\": \"\",\n"
        "        \"serviceFamilyId\": \"\"\n"
        "    },\n"
        "    \"eventData\": {\n"
        "        \"notificationId\": \"c0516360-a0b1-4246-af4c-2b6c586958e0\"\n"
        "    }\n"
        "}"
    );
}

TEST_F(ReportTest, ReportWithoutIssuingEngine)
{
    Tags tag1 = Tags::POLICY_INSTALLATION;
    Tags tag2 = Tags::ACCESS_CONTROL;
    LogField origin("agent", "Secret");

    ::Report report(
        "Log Test",
        chrono::microseconds(90000),
        Type::EVENT,
        Level::LOG,
        LogLevel::INFO,
        Audience::INTERNAL,
        AudienceTeam::AGENT_CORE,
        Severity::INFO,
        Priority::LOW,
        chrono::seconds(3600),
        origin,
        tag1,
        tag2,
        Notification::POLICY_UPDATE
    );

    EXPECT_EQ(
        toJson(report),
        "{\n"
        "    \"eventTime\": \"0:0:0.123\",\n"
        "    \"eventName\": \"Log Test\",\n"
        "    \"eventSeverity\": \"Info\",\n"
        "    \"eventPriority\": \"Low\",\n"
        "    \"eventType\": \"Event Driven\",\n"
        "    \"eventLevel\": \"Log\",\n"
        "    \"eventLogLevel\": \"info\",\n"
        "    \"eventAudience\": \"Internal\",\n"
        "    \"eventAudienceTeam\": \"Agent Core\",\n"
        "    \"eventFrequency\": 3600,\n"
        "    \"eventTags\": [\n"
        "        \"Access Control\",\n"
        "        \"Policy Installation\"\n"
        "    ],\n"
        "    \"eventSource\": {\n"
        "        \"agent\": \"Secret\",\n"
        "        \"eventTraceId\": \"\",\n"
        "        \"eventSpanId\": \"\",\n"
        "        \"issuingEngineVersion\": \"\",\n"
        "        \"serviceName\": \"Unnamed Nano Service\",\n"
        "        \"serviceId\": \"\",\n"
        "        \"serviceFamilyId\": \"\"\n"
        "    },\n"
        "    \"eventData\": {\n"
        "        \"notificationId\": \"c0516360-a0b1-4246-af4c-2b6c586958e0\"\n"
        "    }\n"
        "}"
    );
}

TEST_F(ReportTest, ReportWithoutNotification)
{
    Tags tag1 = Tags::POLICY_INSTALLATION;
    Tags tag2 = Tags::ACCESS_CONTROL;
    LogField origin("agent", "Secret");

    ::Report report(
        "Log Test",
        chrono::microseconds(90000),
        Type::EVENT,
        Level::LOG,
        LogLevel::INFO,
        Audience::INTERNAL,
        AudienceTeam::AGENT_CORE,
        Severity::INFO,
        Priority::LOW,
        chrono::seconds(3600),
        origin,
        tag1,
        tag2,
        IssuingEngine::AGENT_CORE
    );

    EXPECT_EQ(
        toJson(report),
        "{\n"
        "    \"eventTime\": \"0:0:0.123\",\n"
        "    \"eventName\": \"Log Test\",\n"
        "    \"eventSeverity\": \"Info\",\n"
        "    \"eventPriority\": \"Low\",\n"
        "    \"eventType\": \"Event Driven\",\n"
        "    \"eventLevel\": \"Log\",\n"
        "    \"eventLogLevel\": \"info\",\n"
        "    \"eventAudience\": \"Internal\",\n"
        "    \"eventAudienceTeam\": \"Agent Core\",\n"
        "    \"eventFrequency\": 3600,\n"
        "    \"eventTags\": [\n"
        "        \"Access Control\",\n"
        "        \"Policy Installation\"\n"
        "    ],\n"
        "    \"eventSource\": {\n"
        "        \"agent\": \"Secret\",\n"
        "        \"issuingEngine\": \"Agent Core\",\n"
        "        \"eventTraceId\": \"\",\n"
        "        \"eventSpanId\": \"\",\n"
        "        \"issuingEngineVersion\": \"\",\n"
        "        \"serviceName\": \"Unnamed Nano Service\",\n"
        "        \"serviceId\": \"\",\n"
        "        \"serviceFamilyId\": \"\"\n"
        "    },\n"
        "    \"eventData\": {}\n"
        "}"
    );
}

TEST_F(ReportTest, AddOrigin)
{
    Tags tag1 = Tags::POLICY_INSTALLATION;
    Tags tag2 = Tags::ACCESS_CONTROL;
    LogField origin("agent", "Secret");
    LogField another_origin("Bond", "James");

    ::Report report(
        "Log Test",
        chrono::microseconds(90000),
        Type::EVENT,
        Level::LOG,
        LogLevel::INFO,
        Audience::INTERNAL,
        AudienceTeam::AGENT_CORE,
        Severity::INFO,
        Priority::LOW,
        chrono::seconds(0),
        origin,
        tag1,
        tag2,
        Notification::POLICY_UPDATE,
        IssuingEngine::AGENT_CORE
    );
    report.addToOrigin(another_origin);

    EXPECT_EQ(
        toJson(report),
        "{\n"
        "    \"eventTime\": \"0:0:0.123\",\n"
        "    \"eventName\": \"Log Test\",\n"
        "    \"eventSeverity\": \"Info\",\n"
        "    \"eventPriority\": \"Low\",\n"
        "    \"eventType\": \"Event Driven\",\n"
        "    \"eventLevel\": \"Log\",\n"
        "    \"eventLogLevel\": \"info\",\n"
        "    \"eventAudience\": \"Internal\",\n"
        "    \"eventAudienceTeam\": \"Agent Core\",\n"
        "    \"eventFrequency\": 0,\n"
        "    \"eventTags\": [\n"
        "        \"Access Control\",\n"
        "        \"Policy Installation\"\n"
        "    ],\n"
        "    \"eventSource\": {\n"
        "        \"agent\": \"Secret\",\n"
        "        \"issuingEngine\": \"Agent Core\",\n"
        "        \"eventTraceId\": \"\",\n"
        "        \"eventSpanId\": \"\",\n"
        "        \"issuingEngineVersion\": \"\",\n"
        "        \"serviceName\": \"Unnamed Nano Service\",\n"
        "        \"serviceId\": \"\",\n"
        "        \"serviceFamilyId\": \"\",\n"
        "        \"Bond\": \"James\"\n"
        "    },\n"
        "    \"eventData\": {\n"
        "        \"notificationId\": \"c0516360-a0b1-4246-af4c-2b6c586958e0\"\n"
        "    }\n"
        "}"
    );
}

TEST_F(ReportTest, TagSet)
{
    Tags tag1 = Tags::POLICY_INSTALLATION;
    Tags tag2 = Tags::ACCESS_CONTROL;
    Tags tag3 = Tags::FW;
    set<Tags> tag_set = { tag1, tag3 };
    LogField origin("agent", "Secret");

    ::Report report(
        "Log Test",
        chrono::microseconds(90000),
        Type::EVENT,
        Level::LOG,
        LogLevel::INFO,
        Audience::INTERNAL,
        AudienceTeam::AGENT_CORE,
        Severity::INFO,
        Priority::LOW,
        chrono::seconds(0),
        origin,
        tag_set,
        tag2,
        Notification::POLICY_UPDATE,
        IssuingEngine::AGENT_CORE
    );

    EXPECT_EQ(
        toJson(report),
        "{\n"
        "    \"eventTime\": \"0:0:0.123\",\n"
        "    \"eventName\": \"Log Test\",\n"
        "    \"eventSeverity\": \"Info\",\n"
        "    \"eventPriority\": \"Low\",\n"
        "    \"eventType\": \"Event Driven\",\n"
        "    \"eventLevel\": \"Log\",\n"
        "    \"eventLogLevel\": \"info\",\n"
        "    \"eventAudience\": \"Internal\",\n"
        "    \"eventAudienceTeam\": \"Agent Core\",\n"
        "    \"eventFrequency\": 0,\n"
        "    \"eventTags\": [\n"
        "        \"Access Control\",\n"
        "        \"Firewall Information\",\n"
        "        \"Policy Installation\"\n"
        "    ],\n"
        "    \"eventSource\": {\n"
        "        \"agent\": \"Secret\",\n"
        "        \"issuingEngine\": \"Agent Core\",\n"
        "        \"eventTraceId\": \"\",\n"
        "        \"eventSpanId\": \"\",\n"
        "        \"issuingEngineVersion\": \"\",\n"
        "        \"serviceName\": \"Unnamed Nano Service\",\n"
        "        \"serviceId\": \"\",\n"
        "        \"serviceFamilyId\": \"\"\n"
        "    },\n"
        "    \"eventData\": {\n"
        "        \"notificationId\": \"c0516360-a0b1-4246-af4c-2b6c586958e0\"\n"
        "    }\n"
        "}"
    );
}

TEST_F(ReportTest, testSyslogWithoutServiceName)
{
    Tags tag1 = Tags::POLICY_INSTALLATION;
    Tags tag2 = Tags::ACCESS_CONTROL;
    Tags tag3 = Tags::FW;
    set<Tags> tag_set = { tag1, tag3 };
    LogField origin("agent", "Secret");

    ::Report report(
        "Log Test",
        chrono::microseconds(90000),
        Type::EVENT,
        Level::LOG,
        LogLevel::INFO,
        Audience::INTERNAL,
        AudienceTeam::AGENT_CORE,
        Severity::INFO,
        Priority::LOW,
        chrono::seconds(0),
        origin,
        tag_set,
        tag2
    );

    EXPECT_EQ(
        report.getSyslog(),
        "<133>1 0:0:0.123Z cpnano-agent-001 UnnamedNanoService - 0 - "
        "title='Log Test' agent=\"Secret\" eventTraceId=\"\" eventSpanId=\"\" "
        "issuingEngineVersion=\"\" serviceName=\"Unnamed Nano Service\" serviceId=\"\" serviceFamilyId=\"\""
    );
}

TEST_F(ReportTest, testSyslog)
{
    Tags tag1 = Tags::POLICY_INSTALLATION;
    Tags tag2 = Tags::ACCESS_CONTROL;
    Tags tag3 = Tags::FW;
    set<Tags> tag_set = { tag1, tag3 };
    LogField origin("agent", "Secret");

    registerServiceName("Access Control App");

    ::Report report(
        "Log Test",
        chrono::microseconds(90000),
        Type::EVENT,
        Level::LOG,
        LogLevel::INFO,
        Audience::INTERNAL,
        AudienceTeam::AGENT_CORE,
        Severity::INFO,
        Priority::LOW,
        chrono::seconds(0),
        origin,
        tag_set,
        tag2
    );

    vector<vector<string>> f1 = { { "a", "b"}, {"1", "2"} };

    report << LogField("ArrayOfArraies", f1);
    report << LogField("DataWithNewLine", "new\r\nline");
    report << LogField("DataWithQuote", "data'bla");

    string result =
        string("<133>1 0:0:0.123Z cpnano-agent-001 AccessControlApp - 1 - "
        "title='Log Test' agent=\"Secret\"") +
        " eventTraceId=\"\" eventSpanId=\"\" issuingEngineVersion=\"\"" +
        " serviceName=\"Access Control App\" serviceId=\"\" serviceFamilyId=\"\"" +
        string(" ArrayOfArraies=\"[ [ a, b \\], [ 1, 2 \\] \\]\"") +
        string(" DataWithNewLine=\"new\\r\\nline\"") +
        string(" DataWithQuote=\"data\\'bla\"");

    EXPECT_EQ(report.getSyslog(), result);
}

TEST_F(ReportTest, testCef)
{
    Tags tag1 = Tags::POLICY_INSTALLATION;
    Tags tag2 = Tags::ACCESS_CONTROL;
    Tags tag3 = Tags::FW;
    set<Tags> tag_set = { tag1, tag3 };
    LogField origin("agent", "Secret");
    LogField another_origin("Bond", 1);

    registerServiceName("Access Control App");

    ::Report report(
        "Log Test",
        chrono::microseconds(90000),
        Type::EVENT,
        Level::LOG,
        LogLevel::INFO,
        Audience::INTERNAL,
        AudienceTeam::AGENT_CORE,
        Severity::INFO,
        Priority::LOW,
        chrono::seconds(0),
        origin,
        tag_set,
        tag2
    );
    report.addToOrigin(another_origin);

    report << LogField("DataWithQuote", "data'bla");

    EXPECT_EQ(
        report.getCef(),
        "CEF:0|Check Point|AccessControlApp||Event Driven|Log Test|Low|"
        "eventTime=0:0:0.123 agent=\"Secret\" eventTraceId=\"\" eventSpanId=\"\" issuingEngineVersion=\"\""
        " serviceName=\"Access Control App\" serviceId=\"\""
        " serviceFamilyId=\"\" Bond=\"1\" DataWithQuote=\"data\\'bla\""
    );
}

TEST_F(ReportTest, DataAccess)
{
    Tags tag = Tags::FW;
    LogField origin("agent", "Secret");

    ::Report report(
        "Log Test",
        chrono::microseconds(90000),
        Type::EVENT,
        Level::LOG,
        LogLevel::INFO,
        Audience::INTERNAL,
        AudienceTeam::AGENT_CORE,
        Severity::INFO,
        Priority::LOW,
        chrono::seconds(0),
        origin,
        tag
    );

    report << LogField("basic1", "ggg");

    LogField aggr1("aggr1");
    aggr1.addFields(LogField("basic2", "hhh"));
    aggr1.addFields(LogField("basic3", 7));
    report << aggr1;

    auto res1 = report.getStringData("basic1");
    EXPECT_EQ(*res1, "ggg");

    auto res2 = report.getStringData("basic2");
    EXPECT_FALSE(res2.ok());

    auto res3 = report.getStringData("aggr1", "basic2");
    EXPECT_EQ(*res3, "hhh");

    auto res4 = report.getStringData("aggr1", "basic3");
    EXPECT_EQ(*res4, "7");

    auto res5 = report.getStringData("aggr1", "basic3", "no_field");
    EXPECT_FALSE(res5.ok());

    auto res6 = report.getStringData("aggr1");
    EXPECT_FALSE(res6.ok());
}
