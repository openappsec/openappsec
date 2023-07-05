#include "log_generator.h"
#include "log_utils.h"

#include <sstream>
#include <fstream>
#include <set>

#include "cptest.h"
#include "logging_comp.h"
#include "mock/mock_messaging.h"
#include "mock/mock_time_get.h"
#include "mock/mock_rest_api.h"
#include "mock/mock_logging.h"
#include "config.h"
#include "config_component.h"
#include "instance_awareness.h"
#include "environment.h"
#include "agent_details.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_instance_awareness.h"
#include "mock/mock_socket_is.h"
#include "mock/mock_encryptor.h"
#include "mock/mock_agent_details.h"
#include "metric/all_metric_event.h"
#include "mock/mock_shell_cmd.h"
#include "version.h"

using namespace testing;
using namespace std;
using namespace ReportIS;

USE_DEBUG_FLAG(D_REPORT);

class TestEnd {};

static bool should_fail = false;
static bool should_load_file_stream = false;
static bool should_load_k8s_stream = false;

class fakeConfig : Singleton::Consume<I_Logging>
{
public:
    static void
    preload()
    {
        registerExpectedConfiguration<fakeConfig>("fake config");
        registerExpectedConfiguration<bool>("Logging", "Enable event buffer");
        registerExpectedConfiguration<bool>("Logging", "Enable bulk of logs");
        registerExpectedConfiguration<bool>("Logging", "Enable Log skipping");
        registerExpectedConfiguration<string>("Logging", "Log file name");
        registerExpectedConfiguration<string>("Logging", "Fog Log URI");
        registerExpectedConfiguration<string>("Logging", "Syslog IP");
        registerExpectedConfiguration<uint>("Logging", "Syslog port");
        registerExpectedConfiguration<string>("Logging", "CEF IP");
        registerExpectedConfiguration<uint>("Logging", "CEF port");
        registerExpectedConfiguration<uint>("Logging", "Log bulk sending interval in msec");
        registerExpectedConfiguration<uint>("Logging", "Sent log bulk size");
        registerExpectedConfiguration<uint>("Logging", "Maximum number of write retries");
        registerExpectedConfiguration<uint>("Logging", "Metrics Routine Interval");
    }

    void
    load(cereal::JSONInputArchive &ar)
    {
        if (should_fail) throw cereal::Exception("Should fail load");
        if (should_load_file_stream) {
            Singleton::Consume<I_Logging>::by<fakeConfig>()->addStream(ReportIS::StreamType::JSON_LOG_FILE);
            return;
        }
        if (should_load_k8s_stream) {
            Singleton::Consume<I_Logging>::by<fakeConfig>()->addStream(ReportIS::StreamType::JSON_K8S_SVC);
            return;
        }
        Singleton::Consume<I_Logging>::by<fakeConfig>()->addStream(ReportIS::StreamType::JSON_DEBUG);
        Singleton::Consume<I_Logging>::by<fakeConfig>()->addStream(ReportIS::StreamType::JSON_FOG);

        bool is_domain;
        ar(cereal::make_nvp("IsDomain", is_domain));
        if (is_domain) {
            Singleton::Consume<I_Logging>::by<fakeConfig>()->addStream(
                ReportIS::StreamType::CEF,
                "www.youtube.com:123",
                "UDP"
            );
            Singleton::Consume<I_Logging>::by<fakeConfig>()->addStream(
                ReportIS::StreamType::SYSLOG,
                "www.google.com:567",
                "UDP"
            );
        } else {
            Singleton::Consume<I_Logging>::by<fakeConfig>()->addStream(
                ReportIS::StreamType::CEF,
                "1.3.3.0:123", "UDP"
            );
            Singleton::Consume<I_Logging>::by<fakeConfig>()->addStream(
                ReportIS::StreamType::SYSLOG,
                "1.2.3.4:567",
                "UDP"
            );
        }
    }
};

class LogTest : public testing::TestWithParam<bool>
{
public:
    LogTest()
            :
        agent_details(),
        i_agent_details(Singleton::Consume<I_AgentDetails>::from(agent_details)),
        logger(Singleton::Consume<I_Logging>::from(log_comp))
    {
        is_domain = false;
        should_fail = false;
        should_load_file_stream = false;
        should_load_k8s_stream = false;
        env.preload();
        log_comp.preload();
        env.init();

        EXPECT_CALL(
            mock_mainloop,
            addRecurringRoutine(_, _, _, "Logging Fog stream messaging", _)
        ).WillOnce(DoAll(SaveArg<2>(&bulk_routine), Return(1)));

        EXPECT_CALL(
            mock_mainloop,
            addRecurringRoutine(_, _, _, "Metric Fog stream messaging for Logging data", _)
        ).WillOnce(Return(1));

        EXPECT_CALL(mock_mainloop, addOneTimeRoutine(_, _, "Logging Syslog stream messaging", _)).WillRepeatedly(
            DoAll(SaveArg<1>(&sysog_routine), Return(0))
        );

        EXPECT_CALL(mock_socket_is, writeData(1, _)).WillRepeatedly(
            WithArg<1>(
                Invoke(
                    [this](const vector<char> &data)
                    {
                        capture_syslog_cef_data.emplace_back(data.begin(), data.end());
                        return true;
                    }
                )
            )
        );

        EXPECT_CALL(mock_mainloop, doesRoutineExist(_)).WillRepeatedly(Return(true));
        EXPECT_CALL(mock_mainloop, stop(_)).Times(AnyNumber());
        EXPECT_CALL(mock_mainloop, yield(A<bool>())).Times(AnyNumber());

        EXPECT_CALL(mock_timer, getWalltimeStr(_)).WillRepeatedly(Return("0:0:0"));
        EXPECT_CALL(mock_timer, getWalltime()).WillRepeatedly(
            Invoke(
                [&]()
                {
                    return chrono::duration_cast<chrono::microseconds>(chrono::steady_clock::now().time_since_epoch());
                }
            )
        );

        EXPECT_CALL(mock_socket_is, genSocket(_, _, _, _)).WillRepeatedly(Return(1));
        EXPECT_CALL(mock_socket_is, closeSocket(_)).Times(AnyNumber());

        output_filename = file.fname;
        log_comp.init();

        Debug::setUnitTestFlag(D_REPORT, Debug::DebugLevel::DEBUG);
        Debug::setNewDefaultStdout(&capture_debug);
        EXPECT_CALL(
            mock_fog_msg,
            mockSendPersistentMessage(_, _, _, _, _, _, MessageTypeTag::LOG)
        ).WillRepeatedly(DoAll(SaveArg<1>(&body), Return(string())));
    }

    ~LogTest()
    {
        is_domain = false;
        should_fail = false;
        should_load_file_stream = false;
        should_load_k8s_stream = false;
        env.fini();
        log_comp.fini();
        Debug::setUnitTestFlag(D_REPORT, Debug::DebugLevel::INFO);
        Debug::setNewDefaultStdout(&cout);
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

    string
    getMessages()
    {
        auto msgs = capture_debug.str();
        capture_debug.str("");
        return msgs;
    }

    string
    getBodyFogMessage()
    {
        return body;
    }

    void
    cleanBody()
    {
        body = string("");
    }

    string
    readLogFile()
    {
        ofstream file;
        file.open(output_filename, ios::in);

        stringstream string_stream;
        string_stream << file.rdbuf();
        file.close();

        file.open(output_filename, ios::out);
        file << "";
        file.close();
        return string_stream.str();
    }

    bool
    loadFakeConfiguration(
        bool enable_bulk,
        bool domain = false,
        const string &log_file_name = "",
        int bulks_size = -1)
    {
        string is_enable_bulks = enable_bulk ? "true" : "false";
        string is_domain = domain ? "true" : "false";
        fakeConfig::preload();
        output_filename = log_file_name == "" ? file.fname : log_file_name;

        stringstream str_stream;
        str_stream
            << "{\"fake config\": [{\"IsDomain\": "
            << is_domain
            << "}],"
            << "\"Logging\": {\"Log file name\": [{\"value\": \""
            << output_filename
            << "\"}],"
            << "\"Enable bulk of logs\": [{\"value\": "
            << is_enable_bulks
            << "}]";

        if (bulks_size > 0) {
            str_stream << ", \"Sent log bulk size\": [{\"value\": " << bulks_size << "}]";
        }

        str_stream << "}}";

        return Singleton::Consume<Config::I_Config>::from(config)->loadConfiguration(str_stream);
    }

    StrictMock<MockMainLoop>  mock_mainloop;
    StrictMock<MockMessaging> mock_fog_msg;
    StrictMock<MockSocketIS>  mock_socket_is;

    ostringstream             capture_debug;
    LoggingComp               log_comp;
    string                    output_filename;
    AgentDetails              agent_details;
    I_AgentDetails            *i_agent_details;
    I_Logging                 *logger;
    ::Environment             env;
    I_MainLoop::Routine       bulk_routine;
    ConfigComponent           config;
    vector<string>            capture_syslog_cef_data;
    I_MainLoop::Routine       sysog_routine = nullptr;
    StrictMock<MockShellCmd>  mock_shell_cmd;
    bool                      is_domain;

private:
    string                    body;
    StrictMock<MockTimeGet>   mock_timer;
    CPTestTempfile            file;
};

TEST_F(LogTest, load_policy)
{
    EXPECT_TRUE(loadFakeConfiguration(false));
}

TEST_F(LogTest, loadPolicyDomain)
{
    is_domain = true;
    string result = "172.28.1.6";
    EXPECT_CALL(mock_shell_cmd, getExecOutput(_, _, _)).WillRepeatedly(Return(result));
    EXPECT_TRUE(loadFakeConfiguration(false, true));
    string failed_str = "Failed to connect to the CEF server";
    EXPECT_THAT(getMessages(), Not(HasSubstr(failed_str)));
}

TEST_F(LogTest, loadPolicyFailure)
{
    should_fail = true;
    EXPECT_FALSE(loadFakeConfiguration(false));
}

TEST_F(LogTest, LogGen)
{
    loadFakeConfiguration(false);
    Tags tag1 = Tags::POLICY_INSTALLATION;
    Tags tag2 = Tags::ACCESS_CONTROL;

    string str1(
        "{\n"
        "    \"eventTime\": \"0:0:0\",\n"
        "    \"eventName\": \"Install policy\",\n"
        "    \"eventSeverity\": \"Info\",\n"
        "    \"eventPriority\": \"Low\",\n"
        "    \"eventType\": \"Event Driven\",\n"
        "    \"eventLevel\": \"Log\",\n"
        "    \"eventLogLevel\": \"info\",\n"
        "    \"eventAudience\": \"Internal\",\n"
        "    \"eventAudienceTeam\": \"\",\n"
        "    \"eventFrequency\": 0,\n"
        "    \"eventTags\": [\n"
        "        \"Access Control\",\n"
        "        \"Policy Installation\"\n"
        "    ],\n"
        "    \"eventSource\": {\n"
        "        \"agentId\": \"Unknown\",\n"
        "        \"eventTraceId\": \"\",\n"
        "        \"eventSpanId\": \"\",\n"
        "        \"issuingEngineVersion\": \"\",\n"
        "        \"serviceName\": \"Unnamed Nano Service\"\n"
        "    },\n"
        "    \"eventData\": {\n"
        "        \"logIndex\": 1\n"
        "    }\n"
        "}"
    );

    EXPECT_EQ(
        toJson(
            LogGen(
                "Install policy",
                Audience::INTERNAL,
                Severity::INFO,
                Priority::LOW,
                tag1,
                tag2,
                Enreachments::BEAUTIFY_OUTPUT
            )
        ),
        str1
    );
    EXPECT_THAT(getMessages(), HasSubstr(str1));
    EXPECT_THAT(readLogFile(), HasSubstr(str1));

    string str2(
        "{\n"
        "    \"eventTime\": \"0:0:0\",\n"
        "    \"eventName\": \"Install policy\",\n"
        "    \"eventSeverity\": \"Info\",\n"
        "    \"eventPriority\": \"Low\",\n"
        "    \"eventType\": \"Event Driven\",\n"
        "    \"eventLevel\": \"Log\",\n"
        "    \"eventLogLevel\": \"info\",\n"
        "    \"eventAudience\": \"Internal\",\n"
        "    \"eventAudienceTeam\": \"\",\n"
        "    \"eventFrequency\": 0,\n"
        "    \"eventTags\": [\n"
        "        \"Access Control\",\n"
        "        \"Policy Installation\"\n"
        "    ],\n"
        "    \"eventSource\": {\n"
        "        \"agentId\": \"Unknown\",\n"
        "        \"blade\": \"IPS\",\n"
        "        \"ip\": \"1.1.1.1\",\n"
        "        \"eventTraceId\": \"\",\n"
        "        \"eventSpanId\": \"\",\n"
        "        \"issuingEngineVersion\": \"\",\n"
        "        \"serviceName\": \"Unnamed Nano Service\"\n"
        "    },\n"
        "    \"eventData\": {\n"
        "        \"logIndex\": 2\n"
        "    }\n"
        "}"
    );

    EXPECT_EQ(
        toJson(
            LogGen(
                "Install policy",
                Audience::INTERNAL,
                Severity::INFO,
                Priority::LOW,
                LogField("blade", "IPS"),
                LogField("ip", "1.1.1.1"),
                tag1,
                tag2,
                Enreachments::BEAUTIFY_OUTPUT
            )
        ),
        str2
    );
    EXPECT_THAT(getMessages(), HasSubstr(str2));
    EXPECT_THAT(readLogFile(), HasSubstr(str2));

    NiceMock<MockRestApi> mock_rs;
    Singleton::Consume<I_Environment>::from(env)->registerValue<string>("Service Name", "007");
    Version::init();

    string str3(
        "{\n"
        "    \"eventTime\": \"0:0:0\",\n"
        "    \"eventName\": \"Install policy\",\n"
        "    \"eventSeverity\": \"Info\",\n"
        "    \"eventPriority\": \"Low\",\n"
        "    \"eventType\": \"Event Driven\",\n"
        "    \"eventLevel\": \"Log\",\n"
        "    \"eventLogLevel\": \"info\",\n"
        "    \"eventAudience\": \"Internal\",\n"
        "    \"eventAudienceTeam\": \"\",\n"
        "    \"eventFrequency\": 0,\n"
        "    \"eventTags\": [\n"
        "        \"Policy Installation\"\n"
        "    ],\n"
        "    \"eventSource\": {\n"
        "        \"agentId\": \"Unknown\",\n"
        "        \"eventTraceId\": \"\",\n"
        "        \"eventSpanId\": \"\",\n"
        "        \"issuingEngineVersion\": \"" + Version::getFullVersion() + "\",\n"
        "        \"serviceName\": \"007\"\n"
        "    },\n"
        "    \"eventData\": {\n"
        "        \"logIndex\": 3,\n"
        "        \"key\": \"value\"\n"
        "    }\n"
        "}"
    );
    EXPECT_EQ(
        toJson(
            LogGen(
                "Install policy",
                Audience::INTERNAL,
                Severity::INFO,
                Priority::LOW,
                tag1,
                Enreachments::BEAUTIFY_OUTPUT
            ) << LogField("key", string("value"))
        ),
        str3
    );
    EXPECT_THAT(getMessages(), HasSubstr(str3));
    EXPECT_THAT(readLogFile(), HasSubstr(str3));


    enum class TestErrors { CPU, MEMORY, DISK };
    string str4(
        "{\n"
        "    \"eventTime\": \"0:0:0\",\n"
        "    \"eventName\": \"Install policy\",\n"
        "    \"eventSeverity\": \"Info\",\n"
        "    \"eventPriority\": \"Low\",\n"
        "    \"eventType\": \"Event Driven\",\n"
        "    \"eventLevel\": \"Log\",\n"
        "    \"eventLogLevel\": \"info\",\n"
        "    \"eventAudience\": \"Internal\",\n"
        "    \"eventAudienceTeam\": \"\",\n"
        "    \"eventFrequency\": 0,\n"
        "    \"eventTags\": [\n"
        "        \"Policy Installation\"\n"
        "    ],\n"
        "    \"eventSource\": {\n"
        "        \"agentId\": \"Unknown\",\n"
        "        \"eventTraceId\": \"\",\n"
        "        \"eventSpanId\": \"\",\n"
        "        \"issuingEngineVersion\": \"" + Version::getFullVersion() + "\",\n"
        "        \"serviceName\": \"007\"\n"
        "    },\n"
        "    \"eventData\": {\n"
        "        \"logIndex\": 4,\n"
        "        \"eventCode\": \"015-0002\"\n"
        "    }\n"
        "}"
    );
    EXPECT_EQ(
        toJson(
            LogGen(
                "Install policy",
                Audience::INTERNAL,
                Severity::INFO,
                Priority::LOW,
                tag1,
                Enreachments::BEAUTIFY_OUTPUT
            ) << ErrorCode<ReportIS::Tags::IOT>::logError(TestErrors::DISK)
        ),
        str4
    );
    EXPECT_THAT(getMessages(), HasSubstr(str4));
    EXPECT_THAT(readLogFile(), HasSubstr(str4));
}

TEST_F(LogTest, LogSpecificStream)
{
    Tags tag1 = Tags::POLICY_INSTALLATION;
    Tags tag2 = Tags::ACCESS_CONTROL;

    auto getExpectedLogStrOutput =
        []()
        {
            static uint count = 0;
            count++;
            string log_str(
                "{\n"
                "    \"eventTime\": \"0:0:0\",\n"
                "    \"eventName\": \"Install policy\",\n"
                "    \"eventSeverity\": \"Info\",\n"
                "    \"eventPriority\": \"Low\",\n"
                "    \"eventType\": \"Event Driven\",\n"
                "    \"eventLevel\": \"Log\",\n"
                "    \"eventLogLevel\": \"info\",\n"
                "    \"eventAudience\": \"Internal\",\n"
                "    \"eventAudienceTeam\": \"\",\n"
                "    \"eventFrequency\": 0,\n"
                "    \"eventTags\": [\n"
                "        \"Access Control\",\n"
                "        \"Policy Installation\"\n"
                "    ],\n"
                "    \"eventSource\": {\n"
                "        \"agentId\": \"Unknown\",\n"
                "        \"eventTraceId\": \"\",\n"
                "        \"eventSpanId\": \"\",\n"
                "        \"issuingEngineVersion\": \"\",\n"
                "        \"serviceName\": \"Unnamed Nano Service\"\n"
                "    },\n"
                "    \"eventData\": {\n"
                "        \"logIndex\": " + to_string(count) + "\n"
                "    }\n"
                "}"
            );
            return log_str;
        };
    string expected_output = getExpectedLogStrOutput();
    EXPECT_EQ(
        toJson(
            LogGen(
                "Install policy",
                Level::LOG,
                Audience::INTERNAL,
                Severity::INFO,
                Priority::LOW,
                tag1,
                tag2,
                ReportIS::StreamType::JSON_FOG,
                Enreachments::BEAUTIFY_OUTPUT
            )
        ),
        expected_output
    );
    EXPECT_EQ(getMessages(), string(""));
    EXPECT_EQ(readLogFile(), string(""));

    loadFakeConfiguration(false);
    string next_expected_output = getExpectedLogStrOutput();
    EXPECT_EQ(
        toJson(
            LogGen(
                "Install policy",
                Level::LOG,
                Audience::INTERNAL,
                Severity::INFO,
                Priority::LOW,
                tag1,
                tag2,
                ReportIS::StreamType::JSON_DEBUG
            )
        ),
        next_expected_output
    );
    EXPECT_THAT(getMessages(), HasSubstr(next_expected_output));
    EXPECT_EQ(readLogFile(), string(""));

    string last_expected_output = getExpectedLogStrOutput();
    EXPECT_EQ(
        toJson(
            LogGen(
                "Install policy",
                Level::LOG,
                Audience::INTERNAL,
                Severity::INFO,
                Priority::LOW,
                tag1,
                tag2,
                ReportIS::StreamType::JSON_LOG_FILE,
                Enreachments::BEAUTIFY_OUTPUT
            )
        ),
        last_expected_output
    );
    EXPECT_THAT(getMessages(), Not(HasSubstr(last_expected_output)));
    EXPECT_THAT(readLogFile(), HasSubstr(last_expected_output));
}

TEST_F(LogTest, GenLogExtendedFormat)
{
    loadFakeConfiguration(false);
    Tags tag1 = Tags::POLICY_INSTALLATION;
    Tags tag2 = Tags::ACCESS_CONTROL;

    string log(
        "{\n"
        "    \"eventTime\": \"0:0:0\",\n"
        "    \"eventName\": \"Install policy\",\n"
        "    \"eventSeverity\": \"Info\",\n"
        "    \"eventPriority\": \"Low\",\n"
        "    \"eventType\": \"Event Driven\",\n"
        "    \"eventLevel\": \"Insight\",\n"
        "    \"eventLogLevel\": \"info\",\n"
        "    \"eventAudience\": \"Internal\",\n"
        "    \"eventAudienceTeam\": \"\",\n"
        "    \"eventFrequency\": 0,\n"
        "    \"eventTags\": [\n"
        "        \"Access Control\",\n"
        "        \"Policy Installation\"\n"
        "    ],\n"
        "    \"eventSource\": {\n"
        "        \"agentId\": \"Unknown\",\n"
        "        \"eventTraceId\": \"\",\n"
        "        \"eventSpanId\": \"\",\n"
        "        \"issuingEngineVersion\": \"\",\n"
        "        \"serviceName\": \"Unnamed Nano Service\"\n"
        "    },\n"
        "    \"eventData\": {\n"
        "        \"logIndex\": 1\n"
        "    }\n"
        "}"
    );

    EXPECT_EQ(
        toJson(
            LogGen("Install policy", Level::INSIGHT, Audience::INTERNAL, Severity::INFO, Priority::LOW, tag1, tag2)
        ),
        log
    );
}

TEST_F(LogTest, JSONFogTest)
{
    loadFakeConfiguration(false);
    Tags tag1 = Tags::POLICY_INSTALLATION;
    Tags tag2 = Tags::ACCESS_CONTROL;
    setConfiguration<uint>(1, "Logging", "Sent log bulk size");

    string str1(
        "{\n"
        "    \"log\": {\n"
        "        \"eventTime\": \"0:0:0\",\n"
        "        \"eventName\": \"Install policy\",\n"
        "        \"eventSeverity\": \"Info\",\n"
        "        \"eventPriority\": \"Low\",\n"
        "        \"eventType\": \"Event Driven\",\n"
        "        \"eventLevel\": \"Log\",\n"
        "        \"eventLogLevel\": \"info\",\n"
        "        \"eventAudience\": \"Internal\",\n"
        "        \"eventAudienceTeam\": \"\",\n"
        "        \"eventFrequency\": 0,\n"
        "        \"eventTags\": [\n"
        "            \"Access Control\",\n"
        "            \"Policy Installation\"\n"
        "        ],\n"
        "        \"eventSource\": {\n"
        "            \"agentId\": \"Unknown\",\n"
        "            \"eventTraceId\": \"\",\n"
        "            \"eventSpanId\": \"\",\n"
        "            \"issuingEngineVersion\": \"\",\n"
        "            \"serviceName\": \"Unnamed Nano Service\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"logIndex\": 1\n"
        "        }\n"
        "    }\n"
        "}"
    );

    LogGen("Install policy", Audience::INTERNAL, Severity::INFO, Priority::LOW, tag1, tag2);
    EXPECT_EQ(getBodyFogMessage(), str1);

    string str2(
        "{\n"
        "    \"log\": {\n"
        "        \"eventTime\": \"0:0:0\",\n"
        "        \"eventName\": \"Second Install policy\",\n"
        "        \"eventSeverity\": \"Info\",\n"
        "        \"eventPriority\": \"Low\",\n"
        "        \"eventType\": \"Event Driven\",\n"
        "        \"eventLevel\": \"Log\",\n"
        "        \"eventLogLevel\": \"info\",\n"
        "        \"eventAudience\": \"Internal\",\n"
        "        \"eventAudienceTeam\": \"\",\n"
        "        \"eventFrequency\": 0,\n"
        "        \"eventTags\": [\n"
        "            \"Policy Installation\"\n"
        "        ],\n"
        "        \"eventSource\": {\n"
        "            \"agentId\": \"Unknown\",\n"
        "            \"eventTraceId\": \"\",\n"
        "            \"eventSpanId\": \"\",\n"
        "            \"issuingEngineVersion\": \"\",\n"
        "            \"serviceName\": \"Unnamed Nano Service\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"logIndex\": 2\n"
        "        }\n"
        "    }\n"
        "}"
    );

    LogGen("Second Install policy", Audience::INTERNAL, Severity::INFO, Priority::LOW, tag1);
    EXPECT_EQ(getBodyFogMessage(), str2);
}

TEST_F(LogTest, FogBulkLogs)
{
    loadFakeConfiguration(true);
    string local_body;
    string res("[{\"id\": 1, \"code\": 400, \"message\": \"yes\"}]");
    EXPECT_CALL(
        mock_fog_msg,
        mockSendPersistentMessage(_, _, _, _, _, _, MessageTypeTag::LOG)
    ).WillRepeatedly(DoAll(SaveArg<1>(&local_body), Return(res)));

    Tags tag1 = Tags::POLICY_INSTALLATION;
    Tags tag2 = Tags::ACCESS_CONTROL;

    string str1(
        "{\n"
        "    \"logs\": [\n"
        "        {\n"
        "            \"id\": 1,\n"
        "            \"log\": {\n"
        "                \"eventTime\": \"0:0:0\",\n"
        "                \"eventName\": \"Install policy\",\n"
        "                \"eventSeverity\": \"Info\",\n"
        "                \"eventPriority\": \"Low\",\n"
        "                \"eventType\": \"Event Driven\",\n"
        "                \"eventLevel\": \"Log\",\n"
        "                \"eventLogLevel\": \"info\",\n"
        "                \"eventAudience\": \"Internal\",\n"
        "                \"eventAudienceTeam\": \"\",\n"
        "                \"eventFrequency\": 0,\n"
        "                \"eventTags\": [\n"
        "                    \"Access Control\",\n"
        "                    \"Policy Installation\"\n"
        "                ],\n"
        "                \"eventSource\": {\n"
        "                    \"agentId\": \"Unknown\",\n"
        "                    \"eventTraceId\": \"\",\n"
        "                    \"eventSpanId\": \"\",\n"
        "                    \"issuingEngineVersion\": \"\",\n"
        "                    \"serviceName\": \"Unnamed Nano Service\"\n"
        "                },\n"
        "                \"eventData\": {\n"
        "                    \"logIndex\": 1\n"
        "                }\n"
        "            }\n"
        "        }\n"
        "    ]\n"
        "}"
    );

    LogGen("Install policy", Audience::INTERNAL, Severity::INFO, Priority::LOW, tag1, tag2);
    bulk_routine();

    EXPECT_EQ(local_body, str1);
}

TEST_F(LogTest, OfflineK8sSvcTest)
{
    i_agent_details->setOrchestrationMode(OrchestrationMode::HYBRID);
    should_load_k8s_stream = true;
    loadFakeConfiguration(false);
    Tags tag1 = Tags::POLICY_INSTALLATION;
    Tags tag2 = Tags::ACCESS_CONTROL;
    string local_body;
    string res("[{\"id\": 1, \"code\": 400, \"message\": \"yes\"}]");
    EXPECT_CALL(
        mock_fog_msg,
        sendMessage(_, _, _, "open-appsec-tuning-svc", _, _, "/api/v1/agents/events", _, _, MessageTypeTag::LOG)
    ).WillRepeatedly(DoAll(SaveArg<1>(&local_body), Return(res)));

    string str1(
        "{\n"
        "    \"log\": {\n"
        "        \"eventTime\": \"0:0:0\",\n"
        "        \"eventName\": \"Install policy\",\n"
        "        \"eventSeverity\": \"Info\",\n"
        "        \"eventPriority\": \"Low\",\n"
        "        \"eventType\": \"Event Driven\",\n"
        "        \"eventLevel\": \"Log\",\n"
        "        \"eventLogLevel\": \"info\",\n"
        "        \"eventAudience\": \"Internal\",\n"
        "        \"eventAudienceTeam\": \"\",\n"
        "        \"eventFrequency\": 0,\n"
        "        \"eventTags\": [\n"
        "            \"Access Control\",\n"
        "            \"Policy Installation\"\n"
        "        ],\n"
        "        \"eventSource\": {\n"
        "            \"agentId\": \"Unknown\",\n"
        "            \"eventTraceId\": \"\",\n"
        "            \"eventSpanId\": \"\",\n"
        "            \"issuingEngineVersion\": \"\",\n"
        "            \"serviceName\": \"Unnamed Nano Service\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"logIndex\": 1\n"
        "        }\n"
        "    }\n"
        "}"
    );

    LogGen("Install policy", Audience::INTERNAL, Severity::INFO, Priority::LOW, tag1, tag2);
    EXPECT_EQ(local_body, str1);
}

TEST_F(LogTest, OfflineK8sSvcBulkLogs)
{
    i_agent_details->setOrchestrationMode(OrchestrationMode::HYBRID);
    should_load_k8s_stream = true;
    loadFakeConfiguration(true);
    string local_body;
    string res("[{\"id\": 1, \"code\": 400, \"message\": \"yes\"}]");
    EXPECT_CALL(
        mock_fog_msg,
        sendMessage(_, _, _, "open-appsec-tuning-svc", _, _, "/api/v1/agents/events/bulk", _, _, MessageTypeTag::LOG)
    ).WillRepeatedly(DoAll(SaveArg<1>(&local_body), Return(res)));

    Tags tag1 = Tags::POLICY_INSTALLATION;
    Tags tag2 = Tags::ACCESS_CONTROL;


    string str1(
        "{\n"
        "    \"logs\": [\n"
        "        {\n"
        "            \"id\": 1,\n"
        "            \"log\": {\n"
        "                \"eventTime\": \"0:0:0\",\n"
        "                \"eventName\": \"Install policy\",\n"
        "                \"eventSeverity\": \"Info\",\n"
        "                \"eventPriority\": \"Low\",\n"
        "                \"eventType\": \"Event Driven\",\n"
        "                \"eventLevel\": \"Log\",\n"
        "                \"eventLogLevel\": \"info\",\n"
        "                \"eventAudience\": \"Internal\",\n"
        "                \"eventAudienceTeam\": \"\",\n"
        "                \"eventFrequency\": 0,\n"
        "                \"eventTags\": [\n"
        "                    \"Access Control\",\n"
        "                    \"Policy Installation\"\n"
        "                ],\n"
        "                \"eventSource\": {\n"
        "                    \"agentId\": \"Unknown\",\n"
        "                    \"eventTraceId\": \"\",\n"
        "                    \"eventSpanId\": \"\",\n"
        "                    \"issuingEngineVersion\": \"\",\n"
        "                    \"serviceName\": \"Unnamed Nano Service\"\n"
        "                },\n"
        "                \"eventData\": {\n"
        "                    \"logIndex\": 1\n"
        "                }\n"
        "            }\n"
        "        }\n"
        "    ]\n"
        "}"
    );
    {
    LogGen("Install policy", Audience::INTERNAL, Severity::INFO, Priority::LOW, tag1, tag2);
    }
    bulk_routine();

    EXPECT_EQ(local_body, str1);
}

TEST_P(LogTest, metrics_check)
{
    loadFakeConfiguration(true, false, "", 3);
    Tags tag1 = Tags::POLICY_INSTALLATION;
    Tags tag2 = Tags::ACCESS_CONTROL;

    LogGen("Install policy", Audience::INTERNAL, Severity::INFO, Priority::LOW, tag1, tag2);
    LogGen("Install policy", Audience::INTERNAL, Severity::INFO, Priority::LOW, tag1, tag2);
    LogGen("Install policy", Audience::INTERNAL, Severity::INFO, Priority::LOW, tag1, tag2);
    LogGen("Install policy", Audience::INTERNAL, Severity::INFO, Priority::LOW, tag1, tag2);
    LogGen("Install policy", Audience::INTERNAL, Severity::INFO, Priority::LOW, tag1, tag2);
    LogGen("Install policy", Audience::INTERNAL, Severity::INFO, Priority::LOW, tag1, tag2);
    LogGen("Install policy", Audience::INTERNAL, Severity::INFO, Priority::LOW, tag1, tag2);
    bulk_routine();

    string logging_metric_str =
        "{\n"
        "    \"Metric\": \"Logging data\",\n"
        "    \"Reporting interval\": 600,\n"
        "    \"logQueueMaxSizeSample\": 7,\n"
        "    \"logQueueAvgSizeSample\": 4.0,\n"
        "    \"logQueueCurrentSizeSample\": 1,\n"
        "    \"sentLogsSum\": 7,\n"
        "    \"sentLogsBulksSum\": 3\n"
        "}";

    bool is_named_query = GetParam();
    if (is_named_query) {
        EXPECT_THAT(AllMetricEvent().performNamedQuery(), ElementsAre(Pair("Logging data", logging_metric_str)));
    } else {
        EXPECT_THAT(AllMetricEvent().query(), ElementsAre(logging_metric_str));
    }
}

INSTANTIATE_TEST_CASE_P(metrics_check, LogTest, ::testing::Values(false, true));

TEST_F(LogTest, DeleteStreamTest)
{
    loadFakeConfiguration(false);
    Tags tag1 = Tags::POLICY_INSTALLATION;
    Tags tag2 = Tags::ACCESS_CONTROL;

    string str1(
        "{\n"
        "    \"eventTime\": \"0:0:0\",\n"
        "    \"eventName\": \"Install policy\",\n"
        "    \"eventSeverity\": \"Critical\",\n"
        "    \"eventPriority\": \"High\",\n"
        "    \"eventType\": \"Event Driven\",\n"
        "    \"eventLevel\": \"Log\",\n"
        "    \"eventLogLevel\": \"info\",\n"
        "    \"eventAudience\": \"Security\",\n"
        "    \"eventAudienceTeam\": \"\",\n"
        "    \"eventFrequency\": 0,\n"
        "    \"eventTags\": [\n"
        "        \"Access Control\",\n"
        "        \"Policy Installation\"\n"
        "    ],\n"
        "    \"eventSource\": {\n"
        "        \"agentId\": \"Unknown\",\n"
        "        \"eventTraceId\": \"\",\n"
        "        \"eventSpanId\": \"\",\n"
        "        \"issuingEngineVersion\": \"\",\n"
        "        \"serviceName\": \"Unnamed Nano Service\"\n"
        "    },\n"
        "    \"eventData\": {\n"
        "        \"logIndex\": 1\n"
        "    }\n"
        "}"
    );

    string str2(
        "{\n"
        "    \"log\": {\n"
        "        \"eventTime\": \"0:0:0\",\n"
        "        \"eventName\": \"Install policy\",\n"
        "        \"eventSeverity\": \"Critical\",\n"
        "        \"eventPriority\": \"High\",\n"
        "        \"eventType\": \"Event Driven\",\n"
        "        \"eventLevel\": \"Log\",\n"
        "        \"eventLogLevel\": \"info\",\n"
        "        \"eventAudience\": \"Security\",\n"
        "        \"eventAudienceTeam\": \"\",\n"
        "        \"eventFrequency\": 0,\n"
        "        \"eventTags\": [\n"
        "            \"Access Control\",\n"
        "            \"Policy Installation\"\n"
        "        ],\n"
        "        \"eventSource\": {\n"
        "            \"agentId\": \"Unknown\",\n"
        "            \"eventTraceId\": \"\",\n"
        "            \"eventSpanId\": \"\",\n"
        "            \"issuingEngineVersion\": \"\",\n"
        "            \"serviceName\": \"Unnamed Nano Service\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"logIndex\": 1\n"
        "        }\n"
        "    }\n"
        "}"
    );

    EXPECT_EQ(
        toJson(
            LogGen(
                "Install policy",
                Audience::SECURITY,
                Severity::CRITICAL,
                Priority::HIGH,
                tag1,
                tag2,
                Enreachments::BEAUTIFY_OUTPUT
            )
        ),
        str1
    );
    EXPECT_THAT(getMessages(), HasSubstr(str1));

    EXPECT_EQ(getBodyFogMessage(), str2);
    EXPECT_THAT(readLogFile(), HasSubstr(str1));

    cleanBody();
    Debug::setUnitTestFlag(D_REPORT, Debug::DebugLevel::INFO);
    EXPECT_TRUE(logger->delStream(ReportIS::StreamType::JSON_DEBUG));
    EXPECT_TRUE(logger->delStream(ReportIS::StreamType::JSON_FOG));
    EXPECT_TRUE(logger->delStream(ReportIS::StreamType::JSON_LOG_FILE));
    EXPECT_TRUE(logger->delStream(ReportIS::StreamType::CEF));
    EXPECT_TRUE(logger->delStream(ReportIS::StreamType::SYSLOG));
    capture_debug.str("");

    LogGen("Install policy", Audience::SECURITY, Severity::CRITICAL, Priority::HIGH, tag1, tag2);
    EXPECT_EQ(getBodyFogMessage(), string(""));
    EXPECT_EQ(getMessages(), string(""));
    EXPECT_EQ(readLogFile(), string(""));

    EXPECT_FALSE(logger->delStream(ReportIS::StreamType::JSON_DEBUG));
    EXPECT_FALSE(logger->delStream(ReportIS::StreamType::JSON_FOG));
    EXPECT_FALSE(logger->delStream(ReportIS::StreamType::JSON_LOG_FILE));
    Debug::setUnitTestFlag(D_REPORT, Debug::DebugLevel::TRACE);
}

TEST_F(LogTest, ShouldRetryAfterFailedWriteToFile)
{
    loadFakeConfiguration(false);
    EXPECT_TRUE(logger->delStream(ReportIS::StreamType::JSON_LOG_FILE));

    static const string invalid_file_path = "/proc/gibberish";
    loadFakeConfiguration(false, false, invalid_file_path, -1);

    LogGen(
        "Install policy",
        Audience::INTERNAL,
        Severity::INFO,
        Priority::LOW,
        Tags::POLICY_INSTALLATION,
        Tags::ACCESS_CONTROL
    );

    string debug_messages = getMessages();
    EXPECT_THAT(
        debug_messages,
        HasSubstr("Failed to write log to file, will retry. File path: " + invalid_file_path)
    );
}

TEST_F(LogTest, automaticly_added_fields)
{
    using Log = EnvKeyAttr::LogSection;
    Buffer buf("DDD", 3, Buffer::MemoryType::STATIC);

    ScopedContext ctx;
    ctx.registerValue<string>("SourceA", "AAA", Log::SOURCE);
    ctx.registerValue<string>("SourceB", "BBB", Log::SOURCE);
    ctx.registerValue<string>("NotInTheLog", "CCC");
    ctx.registerValue("SourceC", buf, Log::SOURCE);
    ctx.registerValue("DataA", 5, Log::DATA);
    ctx.registerValue("DataB", 92, Log::DATA);
    ctx.registerValue("ToBeOrNotToBe", true, Log::DATA);

    string str1(
        "{\n"
        "    \"eventTime\": \"0:0:0\",\n"
        "    \"eventName\": \"Install policy\",\n"
        "    \"eventSeverity\": \"Critical\",\n"
        "    \"eventPriority\": \"High\",\n"
        "    \"eventType\": \"Event Driven\",\n"
        "    \"eventLevel\": \"Log\",\n"
        "    \"eventLogLevel\": \"info\",\n"
        "    \"eventAudience\": \"Security\",\n"
        "    \"eventAudienceTeam\": \"\",\n"
        "    \"eventFrequency\": 0,\n"
        "    \"eventTags\": [\n"
        "        \"Access Control\",\n"
        "        \"Policy Installation\"\n"
        "    ],\n"
        "    \"eventSource\": {\n"
        "        \"agentId\": \"Unknown\",\n"
        "        \"eventTraceId\": \"\",\n"
        "        \"eventSpanId\": \"\",\n"
        "        \"issuingEngineVersion\": \"\",\n"
        "        \"serviceName\": \"Unnamed Nano Service\",\n"
        "        \"SourceA\": \"AAA\",\n"
        "        \"SourceB\": \"BBB\",\n"
        "        \"SourceC\": \"DDD\"\n"
        "    },\n"
        "    \"eventData\": {\n"
        "        \"logIndex\": 1,\n"
        "        \"DataA\": 5,\n"
        "        \"DataB\": 92,\n"
        "        \"ToBeOrNotToBe\": true\n"
        "    }\n"
        "}"
    );
    loadFakeConfiguration(false);
    Tags tag1 = Tags::POLICY_INSTALLATION;
    Tags tag2 = Tags::ACCESS_CONTROL;
    LogGen("Install policy", Audience::SECURITY, Severity::CRITICAL, Priority::HIGH, tag1, tag2);
    EXPECT_THAT(getMessages(), HasSubstr(str1));
}

TEST(LogTestInstanceAwareness, LogGenInstanceAwareness)
{
    ::Environment env;
    ConfigComponent config;
    StrictMock<MockMainLoop>  mock_mainloop;
    StrictMock<MockTimeGet> mock_timer;
    StrictMock<MockMessaging> mock_fog_msg;
    StrictMock<MockSocketIS> mock_socket_is;
    AgentDetails agent_details;
    LoggingComp log_comp;

    EXPECT_CALL(
        mock_fog_msg,
        mockSendPersistentMessage(_, _, _, _, _, _, MessageTypeTag::LOG)
    ).WillRepeatedly(Return(string()));
    EXPECT_CALL(mock_socket_is, genSocket(_, _, _, _)).WillRepeatedly(Return(1));
    EXPECT_CALL(mock_socket_is, closeSocket(_)).Times(AnyNumber());
    EXPECT_CALL(mock_mainloop, doesRoutineExist(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock_mainloop, stop(_)).Times(AnyNumber());

    EXPECT_CALL(mock_timer, getWalltimeStr(_)).WillRepeatedly(Return("0:0:0"));
    EXPECT_CALL(mock_timer, getWalltime()).WillRepeatedly(
        Invoke(
            [&]()
            {
                return chrono::duration_cast<chrono::microseconds>(chrono::steady_clock::now().time_since_epoch());
            }
        )
    );

    string family_id = "073b8744b4c5";
    string id = family_id + "-11";
    StrictMock<MockInstanceAwareness> mock_aware;
    EXPECT_CALL(mock_aware, getUniqueID(_)).WillRepeatedly(Return(id));
    EXPECT_CALL(mock_aware, getUniqueID()).WillRepeatedly(Return(id));
    EXPECT_CALL(mock_aware, getFamilyID()).WillRepeatedly(Return(family_id));

    string str1(
        "{\n"
        "    \"eventTime\": \"0:0:0\",\n"
        "    \"eventName\": \"Install policy\",\n"
        "    \"eventSeverity\": \"Info\",\n"
        "    \"eventPriority\": \"Low\",\n"
        "    \"eventType\": \"Event Driven\",\n"
        "    \"eventLevel\": \"Log\",\n"
        "    \"eventLogLevel\": \"info\",\n"
        "    \"eventAudience\": \"Internal\",\n"
        "    \"eventAudienceTeam\": \"\",\n"
        "    \"eventFrequency\": 0,\n"
        "    \"eventTags\": [\n"
        "        \"Access Control\",\n"
        "        \"Policy Installation\"\n"
        "    ],\n"
        "    \"eventSource\": {\n"
        "        \"agentId\": \"Unknown\",\n"
        "        \"eventTraceId\": \"\",\n"
        "        \"eventSpanId\": \"\",\n"
        "        \"issuingEngineVersion\": \"\",\n"
        "        \"serviceName\": \"Unnamed Nano Service\",\n"
        "        \"serviceId\": \"" + id + "\",\n"
        "        \"serviceFamilyId\": \"" + family_id + "\"\n"
        "    },\n"
        "    \"eventData\": {\n"
        "        \"logIndex\": 1\n"
        "    }\n"
        "}"
    );

    static const string output_filename("/tmp/cptest_temp_file_random_x");
    string new_output_filename = output_filename + id;
    remove(new_output_filename.c_str());

    should_load_file_stream = true;
    env.preload();
    log_comp.preload();
    fakeConfig::preload();
    stringstream ss;
    ss
        << "{\"fake config\": [{}], \"Logging\": {\"Log file name\": [{\"value\": \"" << output_filename << "\"}],"
        << "\"Enable bulk of logs\": [{\"value\": false}]";
    ss << "}}";
    env.init();
    Singleton::Consume<Config::I_Config>::from(config)->loadConfiguration(ss);

    {
        LogGen(
            "Install policy",
            Audience::INTERNAL,
            Severity::INFO,
            Priority::LOW,
            Tags::POLICY_INSTALLATION,
            Tags::ACCESS_CONTROL,
            Enreachments::BEAUTIFY_OUTPUT
        );
    }
    ifstream text_file(new_output_filename);
    EXPECT_TRUE(text_file.is_open());
    stringstream buffer;
    buffer << text_file.rdbuf();
    EXPECT_THAT(buffer.str(), HasSubstr(str1));
}

TEST(LogTestWithoutComponent, RegisterBasicConfig)
{
    ::Environment env;
    ConfigComponent config;
    NiceMock<MockMainLoop> mock_mainloop;
    NiceMock<MockTimeGet> mock_timer;
    StrictMock<MockMessaging> mock_fog_msg;
    StrictMock<MockAgentDetails> mock_agent_details;
    EXPECT_CALL(mock_agent_details, getOrchestrationMode()).WillRepeatedly(Return(OrchestrationMode::ONLINE));

    EXPECT_CALL(
        mock_fog_msg,
        mockSendPersistentMessage(_, _, _, _, _, _, MessageTypeTag::LOG)
    ).WillRepeatedly(Return(string()));

    LoggingComp log_comp;
    log_comp.preload();
    fakeConfig::preload();
    string config_json =
        "{\n"
        "    \"fake config\": [{}],"
        "    \"Logging\": {\n"
        "        \"Log file name\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"/etc/ngen/logs/fw.log\"\n"
        "            }\n"
        "        ],\n"
        "        \"Fog Log URI\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"/es/log/log\"\n"
        "            }\n"
        "        ]\n"
        "    }\n"
        "}\n";

    istringstream ss(config_json);
    Singleton::Consume<Config::I_Config>::from(config)->loadConfiguration(ss);

    EXPECT_THAT(getConfiguration<string>("Logging", "Log file name"), IsValue("/etc/ngen/logs/fw.log"));
    EXPECT_THAT(getConfiguration<string>("Logging", "Fog Log URI"), IsValue("/es/log/log"));
}

TEST(LogTestWithoutComponent, RegisterAdvancedConfig)
{
    ::Environment env;
    ConfigComponent config;
    NiceMock<MockMainLoop> mock_mainloop;
    NiceMock<MockTimeGet> mock_timer;
    StrictMock<MockMessaging> mock_fog_msg;
    StrictMock<MockAgentDetails> mock_agent_details;
    EXPECT_CALL(mock_agent_details, getOrchestrationMode()).WillRepeatedly(Return(OrchestrationMode::ONLINE));

    EXPECT_CALL(
        mock_fog_msg,
        mockSendPersistentMessage(_, _, _, _, _, _, MessageTypeTag::LOG)
    ).WillRepeatedly(Return(string()));

    LoggingComp log_comp;
    log_comp.preload();

    string config_json =
        "{\n"
        "    \"Logging\": {\n"
        "        \"Log file name\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"/etc/ngen/logs/fw.log\"\n"
        "            }\n"
        "        ],\n"
        "        \"Fog Log URI\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"/es/log/log\"\n"
        "            }\n"
        "        ],\n"
        "        \"Log bulk sending interval in msec\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": 1000\n"
        "            }\n"
        "        ],\n"
        "        \"Sent log bulk size\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": 100\n"
        "            }\n"
        "        ]\n"
        "    }\n"
        "}\n";
    istringstream ss(config_json);
    Singleton::Consume<Config::I_Config>::from(config)->loadConfiguration(ss);

    EXPECT_THAT(getConfiguration<string>("Logging", "Log file name"), IsValue("/etc/ngen/logs/fw.log"));
    EXPECT_THAT(getConfiguration<string>("Logging", "Fog Log URI"), IsValue("/es/log/log"));
    EXPECT_THAT(getConfiguration<uint>("Logging", "Log bulk sending interval in msec"), IsValue(1000));
    EXPECT_THAT(getConfiguration<uint>("Logging", "Sent log bulk size"), IsValue(100));
}

void
changeOne(LogBulkRest &bulk)
{
    for (auto &log : bulk) {
        log << LogField("change one", "this is new!");
    }
}

void
changeTwo(LogBulkRest &bulk)
{
    uint i = 0;
    for (auto &log : bulk) {
        log << LogField("change two", ++i);
    }
}

TEST_F(LogTest, BulkModification)
{
    string local_body;
    string res("[{\"id\": 1, \"code\": 400, \"message\": \"yes\"}]");
    EXPECT_CALL(
        mock_fog_msg,
        mockSendPersistentMessage(_, _, _, _, _, _, MessageTypeTag::LOG)
    ).WillRepeatedly(DoAll(SaveArg<1>(&local_body), Return(res)));

    logger->addGeneralModifier(changeOne);
    logger->addGeneralModifier(changeTwo);
    loadFakeConfiguration(true);
    Tags tag1 = Tags::POLICY_INSTALLATION;
    Tags tag2 = Tags::ACCESS_CONTROL;

    LogGen(
        "Install policy",
        Audience::INTERNAL,
        Severity::INFO,
        Priority::LOW,
        tag1,
        tag2,
        Enreachments::BEAUTIFY_OUTPUT
    );

    LogGen(
        "Install policy",
        Audience::INTERNAL,
        Severity::INFO,
        Priority::LOW,
        tag1,
        tag2,
        Enreachments::BEAUTIFY_OUTPUT
    );

    bulk_routine();

    string str1(
        "{\n"
        "    \"logs\": [\n"
        "        {\n"
        "            \"id\": 1,\n"
        "            \"log\": {\n"
        "                \"eventTime\": \"0:0:0\",\n"
        "                \"eventName\": \"Install policy\",\n"
        "                \"eventSeverity\": \"Info\",\n"
        "                \"eventPriority\": \"Low\",\n"
        "                \"eventType\": \"Event Driven\",\n"
        "                \"eventLevel\": \"Log\",\n"
        "                \"eventLogLevel\": \"info\",\n"
        "                \"eventAudience\": \"Internal\",\n"
        "                \"eventAudienceTeam\": \"\",\n"
        "                \"eventFrequency\": 0,\n"
        "                \"eventTags\": [\n"
        "                    \"Access Control\",\n"
        "                    \"Policy Installation\"\n"
        "                ],\n"
        "                \"eventSource\": {\n"
        "                    \"agentId\": \"Unknown\",\n"
        "                    \"eventTraceId\": \"\",\n"
        "                    \"eventSpanId\": \"\",\n"
        "                    \"issuingEngineVersion\": \"\",\n"
        "                    \"serviceName\": \"Unnamed Nano Service\"\n"
        "                },\n"
        "                \"eventData\": {\n"
        "                    \"logIndex\": 1,\n"
        "                    \"change one\": \"this is new!\",\n"
        "                    \"change two\": 1\n"
        "                }\n"
        "            }\n"
        "        },\n"
        "        {\n"
        "            \"id\": 2,\n"
        "            \"log\": {\n"
        "                \"eventTime\": \"0:0:0\",\n"
        "                \"eventName\": \"Install policy\",\n"
        "                \"eventSeverity\": \"Info\",\n"
        "                \"eventPriority\": \"Low\",\n"
        "                \"eventType\": \"Event Driven\",\n"
        "                \"eventLevel\": \"Log\",\n"
        "                \"eventLogLevel\": \"info\",\n"
        "                \"eventAudience\": \"Internal\",\n"
        "                \"eventAudienceTeam\": \"\",\n"
        "                \"eventFrequency\": 0,\n"
        "                \"eventTags\": [\n"
        "                    \"Access Control\",\n"
        "                    \"Policy Installation\"\n"
        "                ],\n"
        "                \"eventSource\": {\n"
        "                    \"agentId\": \"Unknown\",\n"
        "                    \"eventTraceId\": \"\",\n"
        "                    \"eventSpanId\": \"\",\n"
        "                    \"issuingEngineVersion\": \"\",\n"
        "                    \"serviceName\": \"Unnamed Nano Service\"\n"
        "                },\n"
        "                \"eventData\": {\n"
        "                    \"logIndex\": 2,\n"
        "                    \"change one\": \"this is new!\",\n"
        "                    \"change two\": 2\n"
        "                }\n"
        "            }\n"
        "        }\n"
        "    ]\n"
        "}"
    );

    EXPECT_EQ(local_body, str1);
}

TEST_F(LogTest, ObfuscationTest)
{
    loadFakeConfiguration(false);
    Tags tag1 = Tags::POLICY_INSTALLATION;
    Tags tag2 = Tags::ACCESS_CONTROL;

    static const string expected_obfuscated_log(
        "{\n"
        "    \"log\": {\n"
        "        \"eventTime\": \"0:0:0\",\n"
        "        \"eventName\": \"Install policy\",\n"
        "        \"eventSeverity\": \"Info\",\n"
        "        \"eventPriority\": \"Low\",\n"
        "        \"eventType\": \"Event Driven\",\n"
        "        \"eventLevel\": \"Log\",\n"
        "        \"eventLogLevel\": \"info\",\n"
        "        \"eventAudience\": \"Internal\",\n"
        "        \"eventAudienceTeam\": \"\",\n"
        "        \"eventFrequency\": 0,\n"
        "        \"eventTags\": [\n"
        "            \"Access Control\",\n"
        "            \"Policy Installation\"\n"
        "        ],\n"
        "        \"eventSource\": {\n"
        "            \"agentId\": \"Unknown\",\n"
        "            \"eventTraceId\": \"\",\n"
        "            \"eventSpanId\": \"\",\n"
        "            \"issuingEngineVersion\": \"\",\n"
        "            \"serviceName\": \"Unnamed Nano Service\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"logIndex\": 1,\n"
        "            \"String\": \"{XORANDB64}:mocked field\"\n"
        "        }\n"
        "    }\n"
        "}"
    );
    StrictMock<MockEncryptor> mock_encrypt;
    EXPECT_CALL(mock_encrypt, base64Encode(_)).WillOnce(Return("mocked field"));

    static const string expected_clear_log(
        "{\n"
        "    \"eventTime\": \"0:0:0\",\n"
        "    \"eventName\": \"Install policy\",\n"
        "    \"eventSeverity\": \"Info\",\n"
        "    \"eventPriority\": \"Low\",\n"
        "    \"eventType\": \"Event Driven\",\n"
        "    \"eventLevel\": \"Log\",\n"
        "    \"eventLogLevel\": \"info\",\n"
        "    \"eventAudience\": \"Internal\",\n"
        "    \"eventAudienceTeam\": \"\",\n"
        "    \"eventFrequency\": 0,\n"
        "    \"eventTags\": [\n"
        "        \"Access Control\",\n"
        "        \"Policy Installation\"\n"
        "    ],\n"
        "    \"eventSource\": {\n"
        "        \"agentId\": \"Unknown\",\n"
        "        \"eventTraceId\": \"\",\n"
        "        \"eventSpanId\": \"\",\n"
        "        \"issuingEngineVersion\": \"\",\n"
        "        \"serviceName\": \"Unnamed Nano Service\"\n"
        "    },\n"
        "    \"eventData\": {\n"
        "        \"logIndex\": 1,\n"
        "        \"String\": \"Another string\"\n"
        "    }\n"
        "}"
    );

    {
        LogGen log(
            "Install policy",
            Audience::INTERNAL,
            Severity::INFO,
            Priority::LOW,
            tag1,
            tag2,
            Enreachments::BEAUTIFY_OUTPUT
        );
        log << LogField("String", "Another string", LogFieldOption::XORANDB64);
        EXPECT_EQ(toJson(log), expected_clear_log);
    }

    EXPECT_THAT(getMessages(), HasSubstr(expected_clear_log));
    EXPECT_THAT(readLogFile(), HasSubstr(expected_clear_log));
    EXPECT_EQ(getBodyFogMessage(), expected_obfuscated_log);
    ASSERT_NE(sysog_routine, nullptr);
    sysog_routine();
    EXPECT_EQ(capture_syslog_cef_data.size(), 2);
    for (const string &str : capture_syslog_cef_data) {
        EXPECT_THAT(str, AnyOf(HasSubstr("String='Another string'"), HasSubstr("String=\"Another string\"")));
    }
}

TEST(OfflineLog, OfflineLog)
{
    AgentDetails agent_details;
    StrictMock<MockTimeGet> mock_timer;
    StrictMock<MockLogging> mock_logger;

    EXPECT_CALL(mock_timer, getWalltimeStr(_)).WillOnce(Return("0:0:0"));
    EXPECT_CALL(mock_timer, getWalltime()).WillOnce(Return(chrono::microseconds(0)));
    EXPECT_CALL(mock_logger, getCurrentLogId()).WillOnce(Return(1));

    LogGen log(
        "Install policy",
        Audience::INTERNAL,
        Severity::INFO,
        Priority::LOW,
        Tags::POLICY_INSTALLATION,
        Tags::ACCESS_CONTROL,
        Enreachments::BEAUTIFY_OUTPUT
    );
    log << LogField("String", "Another string");

    string expected_log(
        "{\n"
        "    \"eventTime\": \"0:0:0\",\n"
        "    \"eventName\": \"Install policy\",\n"
        "    \"eventSeverity\": \"Info\",\n"
        "    \"eventPriority\": \"Low\",\n"
        "    \"eventType\": \"Event Driven\",\n"
        "    \"eventLevel\": \"Log\",\n"
        "    \"eventLogLevel\": \"info\",\n"
        "    \"eventAudience\": \"Internal\",\n"
        "    \"eventAudienceTeam\": \"\",\n"
        "    \"eventFrequency\": 0,\n"
        "    \"eventTags\": [\n"
        "        \"Access Control\",\n"
        "        \"Policy Installation\"\n"
        "    ],\n"
        "    \"eventSource\": {\n"
        "        \"agentId\": \"Unknown\",\n"
        "        \"eventTraceId\": \"\",\n"
        "        \"eventSpanId\": \"\",\n"
        "        \"issuingEngineVersion\": \"\",\n"
        "        \"serviceName\": \"Unnamed Nano Service\"\n"
        "    },\n"
        "    \"eventData\": {\n"
        "        \"logIndex\": 1,\n"
        "        \"String\": \"Another string\"\n"
        "    }\n"
        "}"
    );

    EXPECT_EQ(log.getLogInsteadOfSending(), expected_log);
}
