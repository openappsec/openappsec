#include "generic_metric.h"

#include "cptest.h"
#include "metric/all_metric_event.h"
#include "event.h"
#include "mock/mock_mainloop.h"
#include "debug.h"
#include "environment.h"
#include "mock/mock_time_get.h"
#include "mock/mock_rest_api.h"
#include "agent_details.h"
#include "mock/mock_messaging.h"
#include "config.h"
#include "config_component.h"

using namespace std;
using namespace chrono;
using namespace testing;
using namespace MetricCalculations;

USE_DEBUG_FLAG(D_METRICS);

class CPUEvent : public Event<CPUEvent>
{
public:
    void
    setProcessCPU(double value)
    {
        cpu_usage = value;
    }

    double
    getCPU() const
    {
        return cpu_usage;
    }

private:
    double cpu_usage;
};

class CPUMetric
        :
    public GenericMetric,
    public Listener<CPUEvent>
{
public:
    void
    upon(const CPUEvent &event) override
    {
        max.report(event.getCPU());
        min.report(event.getCPU());
        last_report.report(event.getCPU());
        avg.report(event.getCPU());
        samples_counter.report(1);
        top_usage.report(event.getCPU());
    }

    Max<double> max{this, "cpuMax"};
    Min<double> min{this, "cpuMin"};
    Average<double> avg{this, "cpuAvg"};
    LastReportedValue<double> last_report{this, "cpuCurrent"};
    Counter samples_counter{this, "cpuCounter"};
    TopValues<double, 3> top_usage{this, "cpuTops"};
};

class MessageEvent : public Event<MessageEvent>
{
public:
    void
    setMessage(string msg)
    {
        message = msg;
    }

    string
    getMessage() const
    {
        return message;
    }

    int
    getMessageSize() const
    {
        return message.length();
    }

private:
    string message;
};

class MessageMetric
        :
    public GenericMetric,
    public Listener<MessageEvent>
{
public:
    void
    upon(const MessageEvent &event) override
    {
        max.report(event.getMessageSize());
        avg.report(event.getMessageSize());
    }

    Max<int> max{this, "messageMax"};
    Average<double> avg{this, "messageAvg"};
};

class HttpTransaction : public Event<HttpTransaction>
{
public:
    HttpTransaction(const string &_url, uint _bytes) : url(_url), bytes(_bytes) {}

    const string & getUrl() const { return url;}
    uint getBytes() const { return bytes; }

private:
    string url;
    uint bytes;
};

class UrlMetric
        :
    public GenericMetric,
    public Listener<HttpTransaction>
{
public:
    void
    upon(const HttpTransaction &event) override
    {
        avg.report(event.getUrl(), event.getBytes());
    }

private:
    MetricMap<string, Average<double>> avg{this, "PerUrlAvg"};
};

class MetricTest : public Test
{
public:
    MetricTest()
    {
        EXPECT_CALL(rest, mockRestCall(RestAction::ADD, "declare-boolean-variable", _)).WillOnce(Return(true));
        env.init();
        Debug::setNewDefaultStdout(&debug_output);
        Debug::setUnitTestFlag(D_METRICS, Debug::DebugLevel::TRACE);
        setConfiguration<bool>(true, string("metric"), string("fogMetricSendEnable"));
        EXPECT_CALL(
            mock_ml,
            addRecurringRoutine(I_MainLoop::RoutineType::System, chrono::microseconds(5000000), _, _, _))
                .WillRepeatedly(DoAll(SaveArg<2>(&routine), Return(1))
        );
        EXPECT_CALL(timer, getWalltimeStr(_)).WillRepeatedly(Return(string("2016-11-13T17:31:24.087")));
        I_MainLoop::Routine send_debug_routine = nullptr;
    }

    ~MetricTest()
    {
        Debug::setNewDefaultStdout(&cout);
    }

    bool getMetrics(const unique_ptr<RestInit> &p) { get_metrics = p->getRest(); return true; }

    StrictMock<MockMainLoop> mock_ml;
    NiceMock<MockTimeGet> timer;
    StrictMock<MockRestApi> rest;
    ::Environment env;
    ConfigComponent conf;
    AgentDetails agent_details;
    NiceMock<MockMessaging> messaging_mock;
    stringstream debug_output;
    I_MainLoop::Routine routine;
    unique_ptr<ServerRest> get_metrics;
};

TEST_F(MetricTest, basicMetricTest)
{
    CPUMetric cpu_mt;
    cpu_mt.init(
        "CPU usage",
        ReportIS::AudienceTeam::AGENT_CORE,
        ReportIS::IssuingEngine::AGENT_CORE,
        seconds(5),
        false
    );
    cpu_mt.registerListener();

    EXPECT_EQ(cpu_mt.getMetricName(), "CPU usage");
    EXPECT_EQ(cpu_mt.getReportInterval().count(), 5);

    routine();
    EXPECT_EQ(debug_output.str(), "");

    CPUEvent cpu_event;
    cpu_event.setProcessCPU(89);
    cpu_event.notify();

    string metric_str =
        "{\n"
        "    \"Metric\": \"CPU usage\",\n"
        "    \"Reporting interval\": 5,\n"
        "    \"cpuMax\": 89.0,\n"
        "    \"cpuMin\": 89.0,\n"
        "    \"cpuAvg\": 89.0,\n"
        "    \"cpuCurrent\": 89.0,\n"
        "    \"cpuCounter\": 1,\n"
        "    \"cpuTops\": [\n"
        "        89.0\n"
        "    ]\n"
        "}";

    string message_body;
    EXPECT_CALL(
        messaging_mock,
        mockSendPersistentMessage(false, _, _, "/api/v1/agents/events", _, _, MessageTypeTag::METRIC)
    ).WillRepeatedly(DoAll(SaveArg<1>(&message_body), Return(Maybe<string>(string("")))));

    string expected_message =
        "{\n"
        "    \"log\": {\n"
        "        \"eventTime\": \"2016-11-13T17:31:24.087\",\n"
        "        \"eventName\": \"CPU usage\",\n"
        "        \"eventSeverity\": \"Info\",\n"
        "        \"eventPriority\": \"Low\",\n"
        "        \"eventType\": \"Periodic\",\n"
        "        \"eventLevel\": \"Log\",\n"
        "        \"eventLogLevel\": \"info\",\n"
        "        \"eventAudience\": \"Internal\",\n"
        "        \"eventAudienceTeam\": \"Agent Core\",\n"
        "        \"eventFrequency\": 5,\n"
        "        \"eventTags\": [\n"
        "            \"Informational\"\n"
        "        ],\n"
        "        \"eventSource\": {\n"
        "            \"agentId\": \"Unknown\",\n"
        "            \"issuingEngine\": \"Agent Core\",\n"
        "            \"eventTraceId\": \"\",\n"
        "            \"eventSpanId\": \"\",\n"
        "            \"issuingEngineVersion\": \"\",\n"
        "            \"serviceName\": \"Unnamed Nano Service\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"cpuMax\": 89,\n"
        "            \"cpuMin\": 89,\n"
        "            \"cpuAvg\": 89,\n"
        "            \"cpuCurrent\": 89,\n"
        "            \"cpuCounter\": 1,\n"
        "            \"cpuTops\": [\n"
        "                89.0\n"
        "            ]\n"
        "        }\n"
        "    }\n"
        "}";

    routine();
    EXPECT_THAT(debug_output.str(), HasSubstr(metric_str));
    EXPECT_EQ(message_body, expected_message);
    debug_output.str("");

    cpu_event.setProcessCPU(90);
    cpu_event.notify();

    metric_str =
        "{\n"
        "    \"Metric\": \"CPU usage\",\n"
        "    \"Reporting interval\": 5,\n"
        "    \"cpuMax\": 90.0,\n"
        "    \"cpuMin\": 89.0,\n"
        "    \"cpuAvg\": 89.5,\n"
        "    \"cpuCurrent\": 90.0,\n"
        "    \"cpuCounter\": 2,\n"
        "    \"cpuTops\": [\n"
        "        89.0,\n"
        "        90.0\n"
        "    ]\n"
        "}";

    EXPECT_CALL(
        messaging_mock,
        mockSendPersistentMessage(false, _, _, "/api/v1/agents/events", _, _, MessageTypeTag::METRIC)
    ).WillRepeatedly(DoAll(SaveArg<1>(&message_body), Return(Maybe<string>(string("")))));

    expected_message =
        "{\n"
        "    \"log\": {\n"
        "        \"eventTime\": \"2016-11-13T17:31:24.087\",\n"
        "        \"eventName\": \"CPU usage\",\n"
        "        \"eventSeverity\": \"Info\",\n"
        "        \"eventPriority\": \"Low\",\n"
        "        \"eventType\": \"Periodic\",\n"
        "        \"eventLevel\": \"Log\",\n"
        "        \"eventLogLevel\": \"info\",\n"
        "        \"eventAudience\": \"Internal\",\n"
        "        \"eventAudienceTeam\": \"Agent Core\",\n"
        "        \"eventFrequency\": 5,\n"
        "        \"eventTags\": [\n"
        "            \"Informational\"\n"
        "        ],\n"
        "        \"eventSource\": {\n"
        "            \"agentId\": \"Unknown\",\n"
        "            \"issuingEngine\": \"Agent Core\",\n"
        "            \"eventTraceId\": \"\",\n"
        "            \"eventSpanId\": \"\",\n"
        "            \"issuingEngineVersion\": \"\",\n"
        "            \"serviceName\": \"Unnamed Nano Service\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"cpuMax\": 90,\n"
        "            \"cpuMin\": 89,\n"
        "            \"cpuAvg\": 89,\n"
        "            \"cpuCurrent\": 90,\n"
        "            \"cpuCounter\": 2,\n"
        "            \"cpuTops\": [\n"
        "                89.0,\n"
        "                90.0\n"
        "            ]\n"
        "        }\n"
        "    }\n"
        "}";

    routine();
    EXPECT_THAT(debug_output.str(), HasSubstr(metric_str));
    EXPECT_EQ(message_body, expected_message);
    debug_output.str("");

    cpu_event.setProcessCPU(100);
    cpu_event.notify();

    metric_str =
        "{\n"
        "    \"Metric\": \"CPU usage\",\n"
        "    \"Reporting interval\": 5,\n"
        "    \"cpuMax\": 100.0,\n"
        "    \"cpuMin\": 89.0,\n"
        "    \"cpuAvg\": 93.0,\n"
        "    \"cpuCurrent\": 100.0,\n"
        "    \"cpuCounter\": 3,\n"
        "    \"cpuTops\": [\n"
        "        89.0,\n"
        "        90.0,\n"
        "        100.0\n"
        "    ]\n"
        "}";

    EXPECT_CALL(
        messaging_mock,
        mockSendPersistentMessage(false, _, _, "/api/v1/agents/events", _, _, MessageTypeTag::METRIC)
    ).WillRepeatedly(DoAll(SaveArg<1>(&message_body), Return(Maybe<string>(string("")))));

    expected_message =
        "{\n"
        "    \"log\": {\n"
        "        \"eventTime\": \"2016-11-13T17:31:24.087\",\n"
        "        \"eventName\": \"CPU usage\",\n"
        "        \"eventSeverity\": \"Info\",\n"
        "        \"eventPriority\": \"Low\",\n"
        "        \"eventType\": \"Periodic\",\n"
        "        \"eventLevel\": \"Log\",\n"
        "        \"eventLogLevel\": \"info\",\n"
        "        \"eventAudience\": \"Internal\",\n"
        "        \"eventAudienceTeam\": \"Agent Core\",\n"
        "        \"eventFrequency\": 5,\n"
        "        \"eventTags\": [\n"
        "            \"Informational\"\n"
        "        ],\n"
        "        \"eventSource\": {\n"
        "            \"agentId\": \"Unknown\",\n"
        "            \"issuingEngine\": \"Agent Core\",\n"
        "            \"eventTraceId\": \"\",\n"
        "            \"eventSpanId\": \"\",\n"
        "            \"issuingEngineVersion\": \"\",\n"
        "            \"serviceName\": \"Unnamed Nano Service\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"cpuMax\": 100,\n"
        "            \"cpuMin\": 89,\n"
        "            \"cpuAvg\": 93,\n"
        "            \"cpuCurrent\": 100,\n"
        "            \"cpuCounter\": 3,\n"
        "            \"cpuTops\": [\n"
        "                89.0,\n"
        "                90.0,\n"
        "                100.0\n"
        "            ]\n"
        "        }\n"
        "    }\n"
        "}";

    routine();
    EXPECT_THAT(debug_output.str(), HasSubstr(metric_str));
    EXPECT_EQ(message_body, expected_message);
    debug_output.str("");
}

TEST_F(MetricTest, printMetricsTest)
{
    CPTestTempfile metrics_output_file = CPTestTempfile();
    setConfiguration<string>(metrics_output_file.fname, string("metric"), "metricsOutputTmpFile");
    EXPECT_CALL(rest, mockRestCall(RestAction::SHOW, "metrics", _)).WillOnce(
        WithArg<2>(Invoke(this, &MetricTest::getMetrics))
    );

    GenericMetric::preload();
    GenericMetric::init();

    CPUMetric cpu_mt;
    cpu_mt.init(
        "CPU usage",
        ReportIS::AudienceTeam::AGENT_CORE,
        ReportIS::IssuingEngine::AGENT_CORE,
        seconds(5),
        false
    );
    cpu_mt.registerListener();

    routine();

    CPUEvent cpu_event;
    cpu_event.setProcessCPU(89);
    cpu_event.notify();

    EXPECT_CALL(
        messaging_mock,
        mockSendPersistentMessage(false, _, _, "/api/v1/agents/events", _, _, MessageTypeTag::METRIC)
    ).WillRepeatedly(Return(Maybe<string>(string(""))));

    string metric_str =
        "{\n"
        "    \"Metric\": \"CPU usage\",\n"
        "    \"Reporting interval\": 5,\n"
        "    \"cpuMax\": 89.0,\n"
        "    \"cpuMin\": 89.0,\n"
        "    \"cpuAvg\": 89.0,\n"
        "    \"cpuCurrent\": 89.0,\n"
        "    \"cpuCounter\": 1,\n"
        "    \"cpuTops\": [\n"
        "        89.0\n"
        "    ]\n"
        "}";

    routine();

    stringstream empty_json;
    empty_json << "{}";
    auto res = get_metrics->performRestCall(empty_json);
    ASSERT_TRUE(res.ok());
    EXPECT_THAT(metrics_output_file.readFile(), HasSubstr(metric_str));

    GenericMetric::fini();
}

TEST_F(MetricTest, metricTestWithReset)
{
    CPUMetric cpu_mt;
    cpu_mt.init(
        "CPU usage",
        ReportIS::AudienceTeam::AGENT_CORE,
        ReportIS::IssuingEngine::AGENT_CORE,
        seconds(5),
        true
    );
    cpu_mt.registerListener();

    EXPECT_EQ(cpu_mt.getMetricName(), "CPU usage");
    EXPECT_EQ(cpu_mt.getReportInterval().count(), 5);

    routine();
    EXPECT_EQ(debug_output.str(), "");

    CPUEvent cpu_event;
    cpu_event.setProcessCPU(89);
    cpu_event.notify();

    string metric_str =
        "{\n"
        "    \"Metric\": \"CPU usage\",\n"
        "    \"Reporting interval\": 5,\n"
        "    \"cpuMax\": 89.0,\n"
        "    \"cpuMin\": 89.0,\n"
        "    \"cpuAvg\": 89.0,\n"
        "    \"cpuCurrent\": 89.0,\n"
        "    \"cpuCounter\": 1,\n"
        "    \"cpuTops\": [\n"
        "        89.0\n"
        "    ]\n"
        "}";

    string message_body;
    EXPECT_CALL(
        messaging_mock,
        mockSendPersistentMessage(false, _, _, "/api/v1/agents/events", _, _, MessageTypeTag::METRIC)
    ).WillRepeatedly(DoAll(SaveArg<1>(&message_body), Return(Maybe<string>(string("")))));

    string expected_message =
        "{\n"
        "    \"log\": {\n"
        "        \"eventTime\": \"2016-11-13T17:31:24.087\",\n"
        "        \"eventName\": \"CPU usage\",\n"
        "        \"eventSeverity\": \"Info\",\n"
        "        \"eventPriority\": \"Low\",\n"
        "        \"eventType\": \"Periodic\",\n"
        "        \"eventLevel\": \"Log\",\n"
        "        \"eventLogLevel\": \"info\",\n"
        "        \"eventAudience\": \"Internal\",\n"
        "        \"eventAudienceTeam\": \"Agent Core\",\n"
        "        \"eventFrequency\": 5,\n"
        "        \"eventTags\": [\n"
        "            \"Informational\"\n"
        "        ],\n"
        "        \"eventSource\": {\n"
        "            \"agentId\": \"Unknown\",\n"
        "            \"issuingEngine\": \"Agent Core\",\n"
        "            \"eventTraceId\": \"\",\n"
        "            \"eventSpanId\": \"\",\n"
        "            \"issuingEngineVersion\": \"\",\n"
        "            \"serviceName\": \"Unnamed Nano Service\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"cpuMax\": 89,\n"
        "            \"cpuMin\": 89,\n"
        "            \"cpuAvg\": 89,\n"
        "            \"cpuCurrent\": 89,\n"
        "            \"cpuCounter\": 1,\n"
        "            \"cpuTops\": [\n"
        "                89.0\n"
        "            ]\n"
        "        }\n"
        "    }\n"
        "}";

    routine();
    EXPECT_THAT(debug_output.str(), HasSubstr(metric_str));
    EXPECT_EQ(message_body, expected_message);
    debug_output.str("");

    cpu_event.setProcessCPU(90);
    cpu_event.notify();

    metric_str =
        "{\n"
        "    \"Metric\": \"CPU usage\",\n"
        "    \"Reporting interval\": 5,\n"
        "    \"cpuMax\": 90.0,\n"
        "    \"cpuMin\": 90.0,\n"
        "    \"cpuAvg\": 90.0,\n"
        "    \"cpuCurrent\": 90.0,\n"
        "    \"cpuCounter\": 1,\n"
        "    \"cpuTops\": [\n"
        "        90.0\n"
        "    ]\n"
        "}";

    EXPECT_CALL(
        messaging_mock,
        mockSendPersistentMessage(false, _, _, "/api/v1/agents/events", _, _, MessageTypeTag::METRIC)
    ).WillRepeatedly(DoAll(SaveArg<1>(&message_body), Return(Maybe<string>(string("")))));

    expected_message =
        "{\n"
        "    \"log\": {\n"
        "        \"eventTime\": \"2016-11-13T17:31:24.087\",\n"
        "        \"eventName\": \"CPU usage\",\n"
        "        \"eventSeverity\": \"Info\",\n"
        "        \"eventPriority\": \"Low\",\n"
        "        \"eventType\": \"Periodic\",\n"
        "        \"eventLevel\": \"Log\",\n"
        "        \"eventLogLevel\": \"info\",\n"
        "        \"eventAudience\": \"Internal\",\n"
        "        \"eventAudienceTeam\": \"Agent Core\",\n"
        "        \"eventFrequency\": 5,\n"
        "        \"eventTags\": [\n"
        "            \"Informational\"\n"
        "        ],\n"
        "        \"eventSource\": {\n"
        "            \"agentId\": \"Unknown\",\n"
        "            \"issuingEngine\": \"Agent Core\",\n"
        "            \"eventTraceId\": \"\",\n"
        "            \"eventSpanId\": \"\",\n"
        "            \"issuingEngineVersion\": \"\",\n"
        "            \"serviceName\": \"Unnamed Nano Service\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"cpuMax\": 90,\n"
        "            \"cpuMin\": 90,\n"
        "            \"cpuAvg\": 90,\n"
        "            \"cpuCurrent\": 90,\n"
        "            \"cpuCounter\": 1,\n"
        "            \"cpuTops\": [\n"
        "                90.0\n"
        "            ]\n"
        "        }\n"
        "    }\n"
        "}";

    routine();
    EXPECT_THAT(debug_output.str(), HasSubstr(metric_str));
    EXPECT_EQ(message_body, expected_message);
    debug_output.str("");

    cpu_event.setProcessCPU(100);
    cpu_event.notify();

    metric_str =
        "{\n"
        "    \"Metric\": \"CPU usage\",\n"
        "    \"Reporting interval\": 5,\n"
        "    \"cpuMax\": 100.0,\n"
        "    \"cpuMin\": 100.0,\n"
        "    \"cpuAvg\": 100.0,\n"
        "    \"cpuCurrent\": 100.0,\n"
        "    \"cpuCounter\": 1,\n"
        "    \"cpuTops\": [\n"
        "        100.0\n"
        "    ]\n"
        "}";

    EXPECT_CALL(
        messaging_mock,
        mockSendPersistentMessage(false, _, _, "/api/v1/agents/events", _, _, MessageTypeTag::METRIC)
    ).WillRepeatedly(DoAll(SaveArg<1>(&message_body), Return(Maybe<string>(string("")))));

    expected_message =
        "{\n"
        "    \"log\": {\n"
        "        \"eventTime\": \"2016-11-13T17:31:24.087\",\n"
        "        \"eventName\": \"CPU usage\",\n"
        "        \"eventSeverity\": \"Info\",\n"
        "        \"eventPriority\": \"Low\",\n"
        "        \"eventType\": \"Periodic\",\n"
        "        \"eventLevel\": \"Log\",\n"
        "        \"eventLogLevel\": \"info\",\n"
        "        \"eventAudience\": \"Internal\",\n"
        "        \"eventAudienceTeam\": \"Agent Core\",\n"
        "        \"eventFrequency\": 5,\n"
        "        \"eventTags\": [\n"
        "            \"Informational\"\n"
        "        ],\n"
        "        \"eventSource\": {\n"
        "            \"agentId\": \"Unknown\",\n"
        "            \"issuingEngine\": \"Agent Core\",\n"
        "            \"eventTraceId\": \"\",\n"
        "            \"eventSpanId\": \"\",\n"
        "            \"issuingEngineVersion\": \"\",\n"
        "            \"serviceName\": \"Unnamed Nano Service\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"cpuMax\": 100,\n"
        "            \"cpuMin\": 100,\n"
        "            \"cpuAvg\": 100,\n"
        "            \"cpuCurrent\": 100,\n"
        "            \"cpuCounter\": 1,\n"
        "            \"cpuTops\": [\n"
        "                100.0\n"
        "            ]\n"
        "        }\n"
        "    }\n"
        "}";

    routine();
    EXPECT_THAT(debug_output.str(), HasSubstr(metric_str));
    EXPECT_EQ(message_body, expected_message);
    debug_output.str("");
}

TEST_F(MetricTest, generateReportWithReset)
{
    CPUMetric cpu_mt;
    cpu_mt.init(
        "CPU usage",
        ReportIS::AudienceTeam::AGENT_CORE,
        ReportIS::IssuingEngine::AGENT_CORE,
        seconds(5),
        false
    );
    cpu_mt.registerListener();

    EXPECT_EQ(cpu_mt.getMetricName(), "CPU usage");
    EXPECT_EQ(cpu_mt.getReportInterval().count(), 5);

    routine();
    EXPECT_EQ(debug_output.str(), "");

    CPUEvent cpu_event;
    cpu_event.setProcessCPU(89);
    cpu_event.notify();

    string metric_str =
        "{\n"
        "    \"Metric\": \"CPU usage\",\n"
        "    \"Reporting interval\": 5,\n"
        "    \"cpuMax\": 89.0,\n"
        "    \"cpuMin\": 89.0,\n"
        "    \"cpuAvg\": 89.0,\n"
        "    \"cpuCurrent\": 89.0,\n"
        "    \"cpuCounter\": 1,\n"
        "    \"cpuTops\": [\n"
        "        89.0\n"
        "    ]\n"
        "}";

    string message_body;
    EXPECT_CALL(
        messaging_mock,
        mockSendPersistentMessage(false, _, _, "/api/v1/agents/events", _, _, MessageTypeTag::METRIC)
    ).WillRepeatedly(DoAll(SaveArg<1>(&message_body), Return(Maybe<string>(string("")))));

    string expected_message =
        "{\n"
        "    \"log\": {\n"
        "        \"eventTime\": \"2016-11-13T17:31:24.087\",\n"
        "        \"eventName\": \"CPU usage\",\n"
        "        \"eventSeverity\": \"Info\",\n"
        "        \"eventPriority\": \"Low\",\n"
        "        \"eventType\": \"Periodic\",\n"
        "        \"eventLevel\": \"Log\",\n"
        "        \"eventLogLevel\": \"info\",\n"
        "        \"eventAudience\": \"Internal\",\n"
        "        \"eventAudienceTeam\": \"Agent Core\",\n"
        "        \"eventFrequency\": 5,\n"
        "        \"eventTags\": [\n"
        "            \"Informational\"\n"
        "        ],\n"
        "        \"eventSource\": {\n"
        "            \"agentId\": \"Unknown\",\n"
        "            \"issuingEngine\": \"Agent Core\",\n"
        "            \"eventTraceId\": \"\",\n"
        "            \"eventSpanId\": \"\",\n"
        "            \"issuingEngineVersion\": \"\",\n"
        "            \"serviceName\": \"Unnamed Nano Service\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"cpuMax\": 89,\n"
        "            \"cpuMin\": 89,\n"
        "            \"cpuAvg\": 89,\n"
        "            \"cpuCurrent\": 89,\n"
        "            \"cpuCounter\": 1,\n"
        "            \"cpuTops\": [\n"
        "                89.0\n"
        "            ]\n"
        "        }\n"
        "    }\n"
        "}";
    routine();
    EXPECT_THAT(debug_output.str(), HasSubstr(metric_str));
    EXPECT_EQ(message_body, expected_message);
    debug_output.str("");

    auto report = cpu_mt.generateReport(true);
    EXPECT_THAT(metric_str, HasSubstr(report));
    EXPECT_EQ(message_body, expected_message);
    debug_output.str("");

    routine();
    EXPECT_EQ(debug_output.str(), "");

    cpu_event.setProcessCPU(90);
    cpu_event.notify();

    metric_str =
        "{\n"
        "    \"Metric\": \"CPU usage\",\n"
        "    \"Reporting interval\": 5,\n"
        "    \"cpuMax\": 90.0,\n"
        "    \"cpuMin\": 90.0,\n"
        "    \"cpuAvg\": 90.0,\n"
        "    \"cpuCurrent\": 90.0,\n"
        "    \"cpuCounter\": 1,\n"
        "    \"cpuTops\": [\n"
        "        90.0\n"
        "    ]\n"
        "}";

    EXPECT_CALL(
        messaging_mock,
        mockSendPersistentMessage(false, _, _, "/api/v1/agents/events", _, _, MessageTypeTag::METRIC)
    ).WillRepeatedly(DoAll(SaveArg<1>(&message_body), Return(Maybe<string>(string("")))));

    expected_message =
        "{\n"
        "    \"log\": {\n"
        "        \"eventTime\": \"2016-11-13T17:31:24.087\",\n"
        "        \"eventName\": \"CPU usage\",\n"
        "        \"eventSeverity\": \"Info\",\n"
        "        \"eventPriority\": \"Low\",\n"
        "        \"eventType\": \"Periodic\",\n"
        "        \"eventLevel\": \"Log\",\n"
        "        \"eventLogLevel\": \"info\",\n"
        "        \"eventAudience\": \"Internal\",\n"
        "        \"eventAudienceTeam\": \"Agent Core\",\n"
        "        \"eventFrequency\": 5,\n"
        "        \"eventTags\": [\n"
        "            \"Informational\"\n"
        "        ],\n"
        "        \"eventSource\": {\n"
        "            \"agentId\": \"Unknown\",\n"
        "            \"issuingEngine\": \"Agent Core\",\n"
        "            \"eventTraceId\": \"\",\n"
        "            \"eventSpanId\": \"\",\n"
        "            \"issuingEngineVersion\": \"\",\n"
        "            \"serviceName\": \"Unnamed Nano Service\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"cpuMax\": 90,\n"
        "            \"cpuMin\": 90,\n"
        "            \"cpuAvg\": 90,\n"
        "            \"cpuCurrent\": 90,\n"
        "            \"cpuCounter\": 1,\n"
        "            \"cpuTops\": [\n"
        "                90.0\n"
        "            ]\n"
        "        }\n"
        "    }\n"
        "}";
    routine();
    EXPECT_THAT(debug_output.str(), HasSubstr(metric_str));
    EXPECT_EQ(message_body, expected_message);
    debug_output.str("");

    cpu_mt.registerContext<string>("Service Name", "My named nano service");
    cpu_event.setProcessCPU(100);
    cpu_event.notify();

    metric_str =
        "{\n"
        "    \"Metric\": \"CPU usage\",\n"
        "    \"Reporting interval\": 5,\n"
        "    \"cpuMax\": 100.0,\n"
        "    \"cpuMin\": 90.0,\n"
        "    \"cpuAvg\": 95.0,\n"
        "    \"cpuCurrent\": 100.0,\n"
        "    \"cpuCounter\": 2,\n"
        "    \"cpuTops\": [\n"
        "        90.0,\n"
        "        100.0\n"
        "    ]\n"
        "}";

    EXPECT_CALL(
        messaging_mock,
        mockSendPersistentMessage(false, _, _, "/api/v1/agents/events", _, _, MessageTypeTag::METRIC)
    ).WillRepeatedly(DoAll(SaveArg<1>(&message_body), Return(Maybe<string>(string("")))));

    expected_message =
        "{\n"
        "    \"log\": {\n"
        "        \"eventTime\": \"2016-11-13T17:31:24.087\",\n"
        "        \"eventName\": \"CPU usage\",\n"
        "        \"eventSeverity\": \"Info\",\n"
        "        \"eventPriority\": \"Low\",\n"
        "        \"eventType\": \"Periodic\",\n"
        "        \"eventLevel\": \"Log\",\n"
        "        \"eventLogLevel\": \"info\",\n"
        "        \"eventAudience\": \"Internal\",\n"
        "        \"eventAudienceTeam\": \"Agent Core\",\n"
        "        \"eventFrequency\": 5,\n"
        "        \"eventTags\": [\n"
        "            \"Informational\"\n"
        "        ],\n"
        "        \"eventSource\": {\n"
        "            \"agentId\": \"Unknown\",\n"
        "            \"issuingEngine\": \"Agent Core\",\n"
        "            \"eventTraceId\": \"\",\n"
        "            \"eventSpanId\": \"\",\n"
        "            \"issuingEngineVersion\": \"\",\n"
        "            \"serviceName\": \"My named nano service\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"cpuMax\": 100,\n"
        "            \"cpuMin\": 90,\n"
        "            \"cpuAvg\": 95,\n"
        "            \"cpuCurrent\": 100,\n"
        "            \"cpuCounter\": 2,\n"
        "            \"cpuTops\": [\n"
        "                90.0,\n"
        "                100.0\n"
        "            ]\n"
        "        }\n"
        "    }\n"
        "}";
    routine();
    EXPECT_THAT(debug_output.str(), HasSubstr(metric_str));
    EXPECT_EQ(message_body, expected_message);
    debug_output.str("");
}

TEST_F(MetricTest, allMetricTest)
{
    CPUMetric cpu_mt;

    cpu_mt.init(
        "CPU usage",
        ReportIS::AudienceTeam::AGENT_CORE,
        ReportIS::IssuingEngine::AGENT_CORE,
        seconds(5),
        false
    );
    cpu_mt.registerListener();

    EXPECT_EQ(cpu_mt.getMetricName(), "CPU usage");
    EXPECT_EQ(cpu_mt.getReportInterval().count(), 5);

    CPUEvent cpu_event;
    cpu_event.setProcessCPU(89);
    cpu_event.notify();

    cpu_event.setProcessCPU(90);
    cpu_event.notify();

    cpu_event.setProcessCPU(100);
    cpu_event.notify();

    MessageMetric msg_size_mt;
    msg_size_mt.init(
        "Message size",
        ReportIS::AudienceTeam::AGENT_CORE,
        ReportIS::IssuingEngine::AGENT_CORE,
        seconds(5),
        false
    );
    msg_size_mt.registerListener();

    EXPECT_EQ(msg_size_mt.getMetricName(), "Message size");
    EXPECT_EQ(msg_size_mt.getReportInterval().count(), 5);

    MessageEvent msg_event;
    msg_event.setMessage("Hello world!");
    msg_event.notify();

    msg_event.setMessage("Hello world!!");
    msg_event.notify();

    msg_event.setMessage("Hello world!!!");
    msg_event.notify();

    AllMetricEvent all_mt_event;
    all_mt_event.setReset(false);
    all_mt_event.notify();

    string cpu_str =
        "{\n"
        "    \"Metric\": \"CPU usage\",\n"
        "    \"Reporting interval\": 5,\n"
        "    \"cpuMax\": 100.0,\n"
        "    \"cpuMin\": 89.0,\n"
        "    \"cpuAvg\": 93.0,\n"
        "    \"cpuCurrent\": 100.0,\n"
        "    \"cpuCounter\": 3,\n"
        "    \"cpuTops\": [\n"
        "        89.0,\n"
        "        90.0,\n"
        "        100.0\n"
        "    ]\n"
        "}";

    string msg_str =
        "{\n"
        "    \"Metric\": \"Message size\",\n"
        "    \"Reporting interval\": 5,\n"
        "    \"messageMax\": 14,\n"
        "    \"messageAvg\": 13.0\n"
        "}";

    EXPECT_THAT(all_mt_event.query(), ElementsAre(msg_str, cpu_str));
}

TEST_F(MetricTest, testMapMetric)
{
    UrlMetric url_mt;
    url_mt.init(
        "Bytes per URL",
        ReportIS::AudienceTeam::AGENT_CORE,
        ReportIS::IssuingEngine::AGENT_CORE,
        seconds(5),
        true
    );
    url_mt.registerListener();

    HttpTransaction("/index.html", 10).notify();
    HttpTransaction("/index2.html", 20).notify();
    HttpTransaction("/index.html", 40).notify();

    string message_body;
    EXPECT_CALL(
        messaging_mock,
        mockSendPersistentMessage(false, _, _, "/api/v1/agents/events", _, _, MessageTypeTag::METRIC)
    ).WillRepeatedly(DoAll(SaveArg<1>(&message_body), Return(Maybe<string>(string("")))));
    routine();

    string msg_str =
        "{\n"
        "    \"Metric\": \"Bytes per URL\",\n"
        "    \"Reporting interval\": 5,\n"
        "    \"PerUrlAvg\": {\n"
        "        \"/index.html\": 25.0,\n"
        "        \"/index2.html\": 20.0\n"
        "    }\n"
        "}";
    EXPECT_THAT(debug_output.str(), HasSubstr(msg_str));
}

TEST_F(MetricTest, testManyValues)
{
    CPUMetric cpu_mt;

    cpu_mt.init(
        "CPU usage",
        ReportIS::AudienceTeam::AGENT_CORE,
        ReportIS::IssuingEngine::AGENT_CORE,
        seconds(5),
        false
    );
    cpu_mt.registerListener();

    CPUEvent cpu_event;
    cpu_event.setProcessCPU(89);
    cpu_event.notify();
    cpu_event.notify();

    cpu_event.setProcessCPU(90);
    cpu_event.notify();
    cpu_event.notify();

    cpu_event.setProcessCPU(100);
    cpu_event.notify();
    cpu_event.notify();

    string cpu_str =
        "    \"cpuTops\": [\n"
        "        90.0,\n"
        "        100.0,\n"
        "        100.0\n"
        "    ]\n";

    EXPECT_THAT(AllMetricEvent().query(), ElementsAre(HasSubstr(cpu_str)));
}

TEST_F(MetricTest, testManyValuesOutOfOrder)
{
    CPUMetric cpu_mt;

    cpu_mt.init(
        "CPU usage",
        ReportIS::AudienceTeam::AGENT_CORE,
        ReportIS::IssuingEngine::AGENT_CORE,
        seconds(5),
        false
    );
    cpu_mt.registerListener();

    CPUEvent cpu_event;
    cpu_event.setProcessCPU(20);
    cpu_event.notify();

    cpu_event.setProcessCPU(15);
    cpu_event.notify();

    cpu_event.setProcessCPU(10);
    cpu_event.notify();

    cpu_event.setProcessCPU(30);
    cpu_event.notify();

    string cpu_str =
        "    \"cpuTops\": [\n"
        "        15.0,\n"
        "        20.0,\n"
        "        30.0\n"
        "    ]\n";

    EXPECT_THAT(AllMetricEvent().query(), ElementsAre(HasSubstr(cpu_str)));
}
