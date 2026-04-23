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
#include "mock/mock_encryptor.h"
#include "mock/mock_messaging.h"
#include "mock/mock_instance_awareness.h"
#include "config.h"
#include "config_component.h"
#include "metric/metric_scraper.h"

using namespace std;
using namespace chrono;
using namespace testing;
using namespace MetricCalculations;

USE_DEBUG_FLAG(D_METRICS);

TEST(BaseMetric, generic_metadata)
{
    Max<int> test(nullptr, "cpuMax", 0, "cpu.max"_dot, "percent"_unit, "CPU utilization percentage"_desc);

    EXPECT_EQ(test.getMetricName(), "cpuMax");
    EXPECT_EQ(test.getMetricDotName(), "cpu.max");
    EXPECT_EQ(test.getMetircUnits(), "percent");
    EXPECT_EQ(test.getMetircDescription(), "CPU utilization percentage");
}

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
        total_samples_counter.report(1);
        top_usage.report(event.getCPU());
    }

    void
    setAiopsMetric()
    {
        turnOnStream(Stream::AIOPS);
        max.setMetricDotName("cpu.max");
        max.setMetircUnits("percrnt");
    }

    Max<double> max{this, "cpuMax"};
    Min<double> min{this, "cpuMin"};
    Average<double> avg{this, "cpuAvg"};
    LastReportedValue<double> last_report{this, "cpuCurrent"};
    Counter samples_counter{this, "cpuCounter"};
    NoResetCounter total_samples_counter{this, "cpuTotalCounter"};
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
    HttpTransaction(const string &_url, const string &m, uint _bytes) : url(_url), method(m), bytes(_bytes) {}

    const string & getUrl() const { return url; }
    const string & getMethod() const { return method; }
    uint getBytes() const { return bytes; }

private:
    string url;
    string method;
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
        total.report(event.getUrl(), 1);
    }

    void
    setAiopsMetric()
    {
        turnOnStream(Stream::AIOPS);
    }

private:
    MetricMap<string, Average<double>> avg{Average<double>{nullptr, ""}, this, "url", "PerUrlAvg"};
    MetricMap<string, NoResetCounter> total{NoResetCounter{nullptr, ""}, this, "url", "TotalRequests"};
};

class UrlMetric2 : public GenericMetric, public Listener<HttpTransaction>
{
public:
    void
    upon(const HttpTransaction &event) override
    {
        total.report(event.getUrl(), event.getMethod(), 1);
    }

private:
    MetricMap<string, MetricMap<string, NoResetCounter>> total{
        MetricMap<string, NoResetCounter>{NoResetCounter{nullptr, ""}, nullptr, "method", ""},
        this,
        "url",
        "request.total"
    };
};

class MetricTest : public Test
{
public:
    MetricTest()
    {
        EXPECT_CALL(rest, mockRestCall(RestAction::ADD, "declare-boolean-variable", _)).WillOnce(Return(true));
        env.init();
        conf.preload();

        ON_CALL(instance, getUniqueID()).WillByDefault(Return(string("87")));
        ON_CALL(instance, getFamilyID()).WillByDefault(Return(string("")));
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
    NiceMock<MockInstanceAwareness> instance;
    StrictMock<MockRestApi> rest;
    ::Environment env;
    ConfigComponent conf;
    AgentDetails agent_details;
    StrictMock<MockEncryptor> mock_encryptor;
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
        "    \"cpuTotalCounter\": 1,\n"
        "    \"cpuTops\": [\n"
        "        89.0\n"
        "    ]\n"
        "}";

    string message_body;
    EXPECT_CALL(messaging_mock, sendAsyncMessage(
        _,
        "/api/v1/agents/events",
        _,
        MessageCategory::METRIC,
        _,
        _
    )).WillRepeatedly(SaveArg<2>(&message_body));

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
        "            \"serviceName\": \"Unnamed Nano Service\",\n"
        "            \"serviceId\": \"87\",\n"
        "            \"serviceFamilyId\": \"\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"cpuMax\": 89,\n"
        "            \"cpuMin\": 89,\n"
        "            \"cpuAvg\": 89,\n"
        "            \"cpuCurrent\": 89,\n"
        "            \"cpuCounter\": 1,\n"
        "            \"cpuTotalCounter\": 1,\n"
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
        "    \"cpuTotalCounter\": 2,\n"
        "    \"cpuTops\": [\n"
        "        89.0,\n"
        "        90.0\n"
        "    ]\n"
        "}";

    EXPECT_CALL(messaging_mock, sendAsyncMessage(
        _,
        "/api/v1/agents/events",
        _,
        MessageCategory::METRIC,
        _,
        _
    )).WillRepeatedly(SaveArg<2>(&message_body));

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
        "            \"serviceName\": \"Unnamed Nano Service\",\n"
        "            \"serviceId\": \"87\",\n"
        "            \"serviceFamilyId\": \"\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"cpuMax\": 90,\n"
        "            \"cpuMin\": 89,\n"
        "            \"cpuAvg\": 89,\n"
        "            \"cpuCurrent\": 90,\n"
        "            \"cpuCounter\": 2,\n"
        "            \"cpuTotalCounter\": 2,\n"
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
        "    \"cpuTotalCounter\": 3,\n"
        "    \"cpuTops\": [\n"
        "        89.0,\n"
        "        90.0,\n"
        "        100.0\n"
        "    ]\n"
        "}";

    EXPECT_CALL(messaging_mock, sendAsyncMessage(
        _,
        "/api/v1/agents/events",
        _,
        MessageCategory::METRIC,
        _,
        _
    )).WillRepeatedly(SaveArg<2>(&message_body));

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
        "            \"serviceName\": \"Unnamed Nano Service\",\n"
        "            \"serviceId\": \"87\",\n"
        "            \"serviceFamilyId\": \"\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"cpuMax\": 100,\n"
        "            \"cpuMin\": 89,\n"
        "            \"cpuAvg\": 93,\n"
        "            \"cpuCurrent\": 100,\n"
        "            \"cpuCounter\": 3,\n"
        "            \"cpuTotalCounter\": 3,\n"
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

    EXPECT_CALL(messaging_mock, sendAsyncMessage(
        _,
        "/api/v1/agents/events",
        _,
        MessageCategory::METRIC,
        _,
        _
    )).Times(AnyNumber());

    string metric_str =
        "{\n"
        "    \"Metric\": \"CPU usage\",\n"
        "    \"Reporting interval\": 5,\n"
        "    \"cpuMax\": 89.0,\n"
        "    \"cpuMin\": 89.0,\n"
        "    \"cpuAvg\": 89.0,\n"
        "    \"cpuCurrent\": 89.0,\n"
        "    \"cpuCounter\": 1,\n"
        "    \"cpuTotalCounter\": 1,\n"
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

TEST_F(MetricTest, getPromeathusMetric)
{
    MetricScraper metric_scraper;
    function<string()> get_metrics_func;
    EXPECT_CALL(rest, addGetCall("service-metrics", _)).WillOnce(DoAll(SaveArg<1>(&get_metrics_func), Return(true)));
    metric_scraper.init();

    stringstream configuration;
    configuration << "{\"agentSettings\":[{\"key\":\"prometheus\",\"id\":\"id1\",\"value\":\"true\"},";
    configuration << "{\"key\":\"enable_all_metrics\",\"id\":\"id2\",\"value\":\"true\"}]}\n";

    EXPECT_TRUE(Singleton::Consume<Config::I_Config>::from(conf)->loadConfiguration(configuration));

    CPUMetric cpu_mt;
    cpu_mt.init(
        "CPU usage",
        ReportIS::AudienceTeam::AGENT_CORE,
        ReportIS::IssuingEngine::AGENT_CORE,
        seconds(5),
        false,
        ReportIS::Audience::INTERNAL,
        false,
        "asset id"
    );
    cpu_mt.turnOffStream(GenericMetric::Stream::FOG);
    cpu_mt.turnOffStream(GenericMetric::Stream::DEBUG);
    cpu_mt.registerListener();

    CPUEvent cpu_event;
    cpu_event.setProcessCPU(89);
    cpu_event.notify();

    string message_body = get_metrics_func();

    routine();

    string res =
        "{\n"
        "    \"metrics\": [\n"
        "        {\n"
        "            \"metric_name\": \"cpuMax\",\n"
        "            \"unique_name\": \"cpuMax_CPU usage\",\n"
        "            \"metric_type\": \"gauge\",\n"
        "            \"metric_description\": \"\",\n"
        "            \"labels\": \"{agent=\\\"Unknown\\\",assetId=\\\"asset id\\\",id=\\\"87\\\","
                        "metricName=\\\"CPU usage\\\"}\",\n"
        "            \"value\": \"89\"\n"
        "        },\n"
        "        {\n"
        "            \"metric_name\": \"cpuMin\",\n"
        "            \"unique_name\": \"cpuMin_CPU usage\",\n"
        "            \"metric_type\": \"gauge\",\n"
        "            \"metric_description\": \"\",\n"
        "            \"labels\": \"{agent=\\\"Unknown\\\",assetId=\\\"asset id\\\",id=\\\"87\\\","
                        "metricName=\\\"CPU usage\\\"}\",\n"
        "            \"value\": \"89\"\n"
        "        },\n"
        "        {\n"
        "            \"metric_name\": \"cpuAvg\",\n"
        "            \"unique_name\": \"cpuAvg_CPU usage\",\n"
        "            \"metric_type\": \"gauge\",\n"
        "            \"metric_description\": \"\",\n"
        "            \"labels\": \"{agent=\\\"Unknown\\\",assetId=\\\"asset id\\\",id=\\\"87\\\","
                        "metricName=\\\"CPU usage\\\"}\",\n"
        "            \"value\": \"89\"\n"
        "        },\n"
        "        {\n"
        "            \"metric_name\": \"cpuCurrent\",\n"
        "            \"unique_name\": \"cpuCurrent_CPU usage\",\n"
        "            \"metric_type\": \"gauge\",\n"
        "            \"metric_description\": \"\",\n"
        "            \"labels\": \"{agent=\\\"Unknown\\\",assetId=\\\"asset id\\\",id=\\\"87\\\","
                        "metricName=\\\"CPU usage\\\"}\",\n"
        "            \"value\": \"89\"\n"
        "        },\n"
        "        {\n"
        "            \"metric_name\": \"cpuCounter\",\n"
        "            \"unique_name\": \"cpuCounter_CPU usage\",\n"
        "            \"metric_type\": \"gauge\",\n"
        "            \"metric_description\": \"\",\n"
        "            \"labels\": \"{agent=\\\"Unknown\\\",assetId=\\\"asset id\\\",id=\\\"87\\\","
                        "metricName=\\\"CPU usage\\\"}\",\n"
        "            \"value\": \"1\"\n"
        "        },\n"
        "        {\n"
        "            \"metric_name\": \"cpuTotalCounter\",\n"
        "            \"unique_name\": \"cpuTotalCounter_CPU usage\",\n"
        "            \"metric_type\": \"counter\",\n"
        "            \"metric_description\": \"\",\n"
        "            \"labels\": \"{agent=\\\"Unknown\\\",assetId=\\\"asset id\\\",id=\\\"87\\\","
                        "metricName=\\\"CPU usage\\\"}\",\n"
        "            \"value\": \"1\"\n"
        "        }\n"
        "    ]\n"
        "}";

    EXPECT_EQ(message_body, res);
}

TEST_F(MetricTest, getPromeathusMultiMap)
{
    MetricScraper metric_scraper;
    function<string()> get_metrics_func;
    EXPECT_CALL(rest, addGetCall("service-metrics", _)).WillOnce(DoAll(SaveArg<1>(&get_metrics_func), Return(true)));
    metric_scraper.init();

    stringstream configuration;
    configuration << "{\"agentSettings\":[{\"key\":\"prometheus\",\"id\":\"id1\",\"value\":\"true\"},";
    configuration << "{\"key\":\"enable_all_metrics\",\"id\":\"id2\",\"value\":\"true\"}]}\n";

    EXPECT_TRUE(Singleton::Consume<Config::I_Config>::from(conf)->loadConfiguration(configuration));

    UrlMetric2 metric;
    metric.init(
        "Bytes per URL",
        ReportIS::AudienceTeam::AGENT_CORE,
        ReportIS::IssuingEngine::AGENT_CORE,
        seconds(5),
        true,
        ReportIS::Audience::INTERNAL,
        false,
        "asset id"
    );
    metric.registerListener();

    HttpTransaction("/index.html", "GET", 10).notify();
    HttpTransaction("/index2.html", "GET", 20).notify();
    HttpTransaction("/index.html", "POST", 40).notify();

    string message_body = get_metrics_func();
    routine();

    string res =
        "{\n"
        "    \"metrics\": [\n"
        "        {\n"
        "            \"metric_name\": \"request.total\",\n"
        "            \"unique_name\": \"GET_Bytes per URL\",\n"
        "            \"metric_type\": \"counter\",\n"
        "            \"metric_description\": \"\",\n"
        "            \"labels\": \"{agent=\\\"Unknown\\\",assetId=\\\"asset id\\\",id=\\\"87\\\","
                        "metricName=\\\"Bytes per URL\\\",method=\\\"GET\\\",url=\\\"/index.html\\\"}\",\n"
        "            \"value\": \"1\"\n"
        "        },\n"
        "        {\n"
        "            \"metric_name\": \"request.total\",\n"
        "            \"unique_name\": \"POST_Bytes per URL\",\n"
        "            \"metric_type\": \"counter\",\n"
        "            \"metric_description\": \"\",\n"
        "            \"labels\": \"{agent=\\\"Unknown\\\",assetId=\\\"asset id\\\",id=\\\"87\\\","
                        "metricName=\\\"Bytes per URL\\\",method=\\\"POST\\\",url=\\\"/index.html\\\"}\",\n"
        "            \"value\": \"1\"\n"
        "        },\n"
        "        {\n"
        "            \"metric_name\": \"request.total\",\n"
        "            \"unique_name\": \"GET_Bytes per URL\",\n"
        "            \"metric_type\": \"counter\",\n"
        "            \"metric_description\": \"\",\n"
        "            \"labels\": \"{agent=\\\"Unknown\\\",assetId=\\\"asset id\\\",id=\\\"87\\\","
                        "metricName=\\\"Bytes per URL\\\",method=\\\"GET\\\",url=\\\"/index2.html\\\"}\",\n"
        "            \"value\": \"1\"\n"
        "        }\n"
        "    ]\n"
        "}";

    EXPECT_EQ(message_body, res);
}

TEST_F(MetricTest, getPromeathusTwoMetrics)
{
    MetricScraper metric_scraper;
    function<string()> get_metrics_func;
    EXPECT_CALL(rest, addGetCall("service-metrics", _)).WillOnce(DoAll(SaveArg<1>(&get_metrics_func), Return(true)));
    metric_scraper.init();

    stringstream configuration;
    configuration << "{\"agentSettings\":[{\"key\":\"prometheus\",\"id\":\"id1\",\"value\":\"true\"},";
    configuration << "{\"key\":\"enable_all_metrics\",\"id\":\"id2\",\"value\":\"true\"}]}\n";

    EXPECT_TRUE(Singleton::Consume<Config::I_Config>::from(conf)->loadConfiguration(configuration));

    CPUMetric cpu_mt;
    cpu_mt.init(
        "CPU usage",
        ReportIS::AudienceTeam::AGENT_CORE,
        ReportIS::IssuingEngine::AGENT_CORE,
        seconds(5),
        false,
        ReportIS::Audience::INTERNAL,
        false,
        "asset id"
    );
    cpu_mt.turnOffStream(GenericMetric::Stream::FOG);
    cpu_mt.turnOffStream(GenericMetric::Stream::DEBUG);
    cpu_mt.registerListener();

    CPUEvent cpu_event;
    cpu_event.setProcessCPU(89);
    cpu_event.notify();

    UrlMetric2 metric;
    metric.init(
        "Bytes per URL",
        ReportIS::AudienceTeam::AGENT_CORE,
        ReportIS::IssuingEngine::AGENT_CORE,
        seconds(5),
        true,
        ReportIS::Audience::INTERNAL,
        false,
        "asset id"
    );
    metric.registerListener();

    HttpTransaction("/index.html", "GET", 10).notify();
    HttpTransaction("/index2.html", "GET", 20).notify();
    HttpTransaction("/index.html", "POST", 40).notify();

    string message_body = get_metrics_func();
    routine();

    string res =
        "{\n"
        "    \"metrics\": [\n"
        "        {\n"
        "            \"metric_name\": \"request.total\",\n"
        "            \"unique_name\": \"GET_Bytes per URL\",\n"
        "            \"metric_type\": \"counter\",\n"
        "            \"metric_description\": \"\",\n"
        "            \"labels\": \"{agent=\\\"Unknown\\\",assetId=\\\"asset id\\\",id=\\\"87\\\","
                        "metricName=\\\"Bytes per URL\\\",method=\\\"GET\\\",url=\\\"/index.html\\\"}\",\n"
        "            \"value\": \"1\"\n"
        "        },\n"
        "        {\n"
        "            \"metric_name\": \"request.total\",\n"
        "            \"unique_name\": \"POST_Bytes per URL\",\n"
        "            \"metric_type\": \"counter\",\n"
        "            \"metric_description\": \"\",\n"
        "            \"labels\": \"{agent=\\\"Unknown\\\",assetId=\\\"asset id\\\",id=\\\"87\\\","
                        "metricName=\\\"Bytes per URL\\\",method=\\\"POST\\\",url=\\\"/index.html\\\"}\",\n"
        "            \"value\": \"1\"\n"
        "        },\n"
        "        {\n"
        "            \"metric_name\": \"request.total\",\n"
        "            \"unique_name\": \"GET_Bytes per URL\",\n"
        "            \"metric_type\": \"counter\",\n"
        "            \"metric_description\": \"\",\n"
        "            \"labels\": \"{agent=\\\"Unknown\\\",assetId=\\\"asset id\\\",id=\\\"87\\\","
                        "metricName=\\\"Bytes per URL\\\",method=\\\"GET\\\",url=\\\"/index2.html\\\"}\",\n"
        "            \"value\": \"1\"\n"
        "        },\n"
        "        {\n"
        "            \"metric_name\": \"cpuMax\",\n"
        "            \"unique_name\": \"cpuMax_CPU usage\",\n"
        "            \"metric_type\": \"gauge\",\n"
        "            \"metric_description\": \"\",\n"
        "            \"labels\": \"{agent=\\\"Unknown\\\",assetId=\\\"asset id\\\",id=\\\"87\\\","
                        "metricName=\\\"CPU usage\\\"}\",\n"
        "            \"value\": \"89\"\n"
        "        },\n"
        "        {\n"
        "            \"metric_name\": \"cpuMin\",\n"
        "            \"unique_name\": \"cpuMin_CPU usage\",\n"
        "            \"metric_type\": \"gauge\",\n"
        "            \"metric_description\": \"\",\n"
        "            \"labels\": \"{agent=\\\"Unknown\\\",assetId=\\\"asset id\\\",id=\\\"87\\\","
                        "metricName=\\\"CPU usage\\\"}\",\n"
        "            \"value\": \"89\"\n"
        "        },\n"
        "        {\n"
        "            \"metric_name\": \"cpuAvg\",\n"
        "            \"unique_name\": \"cpuAvg_CPU usage\",\n"
        "            \"metric_type\": \"gauge\",\n"
        "            \"metric_description\": \"\",\n"
        "            \"labels\": \"{agent=\\\"Unknown\\\",assetId=\\\"asset id\\\",id=\\\"87\\\","
                        "metricName=\\\"CPU usage\\\"}\",\n"
        "            \"value\": \"89\"\n"
        "        },\n"
        "        {\n"
        "            \"metric_name\": \"cpuCurrent\",\n"
        "            \"unique_name\": \"cpuCurrent_CPU usage\",\n"
        "            \"metric_type\": \"gauge\",\n"
        "            \"metric_description\": \"\",\n"
        "            \"labels\": \"{agent=\\\"Unknown\\\",assetId=\\\"asset id\\\",id=\\\"87\\\","
                        "metricName=\\\"CPU usage\\\"}\",\n"
        "            \"value\": \"89\"\n"
        "        },\n"
        "        {\n"
        "            \"metric_name\": \"cpuCounter\",\n"
        "            \"unique_name\": \"cpuCounter_CPU usage\",\n"
        "            \"metric_type\": \"gauge\",\n"
        "            \"metric_description\": \"\",\n"
        "            \"labels\": \"{agent=\\\"Unknown\\\",assetId=\\\"asset id\\\",id=\\\"87\\\","
                        "metricName=\\\"CPU usage\\\"}\",\n"
        "            \"value\": \"1\"\n"
        "        },\n"
        "        {\n"
        "            \"metric_name\": \"cpuTotalCounter\",\n"
        "            \"unique_name\": \"cpuTotalCounter_CPU usage\",\n"
        "            \"metric_type\": \"counter\",\n"
        "            \"metric_description\": \"\",\n"
        "            \"labels\": \"{agent=\\\"Unknown\\\",assetId=\\\"asset id\\\",id=\\\"87\\\","
                        "metricName=\\\"CPU usage\\\"}\",\n"
        "            \"value\": \"1\"\n"
        "        }\n"
        "    ]\n"
        "}";

    EXPECT_EQ(message_body, res);
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
        "    \"cpuTotalCounter\": 1,\n"
        "    \"cpuTops\": [\n"
        "        89.0\n"
        "    ]\n"
        "}";

    string message_body;

    EXPECT_CALL(messaging_mock, sendAsyncMessage(
        _,
        "/api/v1/agents/events",
        _,
        MessageCategory::METRIC,
        _,
        _
    )).WillRepeatedly(SaveArg<2>(&message_body));

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
        "            \"serviceName\": \"Unnamed Nano Service\",\n"
        "            \"serviceId\": \"87\",\n"
        "            \"serviceFamilyId\": \"\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"cpuMax\": 89,\n"
        "            \"cpuMin\": 89,\n"
        "            \"cpuAvg\": 89,\n"
        "            \"cpuCurrent\": 89,\n"
        "            \"cpuCounter\": 1,\n"
        "            \"cpuTotalCounter\": 1,\n"
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
        "    \"cpuTotalCounter\": 2,\n"
        "    \"cpuTops\": [\n"
        "        90.0\n"
        "    ]\n"
        "}";

    EXPECT_CALL(messaging_mock, sendAsyncMessage(
        _,
        "/api/v1/agents/events",
        _,
        MessageCategory::METRIC,
        _,
        _
    )).WillRepeatedly(SaveArg<2>(&message_body));

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
        "            \"serviceName\": \"Unnamed Nano Service\",\n"
        "            \"serviceId\": \"87\",\n"
        "            \"serviceFamilyId\": \"\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"cpuMax\": 90,\n"
        "            \"cpuMin\": 90,\n"
        "            \"cpuAvg\": 90,\n"
        "            \"cpuCurrent\": 90,\n"
        "            \"cpuCounter\": 1,\n"
        "            \"cpuTotalCounter\": 2,\n"
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
        "    \"cpuTotalCounter\": 3,\n"
        "    \"cpuTops\": [\n"
        "        100.0\n"
        "    ]\n"
        "}";

    EXPECT_CALL(messaging_mock, sendAsyncMessage(
        _,
        "/api/v1/agents/events",
        _,
        MessageCategory::METRIC,
        _,
        _
    )).WillRepeatedly(SaveArg<2>(&message_body));

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
        "            \"serviceName\": \"Unnamed Nano Service\",\n"
        "            \"serviceId\": \"87\",\n"
        "            \"serviceFamilyId\": \"\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"cpuMax\": 100,\n"
        "            \"cpuMin\": 100,\n"
        "            \"cpuAvg\": 100,\n"
        "            \"cpuCurrent\": 100,\n"
        "            \"cpuCounter\": 1,\n"
        "            \"cpuTotalCounter\": 3,\n"
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
    auto init_report = cpu_mt.generateReport();

    EXPECT_NE(init_report, "");

    EXPECT_THAT(init_report, HasSubstr("\"Metric\": \"CPU usage\""));
    EXPECT_THAT(init_report, HasSubstr("\"Reporting interval\": 5,"));
    EXPECT_THAT(init_report, HasSubstr("cpuMax"));
    EXPECT_THAT(init_report, HasSubstr("cpuMin"));
    EXPECT_THAT(init_report, HasSubstr("cpuAvg"));
    EXPECT_THAT(init_report, HasSubstr("cpuCurrent"));
    EXPECT_THAT(init_report, HasSubstr("cpuTops"));

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
        "    \"cpuTotalCounter\": 1,\n"
        "    \"cpuTops\": [\n"
        "        89.0\n"
        "    ]\n"
        "}";

    string message_body;

    EXPECT_CALL(messaging_mock, sendAsyncMessage(
        _,
        "/api/v1/agents/events",
        _,
        MessageCategory::METRIC,
        _,
        _
    )).WillRepeatedly(SaveArg<2>(&message_body));

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
        "            \"serviceName\": \"Unnamed Nano Service\",\n"
        "            \"serviceId\": \"87\",\n"
        "            \"serviceFamilyId\": \"\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"cpuMax\": 89,\n"
        "            \"cpuMin\": 89,\n"
        "            \"cpuAvg\": 89,\n"
        "            \"cpuCurrent\": 89,\n"
        "            \"cpuCounter\": 1,\n"
        "            \"cpuTotalCounter\": 1,\n"
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

    auto report = cpu_mt.generateReport();
    cpu_mt.resetMetrics();
    EXPECT_THAT(metric_str, HasSubstr(report));
    debug_output.str("");

    report = cpu_mt.generateReport();
    metric_str =
        "{\n"
        "    \"Metric\": \"CPU usage\",\n"
        "    \"Reporting interval\": 5,\n"
        "    \"cpuMax\": 0.0,\n"
        "    \"cpuMin\": 0.0,\n"
        "    \"cpuAvg\": 0.0,\n"
        "    \"cpuCurrent\": 0.0,\n"
        "    \"cpuCounter\": 0,\n"
        "    \"cpuTotalCounter\": 1,\n"
        "    \"cpuTops\": []\n"
        "}";
    EXPECT_EQ(report, metric_str);
    debug_output.str("");

    routine();

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
        "    \"cpuTotalCounter\": 2,\n"
        "    \"cpuTops\": [\n"
        "        90.0\n"
        "    ]\n"
        "}";

    EXPECT_CALL(messaging_mock, sendAsyncMessage(
        _,
        "/api/v1/agents/events",
        _,
        MessageCategory::METRIC,
        _,
        _
    )).WillRepeatedly(SaveArg<2>(&message_body));

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
        "            \"serviceName\": \"Unnamed Nano Service\",\n"
        "            \"serviceId\": \"87\",\n"
        "            \"serviceFamilyId\": \"\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"cpuMax\": 90,\n"
        "            \"cpuMin\": 90,\n"
        "            \"cpuAvg\": 90,\n"
        "            \"cpuCurrent\": 90,\n"
        "            \"cpuCounter\": 1,\n"
        "            \"cpuTotalCounter\": 2,\n"
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
        "    \"cpuTotalCounter\": 3,\n"
        "    \"cpuTops\": [\n"
        "        90.0,\n"
        "        100.0\n"
        "    ]\n"
        "}";

    EXPECT_CALL(messaging_mock, sendAsyncMessage(
        _,
        "/api/v1/agents/events",
        _,
        MessageCategory::METRIC,
        _,
        _
    )).WillRepeatedly(SaveArg<2>(&message_body));

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
        "            \"serviceName\": \"My named nano service\",\n"
        "            \"serviceId\": \"87\",\n"
        "            \"serviceFamilyId\": \"\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"cpuMax\": 100,\n"
        "            \"cpuMin\": 90,\n"
        "            \"cpuAvg\": 95,\n"
        "            \"cpuCurrent\": 100,\n"
        "            \"cpuCounter\": 2,\n"
        "            \"cpuTotalCounter\": 3,\n"
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
        "    \"cpuTotalCounter\": 3,\n"
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

    HttpTransaction("/index.html", "GET", 10).notify();
    HttpTransaction("/index2.html", "GET", 20).notify();
    HttpTransaction("/index.html", "POST", 40).notify();

    string message_body;

    EXPECT_CALL(messaging_mock, sendAsyncMessage(
        _,
        "/api/v1/agents/events",
        _,
        MessageCategory::METRIC,
        _,
        _
    )).WillRepeatedly(SaveArg<2>(&message_body));
    routine();

    string msg_str =
        "{\n"
        "    \"Metric\": \"Bytes per URL\",\n"
        "    \"Reporting interval\": 5,\n"
        "    \"PerUrlAvg\": {\n"
        "        \"/index.html\": 25.0,\n"
        "        \"/index2.html\": 20.0\n"
        "    },\n"
        "    \"TotalRequests\": {\n"
        "        \"/index.html\": 2,\n"
        "        \"/index2.html\": 1\n"
        "    }\n"
        "}";
    EXPECT_THAT(debug_output.str(), HasSubstr(msg_str));

    debug_output.str("");
    routine();
    msg_str =
        "{\n"
        "    \"Metric\": \"Bytes per URL\",\n"
        "    \"Reporting interval\": 5,\n"
        "    \"PerUrlAvg\": {},\n"
        "    \"TotalRequests\": {\n"
        "        \"/index.html\": 2,\n"
        "        \"/index2.html\": 1\n"
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

TEST_F(MetricTest, basicAIOPSMetricTest)
{
    EXPECT_CALL(timer, getWalltimeStr()).WillRepeatedly(Return(string("2016-11-13T17:31:24.087")));
    EXPECT_CALL(mock_encryptor, base64Encode(_)).WillRepeatedly(Return("compress and encode metric payload"));

    CPUMetric cpu_mt;
    cpu_mt.init(
        "CPU usage",
        ReportIS::AudienceTeam::AGENT_CORE,
        ReportIS::IssuingEngine::AGENT_CORE,
        seconds(5),
        false
    );
    cpu_mt.setAiopsMetric();
    cpu_mt.registerListener();

    EXPECT_EQ(cpu_mt.getMetricName(), "CPU usage");
    EXPECT_EQ(cpu_mt.getReportInterval().count(), 5);

    routine();

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
        "    \"cpuTotalCounter\": 1,\n"
        "    \"cpuTops\": [\n"
        "        89.0\n"
        "    ]\n"
        "}";

    string message_body;
    EXPECT_CALL(messaging_mock, sendAsyncMessage(
        _,
        "/api/v1/agents/events",
        _,
        MessageCategory::METRIC,
        _,
        _
    )).WillRepeatedly(SaveArg<2>(&message_body));

    string expected_message =
        "{\n"
        "    \"log\": {\n"
        "        \"eventTime\": \"2016-11-13T17:31:24.087\",\n"
        "        \"eventName\": \"AIOPS Metric Data\",\n"
        "        \"eventSeverity\": \"Info\",\n"
        "        \"eventPriority\": \"Low\",\n"
        "        \"eventType\": \"Periodic\",\n"
        "        \"eventLevel\": \"Log\",\n"
        "        \"eventLogLevel\": \"info\",\n"
        "        \"eventAudience\": \"Internal\",\n"
        "        \"eventAudienceTeam\": \"\",\n"
        "        \"eventFrequency\": 5,\n"
        "        \"eventTags\": [\n"
        "            \"Informational\"\n"
        "        ],\n"
        "        \"eventSource\": {\n"
        "            \"agentId\": \"Unknown\",\n"
        "            \"issuingEngine\": \"horizonTelemetryMetrics\",\n"
        "            \"eventTraceId\": \"\",\n"
        "            \"eventSpanId\": \"\",\n"
        "            \"issuingEngineVersion\": \"\",\n"
        "            \"serviceName\": \"Unnamed Nano Service\",\n"
        "            \"serviceId\": \"87\",\n"
        "            \"serviceFamilyId\": \"\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"eventObject\": {\n"
        "                \"records\": \"compress and encode metric payload\"\n"
        "            }\n"
        "        }\n"
        "    }\n"
        "}";

    routine();
    EXPECT_THAT(debug_output.str(), HasSubstr(metric_str));
    EXPECT_EQ(message_body, expected_message);
    debug_output.str("");
}

TEST_F(MetricTest, testAIOPSMapMetric)
{
    EXPECT_CALL(timer, getWalltimeStr()).WillRepeatedly(Return(string("2016-11-13T17:31:24.087")));
    UrlMetric url_mt;
    url_mt.init(
        "Bytes per URL",
        ReportIS::AudienceTeam::AGENT_CORE,
        ReportIS::IssuingEngine::AGENT_CORE,
        seconds(5),
        true
    );
    url_mt.registerListener();

    url_mt.setAiopsMetric();

    HttpTransaction("/index.html", "GET", 10).notify();
    HttpTransaction("/index2.html", "GET", 20).notify();
    HttpTransaction("/index.html", "POST", 40).notify();

    string message_body;

    EXPECT_CALL(messaging_mock, sendAsyncMessage(
        _,
        "/api/v1/agents/events",
        _,
        MessageCategory::METRIC,
        _,
        _
    )).WillRepeatedly(SaveArg<2>(&message_body));
    EXPECT_CALL(mock_encryptor, base64Encode(_)).WillRepeatedly(Return("compress and encode metric payload"));
    routine();

    // aiops data example
    //     "                \"Metrics\": [\n"
    //     "                    {\n"
    //     "                        \"Timestamp\": \"2016-11-13T17:31:24Z\",\n"
    //     "                        \"MetricName\": \"/index.html\",\n"
    //     "                        \"MetricType\": \"Gauge\",\n"
    //     "                        \"MetricUnit\": \"\",\n"
    //     "                        \"MetricDescription\": \"\",\n"
    //     "                        \"MetricValue\": 0.0,\n"
    //     "                        \"ResourceAttributes\": {},\n"
    //     "                        \"MetricAttributes\": {\n"
    //     "                            \"key1\": \"value1\",\n"
    //     "                            \"key2\": \"value2\"\n"
    //     "                        },\n"
    //     "                        \"AssetID\": \"Unknown\"\n"
    //     "                    },\n"
    //     "                    {\n"
    //     "                        \"Timestamp\": \"2016-11-13T17:31:24Z\",\n"
    //     "                        \"MetricName\": \"/index2.html\",\n"
    //     "                        \"MetricType\": \"Gauge\",\n"
    //     "                        \"MetricUnit\": \"\",\n"
    //     "                        \"MetricDescription\": \"\",\n"
    //     "                        \"MetricValue\": 0.0,\n"
    //     "                        \"ResourceAttributes\": {},\n"
    //     "                        \"MetricAttributes\": {\n"
    //     "                            \"key1\": \"value1\",\n"
    //     "                            \"key2\": \"value2\"\n"
    //     "                        },\n"
    //     "                        \"AssetID\": \"Unknown\"\n"
    //     "                    },\n"
    //     "                    {\n"
    //     "                        \"Timestamp\": \"2016-11-13T17:31:24Z\",\n"
    //     "                        \"MetricName\": \"/index.html\",\n"
    //     "                        \"MetricType\": \"Counter\",\n"
    //     "                        \"MetricUnit\": \"\",\n"
    //     "                        \"MetricDescription\": \"\",\n"
    //     "                        \"MetricValue\": 0.0,\n"
    //     "                        \"ResourceAttributes\": {},\n"
    //     "                        \"MetricAttributes\": {},\n"
    //     "                        \"AssetID\": \"Unknown\"\n"
    //     "                    },\n"
    //     "                    {\n"
    //     "                        \"Timestamp\": \"2016-11-13T17:31:24Z\",\n"
    //     "                        \"MetricName\": \"/index2.html\",\n"
    //     "                        \"MetricType\": \"Counter\",\n"
    //     "                        \"MetricUnit\": \"\",\n"
    //     "                        \"MetricDescription\": \"\",\n"
    //     "                        \"MetricValue\": 0.0,\n"
    //     "                        \"ResourceAttributes\": {},\n"
    //     "                        \"MetricAttributes\": {},\n"
    //     "                        \"AssetID\": \"Unknown\"\n"
    //     "                    }\n"
    //     "                ]\n"
    //     "            }\n"
    //     "        }\n"
    //     "    }\n"
    //     "}";


    string expected_message =
        "{\n"
        "    \"log\": {\n"
        "        \"eventTime\": \"2016-11-13T17:31:24.087\",\n"
        "        \"eventName\": \"AIOPS Metric Data\",\n"
        "        \"eventSeverity\": \"Info\",\n"
        "        \"eventPriority\": \"Low\",\n"
        "        \"eventType\": \"Periodic\",\n"
        "        \"eventLevel\": \"Log\",\n"
        "        \"eventLogLevel\": \"info\",\n"
        "        \"eventAudience\": \"Internal\",\n"
        "        \"eventAudienceTeam\": \"\",\n"
        "        \"eventFrequency\": 5,\n"
        "        \"eventTags\": [\n"
        "            \"Informational\"\n"
        "        ],\n"
        "        \"eventSource\": {\n"
        "            \"agentId\": \"Unknown\",\n"
        "            \"issuingEngine\": \"horizonTelemetryMetrics\",\n"
        "            \"eventTraceId\": \"\",\n"
        "            \"eventSpanId\": \"\",\n"
        "            \"issuingEngineVersion\": \"\",\n"
        "            \"serviceName\": \"Unnamed Nano Service\",\n"
        "            \"serviceId\": \"87\",\n"
        "            \"serviceFamilyId\": \"\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"eventObject\": {\n"
        "                \"records\": \"compress and encode metric payload\"\n"
        "            }\n"
        "        }\n"
        "    }\n"
        "}";

    EXPECT_EQ(message_body, expected_message);
}
