#include "ips_comp.h"

#include <sstream>

#include "cptest.h"
#include "ips_entry.h"
#include "new_table_entry.h"
#include "keyword_comp.h"
#include "environment.h"
#include "mock/mock_table.h"
#include "config.h"
#include "http_manager.h"
#include "config_component.h"
#include "agent_details.h"
#include "mock/mock_logging.h"
#include "mock/mock_time_get.h"
#include "mock/mock_mainloop.h"
#include "encryptor.h"
#include "generic_rulebase/generic_rulebase.h"
#include "generic_rulebase/triggers_config.h"

using namespace testing;
using namespace std;

class ComponentTest : public Test
{
public:
    ComponentTest()
    {
        comp.preload();
        comp.init();
    }

    ~ComponentTest()
    {
        comp.fini();
    }

    void
    loadPolicy(const string &config)
    {
        stringstream ss;
        ss << config;
        Singleton::Consume<Config::I_Config>::from(conf)->loadConfiguration(ss);
    }

    void
    setTrigger()
    {
        string log_trigger(
            "{"
            "    \"context\": \"triggerId(5eaeefde6765c30010bae8b6)\","
            "    \"triggerName\": \"Logging Trigger\","
            "    \"triggerType\": \"log\","
            "    \"urlForSyslog\": \"\","
            "    \"urlForCef\": \"128.1.1.1:333\","
            "    \"acAllow\": false,"
            "    \"acDrop\": true,"
            "    \"complianceViolations\": true,"
            "    \"complianceWarnings\": true,"
            "    \"logToAgent\": true,"
            "    \"logToCloud\": true,"
            "    \"logToSyslog\": false,"
            "    \"logToCef\": true,"
            "    \"tpDetect\": true,"
            "    \"tpPrevent\": true,"
            "    \"verbosity\": \"Standard\","
            "    \"webBody\": true,"
            "    \"webHeaders\": true,"
            "    \"webRequests\": true,"
            "    \"webUrlPath\": true,"
            "    \"webUrlQuery\": true"
            "}"
        );

        stringstream ss(log_trigger);
        cereal::JSONInputArchive ar(ss);
        LogTriggerConf trigger;
        trigger.load(ar);

        setConfiguration(trigger, "rulebase", "log");
    }

    IPSComp comp;
    StrictMock<MockTable> table;
    IPSEntry entry;

    GenericRulebase generic_rulebase;
    ConfigComponent conf;
    Encryptor encryptor;
    KeywordComp keywords;
    ::Environment env;
    AgentDetails details;
    NiceMock<MockLogging> logs;
    NiceMock<MockTimeGet> time;
    NiceMock<MockMainLoop> mainloop;
    static const EventVerdict inspect;
    static const EventVerdict accept;
    static const EventVerdict drop;

    HttpHeader end_headers{Buffer(""), Buffer(""), 0, true};
};

static bool
operator ==(const EventVerdict &first, const EventVerdict &second)
{
    return first.getVerdict() == second.getVerdict();
}

const EventVerdict ComponentTest::inspect(ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INSPECT);

const EventVerdict ComponentTest::accept(ngx_http_cp_verdict_e::TRAFFIC_VERDICT_ACCEPT);

const EventVerdict ComponentTest::drop(ngx_http_cp_verdict_e::TRAFFIC_VERDICT_DROP);

TEST_F(ComponentTest, check_init_fini_do_not_crush)
{
}

TEST_F(ComponentTest, new_table_entry_with_empty_configuration)
{
    NewTableEntry().notify();
}

TEST_F(ComponentTest, new_table_entry_with_configuration)
{
    string config =
        "{"
            "\"IPS\": {"
                "\"configurations\": ["
                    "{"
                        "\"context\": \"\","
                        "\"contextsConfiguration\": ["
                            "{"
                                "\"type\": \"keep\","
                                "\"name\": \"HTTP_REQUEST_BODY\""
                            "}"
                        "]"
                    "}"
                "],"
                "\"protections\": ["
                    "{"
                        "\"protectionMetadata\": {"
                            "\"protectionName\": \"Test\","
                            "\"maintrainId\": \"101\","
                            "\"severity\": \"Low\","
                            "\"confidenceLevel\": \"Low\","
                            "\"performanceImpact\": \"Medium High\","
                            "\"lastUpdate\": \"20210420\","
                            "\"tags\": [],"
                            "\"cveList\": []"
                        "},"
                        "\"detectionRules\": {"
                            "\"type\": \"simple\","
                            "\"SSM\": \"\","
                            "\"keywords\": \"data: \\\"ddd\\\";\","
                            "\"context\": [\"HTTP_REQUEST_BODY\"]"
                        "}"
                    "}"
                "],"
                "\"IpsProtections\": ["
                    "{"
                        "\"context\": \"\","
                        "\"ruleName\": \"rule1\","
                        "\"assetName\": \"asset1\","
                        "\"assetId\": \"1-1-1\","
                        "\"practiceId\": \"2-2-2\","
                        "\"practiceName\": \"practice1\","
                        "\"defaultAction\": \"Detect\","
                        "\"rules\": ["
                            "{"
                                "\"action\": \"Prevent\","
                                "\"severityLevel\": \"Low or above\","
                                "\"performanceImpact\": \"High or lower\","
                                "\"confidenceLevel\": \"Low\""
                            "}"
                        "]"
                    "}"
                "]"
            "}"
        "}";

    loadPolicy(config);
    EXPECT_CALL(table, createStateRValueRemoved(_, _));
    EXPECT_CALL(table, getState(_)).WillOnce(Return(&entry));
    NewTableEntry().notify();
}

TEST_F(ComponentTest, events)
{
    EXPECT_CALL(table, hasState(_)).WillRepeatedly(Return(true));
    IPSEntry entry;
    EXPECT_CALL(table, getState(_)).WillRepeatedly(Return(&entry));

    HttpTransactionData transaction;
    EXPECT_THAT(NewHttpTransactionEvent(transaction).query(), ElementsAre(accept));
    HttpHeader header_req(Buffer("key"), Buffer("val"), 1);
    EXPECT_THAT(HttpRequestHeaderEvent(header_req).query(), ElementsAre(inspect));
    HttpBody body_req(Buffer("data"), 0, true);
    EXPECT_THAT(HttpRequestBodyEvent(body_req, Buffer()).query(), ElementsAre(inspect));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(accept));

    EXPECT_THAT(ResponseCodeEvent(200).query(), ElementsAre(inspect));
    HttpHeader header_res(Buffer("key"), Buffer("val"), 2);
    EXPECT_THAT(HttpResponseHeaderEvent(header_res).query(), ElementsAre(inspect));
    HttpBody body_res(Buffer("data"), true, 0);
    EXPECT_THAT(HttpResponseBodyEvent(body_res, Buffer()).query(), ElementsAre(accept));
    EXPECT_THAT(EndTransactionEvent().performNamedQuery(), ElementsAre(Pair("ips application", accept)));
}

TEST_F(ComponentTest, check_url_decoding)
{
    string config =
        "{"
            "\"IPS\": {"
                "\"protections\": ["
                    "{"
                        "\"protectionMetadata\": {"
                            "\"protectionName\": \"Test\","
                            "\"maintrainId\": \"101\","
                            "\"severity\": \"Low\","
                            "\"confidenceLevel\": \"Low\","
                            "\"performanceImpact\": \"Medium High\","
                            "\"lastUpdate\": \"20210420\","
                            "\"tags\": [],"
                            "\"cveList\": []"
                        "},"
                        "\"detectionRules\": {"
                            "\"type\": \"simple\","
                            "\"SSM\": \"\","
                            "\"keywords\": \"data: \\\"d d\\\";\","
                            "\"context\": [\"HTTP_COMPLETE_URL_DECODED\"]"
                        "}"
                    "}"
                "],"
                "\"IpsProtections\": ["
                    "{"
                        "\"context\": \"\","
                        "\"ruleName\": \"rule1\","
                        "\"assetName\": \"asset1\","
                        "\"assetId\": \"1-1-1\","
                        "\"practiceId\": \"2-2-2\","
                        "\"practiceName\": \"practice1\","
                        "\"defaultAction\": \"Detect\","
                        "\"rules\": ["
                            "{"
                                "\"action\": \"Prevent\","
                                "\"severityLevel\": \"Low or above\","
                                "\"performanceImpact\": \"High or lower\","
                                "\"confidenceLevel\": \"Low\""
                            "}"
                        "]"
                    "}"
                "]"
            "}"
        "}";
    loadPolicy(config);

    EXPECT_CALL(table, createStateRValueRemoved(_, _));
    EXPECT_CALL(table, getState(_)).WillRepeatedly(Return(&entry));
    EXPECT_CALL(table, hasState(_)).WillRepeatedly(Return(true));

    HttpTransactionData new_transaction(
        "1.1",
        "GET",
        "ffff",
        IPAddr::createIPAddr("0.0.0.0").unpack(),
        80,
        "d%20d",
        IPAddr::createIPAddr("1.1.1.1").unpack(),
        5428
    );

    EXPECT_THAT(NewHttpTransactionEvent(new_transaction).query(), ElementsAre(inspect));
    EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(drop));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(drop));
}

TEST_F(ComponentTest, check_query)
{
    string config =
        "{"
            "\"IPS\": {"
                "\"protections\": ["
                    "{"
                        "\"protectionMetadata\": {"
                            "\"protectionName\": \"Test\","
                            "\"maintrainId\": \"101\","
                            "\"severity\": \"Low\","
                            "\"confidenceLevel\": \"Low\","
                            "\"performanceImpact\": \"Medium High\","
                            "\"lastUpdate\": \"20210420\","
                            "\"tags\": [],"
                            "\"cveList\": []"
                        "},"
                        "\"detectionRules\": {"
                            "\"type\": \"simple\","
                            "\"SSM\": \"\","
                            "\"keywords\": \"data: \\\"g=#\\\";\","
                            "\"context\": [\"HTTP_QUERY_DECODED\"]"
                        "}"
                    "}"
                "],"
                "\"IpsProtections\": ["
                    "{"
                        "\"context\": \"\","
                        "\"ruleName\": \"rule1\","
                        "\"assetName\": \"asset1\","
                        "\"assetId\": \"1-1-1\","
                        "\"practiceId\": \"2-2-2\","
                        "\"practiceName\": \"practice1\","
                        "\"defaultAction\": \"Detect\","
                        "\"rules\": ["
                            "{"
                                "\"action\": \"Prevent\","
                                "\"severityLevel\": \"Low or above\","
                                "\"performanceImpact\": \"High or lower\","
                                "\"confidenceLevel\": \"Low\""
                            "}"
                        "]"
                    "}"
                "]"
            "}"
        "}";
    loadPolicy(config);

    EXPECT_CALL(table, createStateRValueRemoved(_, _));
    EXPECT_CALL(table, getState(_)).WillRepeatedly(Return(&entry));
    EXPECT_CALL(table, hasState(_)).WillRepeatedly(Return(true));

    HttpTransactionData new_transaction(
        "1.1",
        "GET",
        "ffff",
        IPAddr::createIPAddr("0.0.0.0").unpack(),
        80,
        "d%20d?g=%23",
        IPAddr::createIPAddr("1.1.1.1").unpack(),
        5428
    );

    EXPECT_THAT(NewHttpTransactionEvent(new_transaction).query(), ElementsAre(inspect));
    EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(drop));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(drop));
}

TEST_F(ComponentTest, check_query_detect_mode)
{
    string config =
        "{"
            "\"IPS\": {"
                "\"protections\": ["
                    "{"
                        "\"protectionMetadata\": {"
                            "\"protectionName\": \"Test\","
                            "\"maintrainId\": \"101\","
                            "\"severity\": \"Low\","
                            "\"confidenceLevel\": \"Low\","
                            "\"performanceImpact\": \"Medium High\","
                            "\"lastUpdate\": \"20210420\","
                            "\"tags\": [],"
                            "\"cveList\": []"
                        "},"
                        "\"detectionRules\": {"
                            "\"type\": \"simple\","
                            "\"SSM\": \"\","
                            "\"keywords\": \"data: \\\"d d\\\";\","
                            "\"context\": [\"HTTP_QUERY_DECODED\"]"
                        "}"
                    "}"
                "],"
                "\"IpsProtections\": ["
                    "{"
                        "\"context\": \"\","
                        "\"ruleName\": \"rule1\","
                        "\"assetName\": \"asset1\","
                        "\"assetId\": \"1-1-1\","
                        "\"practiceId\": \"2-2-2\","
                        "\"practiceName\": \"practice1\","
                        "\"defaultAction\": \"Detect\","
                        "\"rules\": ["
                            "{"
                                "\"action\": \"Detect\","
                                "\"severityLevel\": \"Low or above\","
                                "\"performanceImpact\": \"High or lower\","
                                "\"confidenceLevel\": \"Low\""
                            "}"
                        "]"
                    "}"
                "]"
            "}"
        "}";
    loadPolicy(config);

    EXPECT_CALL(table, createStateRValueRemoved(_, _));
    EXPECT_CALL(table, getState(_)).WillOnce(Return(&entry));

    HttpTransactionData new_transaction(
        "1.1",
        "GET",
        "ffff",
        IPAddr::createIPAddr("0.0.0.0").unpack(),
        80,
        "d%20d",
        IPAddr::createIPAddr("1.1.1.1").unpack(),
        5428
    );

    EXPECT_THAT(NewHttpTransactionEvent(new_transaction).query(), ElementsAre(inspect));
    EXPECT_THAT(EndTransactionEvent().query(), ElementsAre(accept));
}

TEST_F(ComponentTest, check_query_inactive_mode)
{
    string config =
        "{"
            "\"IPS\": {"
                "\"protections\": ["
                    "{"
                        "\"protectionMetadata\": {"
                            "\"protectionName\": \"Test\","
                            "\"maintrainId\": \"101\","
                            "\"severity\": \"Low\","
                            "\"confidenceLevel\": \"Low\","
                            "\"performanceImpact\": \"Medium High\","
                            "\"lastUpdate\": \"20210420\","
                            "\"tags\": [],"
                            "\"cveList\": []"
                        "},"
                        "\"detectionRules\": {"
                            "\"type\": \"simple\","
                            "\"SSM\": \"\","
                            "\"keywords\": \"data: \\\"g=#\\\";\","
                            "\"context\": [\"HTTP_QUERY_DECODED\"]"
                        "}"
                    "}"
                "],"
                "\"IpsProtections\": ["
                    "{"
                        "\"context\": \"\","
                        "\"ruleName\": \"rule1\","
                        "\"assetName\": \"asset1\","
                        "\"assetId\": \"1-1-1\","
                        "\"practiceId\": \"2-2-2\","
                        "\"practiceName\": \"practice1\","
                        "\"defaultAction\": \"Prevent\","
                        "\"rules\": ["
                            "{"
                                "\"action\": \"Inactive\","
                                "\"severityLevel\": \"Low or above\","
                                "\"performanceImpact\": \"High or lower\","
                                "\"confidenceLevel\": \"Low\""
                            "}"
                        "]"
                    "}"
                "]"
            "}"
        "}";
    loadPolicy(config);

    HttpTransactionData new_transaction(
        "1.1",
        "GET",
        "ffff",
        IPAddr::createIPAddr("0.0.0.0").unpack(),
        80,
        "d%20d?g=%23",
        IPAddr::createIPAddr("1.1.1.1").unpack(),
        5428
    );

    EXPECT_THAT(NewHttpTransactionEvent(new_transaction).query(), ElementsAre(accept));
}

TEST_F(ComponentTest, check_query_silent_mode)
{
    string config =
        "{"
            "\"IPS\": {"
                "\"protections\": ["
                    "{"
                        "\"protectionMetadata\": {"
                            "\"silent\": true,"
                            "\"protectionName\": \"Test\","
                            "\"maintrainId\": \"101\","
                            "\"severity\": \"Low\","
                            "\"confidenceLevel\": \"Low\","
                            "\"performanceImpact\": \"Medium High\","
                            "\"lastUpdate\": \"20210420\","
                            "\"tags\": [],"
                            "\"cveList\": []"
                        "},"
                        "\"detectionRules\": {"
                            "\"type\": \"simple\","
                            "\"SSM\": \"\","
                            "\"keywords\": \"data: \\\"g=#\\\";\","
                            "\"context\": [\"HTTP_QUERY_DECODED\"]"
                        "}"
                    "}"
                "],"
                "\"IpsProtections\": ["
                    "{"
                        "\"context\": \"\","
                        "\"ruleName\": \"rule1\","
                        "\"assetName\": \"asset1\","
                        "\"assetId\": \"1-1-1\","
                        "\"practiceId\": \"2-2-2\","
                        "\"practiceName\": \"practice1\","
                        "\"defaultAction\": \"Prevent\","
                        "\"rules\": []"
                    "}"
                "]"
            "}"
        "}";
    loadPolicy(config);

    HttpTransactionData new_transaction(
        "1.1",
        "GET",
        "ffff",
        IPAddr::createIPAddr("0.0.0.0").unpack(),
        80,
        "d%20d?g=%23",
        IPAddr::createIPAddr("1.1.1.1").unpack(),
        5428
    );

    EXPECT_CALL(table, createStateRValueRemoved(_, _));
    EXPECT_CALL(table, getState(_)).WillRepeatedly(Return(&entry));
    EXPECT_CALL(table, hasState(_)).WillRepeatedly(Return(true));

    EXPECT_THAT(NewHttpTransactionEvent(new_transaction).query(), ElementsAre(inspect));
    EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(inspect));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(accept));
}

TEST_F(ComponentTest, check_filtering_by_year)
{
    string config =
        "{"
            "\"IPS\": {"
                "\"protections\": ["
                    "{"
                        "\"protectionMetadata\": {"
                            "\"protectionName\": \"Test\","
                            "\"maintrainId\": \"101\","
                            "\"severity\": \"Low\","
                            "\"confidenceLevel\": \"Low\","
                            "\"performanceImpact\": \"Medium High\","
                            "\"lastUpdate\": \"20210420\","
                            "\"tags\": [ \"ggg\", \"Threat_Year_2014\", \"hhh\" ],"
                            "\"cveList\": []"
                        "},"
                        "\"detectionRules\": {"
                            "\"type\": \"simple\","
                            "\"SSM\": \"\","
                            "\"keywords\": \"data: \\\"g=#\\\";\","
                            "\"context\": [\"HTTP_QUERY_DECODED\"]"
                        "}"
                    "}"
                "],"
                "\"IpsProtections\": ["
                    "{"
                        "\"context\": \"\","
                        "\"ruleName\": \"rule1\","
                        "\"assetName\": \"asset1\","
                        "\"assetId\": \"1-1-1\","
                        "\"practiceId\": \"2-2-2\","
                        "\"practiceName\": \"practice1\","
                        "\"defaultAction\": \"Prevent\","
                        "\"rules\": ["
                            "{"
                                "\"action\": \"Inactive\","
                                "\"protectionsFromYear\": 2013"
                            "}"
                        "]"
                    "}"
                "]"
            "}"
        "}";
    loadPolicy(config);

    HttpTransactionData new_transaction(
        "1.1",
        "GET",
        "ffff",
        IPAddr::createIPAddr("0.0.0.0").unpack(),
        80,
        "d%20d?g=%23",
        IPAddr::createIPAddr("1.1.1.1").unpack(),
        5428
    );

    EXPECT_THAT(NewHttpTransactionEvent(new_transaction).query(), ElementsAre(accept));
}

TEST_F(ComponentTest, log_fields)
{
    string config =
        "{"
            "\"IPS\": {"
                "\"Max Field Size\": ["
                    "{"
                        "\"value\": 25"
                    "}"
                "],"
                "\"protections\": ["
                    "{"
                        "\"protectionMetadata\": {"
                            "\"protectionName\": \"Test\","
                            "\"maintrainId\": \"101\","
                            "\"severity\": \"Low\","
                            "\"confidenceLevel\": \"Low\","
                            "\"performanceImpact\": \"Medium High\","
                            "\"lastUpdate\": \"20210420\","
                            "\"tags\": [],"
                            "\"cveList\": []"
                        "},"
                        "\"detectionRules\": {"
                            "\"type\": \"simple\","
                            "\"SSM\": \"\","
                            "\"keywords\": \"data: \\\"ddd\\\";\","
                            "\"context\": [\"HTTP_REQUEST_BODY\"]"
                        "}"
                    "}"
                "],"
                "\"IpsProtections\": ["
                    "{"
                        "\"context\": \"\","
                        "\"ruleName\": \"rule1\","
                        "\"assetName\": \"asset1\","
                        "\"assetId\": \"1-1-1\","
                        "\"practiceId\": \"2-2-2\","
                        "\"practiceName\": \"practice1\","
                        "\"defaultAction\": \"Detect\","
                        "\"rules\": ["
                            "{"
                                "\"action\": \"Prevent\","
                                "\"severityLevel\": \"Low or above\","
                                "\"performanceImpact\": \"High or lower\","
                                "\"confidenceLevel\": \"Low\""
                            "}"
                        "]"
                    "}"
                "]"
            "}"
        "}";
    loadPolicy(config);
    setTrigger();

    EXPECT_CALL(table, createStateRValueRemoved(_, _));
    EXPECT_CALL(table, getState(_)).WillRepeatedly(Return(&entry));
    EXPECT_CALL(table, hasState(_)).WillRepeatedly(Return(true));

    Report report;
    EXPECT_CALL(logs, sendLog(_)).WillOnce(SaveArg<0>(&report));

    HttpTransactionData new_transaction(
        "1.1",
        "POST",
        "ffff",
        IPAddr::createIPAddr("0.0.0.0").unpack(),
        80,
        "d%20d?g=%23",
        IPAddr::createIPAddr("1.1.1.1").unpack(),
        5428
    );

    EXPECT_THAT(NewHttpTransactionEvent(new_transaction).query(), ElementsAre(inspect));
    HttpHeader header_req1(Buffer("key1"), Buffer("val1"), 1);
    EXPECT_THAT(HttpRequestHeaderEvent(header_req1).query(), ElementsAre(inspect));
    HttpHeader header_req2(Buffer("key2"), Buffer("val2"), 2);
    EXPECT_THAT(HttpRequestHeaderEvent(header_req2).query(), ElementsAre(inspect));
    HttpHeader header_req3(Buffer("key3"), Buffer("val3"), 3);
    EXPECT_THAT(HttpRequestHeaderEvent(header_req3).query(), ElementsAre(inspect));
    string body_str("data: ddd");
    HttpBody body_req(Buffer(body_str), 0, true);
    EXPECT_THAT(HttpRequestBodyEvent(body_req, Buffer()).query(), ElementsAre(inspect));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(drop));

    EXPECT_THAT(report.getSyslog(), HasSubstr("httpRequestHeaders=\"key1: val1, key2: val2\""));
    EXPECT_THAT(report.getSyslog(), HasSubstr("httpRequestBody=\"" + body_str + "\""));
    EXPECT_THAT(report.getSyslog(), HasSubstr("signatureVersion=\"20210420\""));
}

TEST_F(ComponentTest, log_field_httpRequestHeader)
{
    string config =
        "{"
        "\"IPS\": {"
        "\"Max Field Size\": ["
        "{"
        "\"value\": 25"
        "}"
        "],"
        "\"protections\": ["
        "{"
        "\"protectionMetadata\": {"
        "\"protectionName\": \"Test\","
        "\"maintrainId\": \"101\","
        "\"severity\": \"Low\","
        "\"confidenceLevel\": \"Low\","
        "\"performanceImpact\": \"Medium High\","
        "\"lastUpdate\": \"20210420\","
        "\"tags\": [],"
        "\"cveList\": []"
        "},"
        "\"detectionRules\": {"
        "\"type\": \"simple\","
        "\"SSM\": \"\","
        "\"keywords\": \"data: \\\"ddd\\\";\","
        "\"context\": [\"HTTP_REQUEST_BODY\"]"
        "}"
        "}"
        "],"
        "\"IpsProtections\": ["
        "{"
        "\"context\": \"\","
        "\"ruleName\": \"rule1\","
        "\"assetName\": \"asset1\","
        "\"assetId\": \"1-1-1\","
        "\"practiceId\": \"2-2-2\","
        "\"practiceName\": \"practice1\","
        "\"defaultAction\": \"Detect\","
        "\"rules\": ["
        "{"
        "\"action\": \"Prevent\","
        "\"severityLevel\": \"Low or above\","
        "\"performanceImpact\": \"High or lower\","
        "\"confidenceLevel\": \"Low\""
        "}"
        "]"
        "}"
        "]"
        "}"
        "}";
    loadPolicy(config);
    setTrigger();

    EXPECT_CALL(table, createStateRValueRemoved(_, _));
    IPSEntry entry;
    EXPECT_CALL(table, getState(_)).WillRepeatedly(Return(&entry));
    EXPECT_CALL(table, hasState(_)).WillRepeatedly(Return(true));

    Report report;
    EXPECT_CALL(logs, sendLog(_)).WillOnce(SaveArg<0>(&report));

    HttpTransactionData new_transaction(
        "1.1",
        "POST",
        "ffff",
        IPAddr::createIPAddr("0.0.0.0").unpack(),
        80,
        "d%20d?g=%23",
        IPAddr::createIPAddr("1.1.1.1").unpack(),
        5428
    );

    EXPECT_THAT(NewHttpTransactionEvent(new_transaction).query(), ElementsAre(inspect));
    HttpHeader header_req1(Buffer("key1"), Buffer("val1"), 1);
    EXPECT_THAT(HttpRequestHeaderEvent(header_req1).query(), ElementsAre(inspect));
    HttpBody body_req(Buffer("data: ddd"), 0, true);
    EXPECT_THAT(HttpRequestBodyEvent(body_req, Buffer()).query(), ElementsAre(inspect));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(drop));

    EXPECT_THAT(report.getSyslog(), HasSubstr("httpRequestHeaders=\"key1: val1\""));

    EXPECT_CALL(table, createStateRValueRemoved(_, _));
    IPSEntry entry1;
    EXPECT_CALL(table, getState(_)).WillRepeatedly(Return(&entry1));
    Report report1;
    EXPECT_CALL(logs, sendLog(_)).WillOnce(SaveArg<0>(&report1));

    HttpTransactionData new_transaction2(
        "1.1",
        "POST",
        "ffff",
        IPAddr::createIPAddr("0.0.0.0").unpack(),
        80,
        "d%20d?g=%23",
        IPAddr::createIPAddr("1.1.1.1").unpack(),
        5428
    );

    EXPECT_THAT(NewHttpTransactionEvent(new_transaction2).query(), ElementsAre(inspect));
    HttpHeader header_req2(Buffer("key2"), Buffer("val2"), 1);
    EXPECT_THAT(HttpRequestHeaderEvent(header_req2).query(), ElementsAre(inspect));

    HttpBody body_req2(Buffer("data: ddd"), 0, true);
    EXPECT_THAT(HttpRequestBodyEvent(body_req2, Buffer()).query(), ElementsAre(inspect));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(drop));

    EXPECT_THAT(report1.getSyslog(), HasSubstr("httpRequestHeaders=\"key2: val2\""));
}

TEST_F(ComponentTest, prxeem_exception_bug)
{
    generic_rulebase.preload();
    generic_rulebase.init();
    string config =
        "{"
        "    \"IPS\": {"
        "        \"protections\": ["
        "            {"
        "                \"protectionMetadata\": {"
        "                    \"protectionName\": \"Null HTTP Encodings\","
        "                    \"maintrainId\": \"101\","
        "                    \"severity\": \"Low\","
        "                    \"confidenceLevel\": \"Low\","
        "                    \"performanceImpact\": \"Medium High\","
        "                    \"lastUpdate\": \"20210420\","
        "                    \"tags\": [],"
        "                    \"cveList\": []"
        "                },"
        "                \"detectionRules\": {"
        "                    \"type\": \"simple\","
        "                    \"SSM\": \"\","
        "                    \"keywords\": \"data: \\\"|25|00\\\"; data: \\\"?\\\";\","
        "                    \"context\": [\"HTTP_COMPLETE_URL_ENCODED\"]"
        "                }"
        "            }"
        "        ],"
        "        \"IpsProtections\": ["
        "            {"
        "                \"context\": \"\","
        "                \"ruleName\": \"rule1\","
        "                \"assetName\": \"asset1\","
        "                \"assetId\": \"1-1-1\","
        "                \"practiceId\": \"2-2-2\","
        "                \"practiceName\": \"practice1\","
        "                \"defaultAction\": \"Prevent\","
        "                \"rules\": []"
        "            }"
        "        ]"
        "    },"
        "    \"rulebase\": {"
        "        \"rulesConfig\": ["
        "            {"
        "                \"context\": \"All()\","
        "                \"priority\": 1,"
        "                \"ruleId\": \"5eaef0726765c30010bae8bb\","
        "                \"ruleName\": \"Acme web API\","
        "                \"assetId\": \"5e243effd858007660b758ad\","
        "                \"assetName\": \"Acme Power API\","
        "                \"parameters\": ["
        "                    {"
        "                       \"parameterId\": \"6c3867be-4da5-42c2-93dc-8f509a764003\","
        "                       \"parameterType\": \"exceptions\","
        "                       \"parameterName\": \"exception\""
        "                    }"
        "                ],"
        "                \"zoneId\": \"\","
        "                \"zoneName\": \"\""
        "            }"
        "        ],"
        "        \"exception\": ["
        "            {"
        "                \"context\": \"parameterId(6c3867be-4da5-42c2-93dc-8f509a764003)\","
        "                \"match\": {"
        "                   \"type\": \"operator\","
        "                   \"op\": \"and\","
        "                   \"items\": [{"
        "                       \"type\": \"condition\","
        "                       \"op\": \"equals\","
        "                       \"key\": \"url\","
        "                       \"value\": [\"(/en|/de)?/admin/helpdesk/dashboard/operator/advanced_search.*\"]"
        "                   }, {"
        "                       \"type\": \"operator\","
        "                       \"op\": \"or\","
        "                       \"items\": [{"
        "                           \"type\": \"condition\","
        "                           \"op\": \"equals\","
        "                           \"key\": \"protectionName\","
        "                           \"value\": [\"Null HTTP Encodings\"]"
        "                       }, {"
        "                           \"type\": \"condition\","
        "                           \"op\": \"equals\","
        "                           \"key\": \"parameterName\","
        "                           \"value\": [\"op\\\\.submit\\\\.reset\"]"
        "                       }]"
        "                    }]"
        "                },"
        "                \"behavior\": {"
        "                    \"key\": \"action\","
        "                    \"value\": \"accept\""
        "                }"
        "            }"
        "        ]"
        "    }"
        "}";
    loadPolicy(config);


    EXPECT_CALL(table, createStateRValueRemoved(_, _));
    IPSEntry entry;
    EXPECT_CALL(table, getState(_)).WillRepeatedly(Return(&entry));
    EXPECT_CALL(table, hasState(_)).WillRepeatedly(Return(true));

    HttpTransactionData new_transaction(
        "1.1",
        "POST",
        "ffff",
        IPAddr::createIPAddr("0.0.0.0").unpack(),
        80,
        "/admin/helpdesk/dashboard/operator/advanced_search?order=created&stuff=%00",
        IPAddr::createIPAddr("1.1.1.1").unpack(),
        5428
    );

    EXPECT_THAT(NewHttpTransactionEvent(new_transaction).query(), ElementsAre(inspect));
    HttpHeader header_req1(Buffer("key1"), Buffer("val1"), 0, true);
    EXPECT_THAT(HttpRequestHeaderEvent(header_req1).query(), ElementsAre(inspect));
}
