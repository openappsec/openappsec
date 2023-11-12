#include "layer_7_access_control.h"

#include "cptest.h"
#include "config_component.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_time_get.h"
#include "mock/mock_http_manager.h"
#include "mock/mock_logging.h"
#include "mock/mock_messaging.h"
#include "mock/mock_rest_api.h"
#include "intelligence_comp_v2.h"
#include "agent_details.h"

using namespace std;
using namespace testing;

USE_DEBUG_FLAG(D_L7_ACCESS_CONTROL);

class Layer7AccessControlTest : public Test
{
public:
    Layer7AccessControlTest()
    {
        Debug::setUnitTestFlag(D_L7_ACCESS_CONTROL, Debug::DebugLevel::TRACE);
        EXPECT_CALL(mock_logging, getCurrentLogId()).Times(AnyNumber());
        EXPECT_CALL(mock_time, getWalltimeStr(_)).WillRepeatedly(Return(string("2016-11-13T17:31:24.087")));
        EXPECT_CALL(mock_time, getWalltime()).WillRepeatedly(Return(chrono::seconds(0)));
        EXPECT_CALL(mock_time, getMonotonicTime()).WillRepeatedly(Return(chrono::seconds(60)));
        EXPECT_CALL(mock_ml, doesRoutineExist(_)).WillRepeatedly(Return(true));
        EXPECT_CALL(mock_ml, stop(_)).WillRepeatedly(Return());
        EXPECT_CALL(mock_ml, addRecurringRoutine(_, _, _, "Sending intelligence invalidation", _));
        env.preload();
        env.init();
        config.preload();
        intelligence_comp.preload();
        intelligence_comp.init();
        l7_access_control.preload();
        l7_access_control.init();
        ctx.activate();
    }
    
    ~Layer7AccessControlTest()
    {
        ctx.deactivate();
        l7_access_control.fini();
    }

    string loadIntelligenceResponse(const string &file_path);
    void registerTransactionData();
    void verifyReport(const Report &report, const string &source_identifier, const string &security_action);

    const EventVerdict drop_verdict = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_DROP;
    const EventVerdict accept_verdict = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_ACCEPT;
    const EventVerdict inspect_verdict = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INSPECT;
    const EventVerdict wait_verdict = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_WAIT;
    Layer7AccessControl         l7_access_control;
    ::Environment               env;
    ConfigComponent             config;
    StrictMock<MockLogging>     mock_logging;
    StrictMock<MockTimeGet>     mock_time;
    StrictMock<MockMainLoop>    mock_ml;
    StrictMock<MockMessaging>   messaging_mock;
    NiceMock<MockRestApi>       mock_rest;
    AgentDetails                agent_details;
    IntelligenceComponentV2     intelligence_comp;
    I_MainLoop::Routine         query_intelligence_routine;
    Context ctx;
};

string prevent_settings =
"{\n"
    "\"agentSettings\": [\n"
        "{\n"
            "\"id\": \"aac36348-5826-17d4-de11-195dd4dfca4a\","
            "\"key\": \"agent.config.useLocalIntelligence\","
            "\"value\": \"true\""
        "},"
        "{"
            "\"id\": \"f6c386fb-e221-59af-dbf5-b9bed680ec6b\","
            "\"key\": \"layer7AccessControl.logOnDrop\","
            "\"value\": \"true\""
        "},"
        "{"
            "\"id\": \"5ac38ee8-8b3c-481b-b382-f1f0735c0468\","
            "\"key\": \"layer7AccessControl.securityMode\","
            "\"value\": \"prevent\""
        "},"
        "{"
            "\"id\": \"54c38f89-8fe2-871e-b29a-31e088f1b1d3\","
            "\"key\": \"layer7AccessControl.crowdsec.enabled\","
            "\"value\": \"true\""
        "}"
    "],\n";

string detect_settings =
"{\n"
    "\"agentSettings\": [\n"
        "{\n"
            "\"id\": \"aac36348-5826-17d4-de11-195dd4dfca4a\","
            "\"key\": \"agent.config.useLocalIntelligence\","
            "\"value\": \"true\""
        "},"
        "{"
            "\"id\": \"f6c386fb-e221-59af-dbf5-b9bed680ec6b\","
            "\"key\": \"layer7AccessControl.logOnDrop\","
            "\"value\": \"true\""
        "},"
        "{"
            "\"id\": \"5ac38ee8-8b3c-481b-b382-f1f0735c0468\","
            "\"key\": \"layer7AccessControl.securityMode\","
            "\"value\": \"detect\""
        "},"
        "{"
        "\"id\": \"54c38f89-8fe2-871e-b29a-31e088f1b1d3\","
        "\"key\": \"layer7AccessControl.crowdsec.enabled\","
        "\"value\": \"true\""
        "}"
    "],\n";

string disabled_settings =
"{"
    "\"agentSettings\": [\n"
        "{\n"
            "\"id\": \"aac36348-5826-17d4-de11-195dd4dfca4a\","
            "\"key\": \"agent.config.useLocalIntelligence\","
            "\"value\": \"true\""
        "},"
        "{"
            "\"id\": \"f6c386fb-e221-59af-dbf5-b9bed680ec6b\","
            "\"key\": \"layer7AccessControl.logOnDrop\","
            "\"value\": \"true\""
        "},"
        "{"
            "\"id\": \"5ac38ee8-8b3c-481b-b382-f1f0735c0468\","
            "\"key\": \"layer7AccessControl.securityMode\","
            "\"value\": \"detect\""
        "},"
        "{"
            "\"id\": \"54c38f89-8fe2-871e-b29a-31e088f1b1d3\","
            "\"key\": \"layer7AccessControl.crowdsec.enabled\","
            "\"value\": \"false\""
        "}"
    "],\n";

string policy =
    "\"rulebase\": {"
        "\"usersIdentifiers\": ["
            "{"
                "\"context\": \"Any(All(Any(EqualHost(juice-shop.checkpoint.com)),EqualListeningPort(80)))\","
                "\"identifierValues\": [],"
                "\"sourceIdentifier\": \"\","
                "\"sourceIdentifiers\": ["
                    "{"
                        "\"identifierValues\": [],"
                        "\"sourceIdentifier\": \"x-forwarded-for\""
                    "}"
                "]"
            "}"
        "],\n"
        "\"rulesConfig\": ["
            "{"
                "\"assetId\": \"00c37544-047b-91d4-e5e5-31d90070bcfd\","
                "\"assetName\": \"juice\","
                "\"context\": \"Any(All(Any(EqualHost(juice-shop.checkpoint.com)),EqualListeningPort(80)))\","
                "\"isCleanup\": false,"
                "\"parameters\": [],"
                "\"practices\": ["
                    "{"
                        "\"practiceId\": \"36be58f5-2c99-1f16-f816-bf25118d9bc1\","
                        "\"practiceName\": \"WEB APPLICATION BEST PRACTICE\","
                        "\"practiceType\": \"WebApplication\""
                    "}"
                "],"
                "\"priority\": 1,"
                "\"ruleId\": \"00c37544-047b-91d4-e5e5-31d90070bcfd\","
                "\"ruleName\": \"juice\","
                "\"triggers\": ["
                    "{"
                        "\"triggerId\": \"86be58f5-2b65-18ee-2bd7-b4429dab245d\","
                        "\"triggerName\": \"Log Trigger\","
                        "\"triggerType\": \"log\""
                    "}"
                "],"
                "\"zoneId\": \"\","
                "\"zoneName\": \"\""
            "}"
        "]"
    "}\n"
"}\n";

void
Layer7AccessControlTest::registerTransactionData()
{
    ctx.registerValue<IPAddr>(HttpTransactionData::client_ip_ctx, IPAddr::createIPAddr("4.4.4.4").unpack());
    ctx.registerValue<IPAddr>(HttpTransactionData::listening_ip_ctx, IPAddr::createIPAddr("5.6.7.8").unpack());
    ctx.registerValue<string>(HttpTransactionData::http_proto_ctx, "http");
    ctx.registerValue<string>(HttpTransactionData::method_ctx, "POST");
    ctx.registerValue<string>(HttpTransactionData::host_name_ctx, "juice-shop.checkpoint.com");
    ctx.registerValue<uint16_t>(HttpTransactionData::listening_port_ctx, 80);
    ctx.registerValue<uint16_t>(HttpTransactionData::client_port_ctx, 12345);
    ctx.registerValue<string>(HttpTransactionData::uri_ctx, "/");
}

static bool
operator==(const EventVerdict &first, const EventVerdict &second)
{
    return first.getVerdict() == second.getVerdict();
}

string
Layer7AccessControlTest::loadIntelligenceResponse(const string &file_path)
{
    stringstream ss;
    ifstream f(cptestFnameInExeDir(file_path), ios::in);
    dbgTrace(D_L7_ACCESS_CONTROL) << "Loading intelligence response from: " << file_path;
    ss << f.rdbuf();
    f.close();
    return ss.str();
}

template <typename T>
string
reportToStr(const T &obj)
{
    stringstream ss;
    {
        cereal::JSONOutputArchive ar(ss);
        obj.serialize(ar);
    }
    return ss.str();
}

void
Layer7AccessControlTest::verifyReport(
    const Report &report,
    const string &source_identifier,
    const string &security_action
)
{
    string log = reportToStr(report);
    dbgTrace(D_L7_ACCESS_CONTROL) << "Report: " << log;

    if (!source_identifier.empty()) EXPECT_THAT(log, HasSubstr("\"httpSourceId\": \"" + source_identifier + "\""));
    EXPECT_THAT(log, HasSubstr("\"securityAction\": \"" + security_action + "\""));
    EXPECT_THAT(log, HasSubstr("\"eventName\": \"Access Control External Vendor Reputation\""));
    EXPECT_THAT(log, HasSubstr("\"httpHostName\": \"juice-shop.checkpoint.com\""));
    EXPECT_THAT(log, HasSubstr("\"httpUriPath\": \"/\""));
    EXPECT_THAT(log, HasSubstr("\"httpMethod\": \"POST\""));
    EXPECT_THAT(log, HasSubstr("\"ipProtocol\": \"http\""));
    EXPECT_THAT(log, HasSubstr("\"destinationIP\": \"5.6.7.8\""));
    EXPECT_THAT(log, HasSubstr("\"externalVendorName\": \"CrowdSec\""));
    EXPECT_THAT(log, HasSubstr("\"waapIncidentType\": \"CrowdSec\""));
    EXPECT_THAT(log, HasSubstr("\"externalVendorRecommendationId\": \"2253734\""));
    EXPECT_THAT(log, HasSubstr("\"externalVendorRecommendedAction\": \"ban\""));
    EXPECT_THAT(log, HasSubstr("\"externalVendorRecommendationOrigin\": \"cscli\""));
    EXPECT_THAT(log, HasSubstr("\"externalVendorRecommendedAffectedScope\": \"1.2.3.4\""));
    EXPECT_THAT(log, HasSubstr("\"externalVendorRecommendationOriginDetails\": \"manual 'ban' from 'localhost'\""));
}

TEST_F(Layer7AccessControlTest, ReturnAcceptVerdict)
{
    stringstream ss_conf(prevent_settings + policy);
    Singleton::Consume<Config::I_Config>::from(config)->loadConfiguration(ss_conf);
    
    string intelligence_response_ok = loadIntelligenceResponse("data/ok_intelligence_response.json");

    EXPECT_CALL(
        messaging_mock,
        sendMessage(true, _, _, _, _, _, _, MessageTypeTag::INTELLIGENCE)
    ).WillOnce(Return(intelligence_response_ok));

    registerTransactionData();
    ctx.registerValue<string>(HttpTransactionData::source_identifier, "1.2.3.4");
    const HttpHeader header1{ Buffer("Content-Type"), Buffer("application/json"), 0 };
    const HttpHeader header2{ Buffer("date"), Buffer("Sun, 26 Mar 2023 18:45:22 GMT"), 1 };
    const HttpHeader header3{ Buffer("x-forwarded-for"), Buffer("1.2.3.4"), 2, true};

    EXPECT_CALL(
        mock_ml,
        addOneTimeRoutine(_, _, "Check IP reputation", _))
            .WillOnce(DoAll(SaveArg<1>(&query_intelligence_routine), Return(0))
    );
    EXPECT_CALL(mock_ml, yield(A<bool>())).Times(1);

    EXPECT_THAT(
        HttpRequestHeaderEvent(header1).performNamedQuery(),
        ElementsAre(Pair("Layer-7 Access Control app", inspect_verdict))
    );
    EXPECT_THAT(
        HttpRequestHeaderEvent(header2).performNamedQuery(),
        ElementsAre(Pair("Layer-7 Access Control app", inspect_verdict))
    );
    EXPECT_THAT(
        HttpRequestHeaderEvent(header3).performNamedQuery(),
        ElementsAre(Pair("Layer-7 Access Control app", wait_verdict))
    );

    query_intelligence_routine();

    EXPECT_THAT(
        WaitTransactionEvent().performNamedQuery(),
        ElementsAre(Pair("Layer-7 Access Control app", accept_verdict))
    );
}

TEST_F(Layer7AccessControlTest, ReturnDropVerdictOnMaliciousReputation)
{
    stringstream ss_conf(prevent_settings + policy);
    Singleton::Consume<Config::I_Config>::from(config)->loadConfiguration(ss_conf);
    
    string malicious_intelligence_response = loadIntelligenceResponse("data/malicious_intelligence_response.json");

    EXPECT_CALL(
        messaging_mock,
        sendMessage(true, _, _, _, _, _, _, MessageTypeTag::INTELLIGENCE)
    ).WillOnce(Return(malicious_intelligence_response));

    EXPECT_CALL(
        mock_ml,
        addOneTimeRoutine(_, _, "Check IP reputation", _))
        .WillOnce(DoAll(SaveArg<1>(&query_intelligence_routine), Return(0))
    );
    EXPECT_CALL(mock_ml, yield(A<bool>())).Times(1);

    registerTransactionData();
    ctx.registerValue<string>(HttpTransactionData::source_identifier, "1.2.3.4");
    const HttpHeader header1{ Buffer("Content-Type"), Buffer("application/json"), 0 };
    const HttpHeader header2{ Buffer("date"), Buffer("Sun, 26 Mar 2023 18:45:22 GMT"), 1 };
    const HttpHeader header3{ Buffer("x-forwarded-for"), Buffer("1.2.3.4"), 2, true};

    Report report;
    EXPECT_CALL(mock_logging, sendLog(_)).WillOnce(SaveArg<0>(&report));

    EXPECT_THAT(HttpRequestHeaderEvent(header1).query(), ElementsAre(inspect_verdict));
    EXPECT_THAT(HttpRequestHeaderEvent(header2).query(), ElementsAre(inspect_verdict));

    EXPECT_THAT(
        HttpRequestHeaderEvent(header3).performNamedQuery(),
        ElementsAre(Pair("Layer-7 Access Control app", wait_verdict))
    );

    query_intelligence_routine();

    EXPECT_THAT(
        WaitTransactionEvent().performNamedQuery(),
        ElementsAre(Pair("Layer-7 Access Control app", drop_verdict))
    );

    verifyReport(report, "1.2.3.4", "Prevent");
}

TEST_F(Layer7AccessControlTest, ReturnDropVerdictCacheBased)
{
    stringstream ss_conf(prevent_settings + policy);
    Singleton::Consume<Config::I_Config>::from(config)->loadConfiguration(ss_conf);

    string malicious_intelligence_response = loadIntelligenceResponse("data/malicious_intelligence_response.json");

    EXPECT_CALL(
        messaging_mock,
        sendMessage(true, _, _, _, _, _, _, MessageTypeTag::INTELLIGENCE)
    ).WillOnce(Return(malicious_intelligence_response));

    EXPECT_CALL(
        mock_ml,
        addOneTimeRoutine(_, _, "Check IP reputation", _))
        .WillOnce(DoAll(SaveArg<1>(&query_intelligence_routine), Return(0))
    );
    EXPECT_CALL(mock_ml, yield(A<bool>())).Times(1);

    registerTransactionData();
    ctx.registerValue<string>(HttpTransactionData::source_identifier, "1.2.3.4");
    const HttpHeader header1{ Buffer("Content-Type"), Buffer("application/json"), 0 };
    const HttpHeader header2{ Buffer("date"), Buffer("Sun, 26 Mar 2023 18:45:22 GMT"), 1 };
    const HttpHeader header3{ Buffer("x-forwarded-for"), Buffer("1.2.3.4"), 2, true};

    Report report;
    EXPECT_CALL(mock_logging, sendLog(_)).Times(2).WillRepeatedly(SaveArg<0>(&report));

    EXPECT_THAT(HttpRequestHeaderEvent(header1).query(), ElementsAre(inspect_verdict));
    EXPECT_THAT(HttpRequestHeaderEvent(header2).query(), ElementsAre(inspect_verdict));

    EXPECT_THAT(
        HttpRequestHeaderEvent(header3).performNamedQuery(),
        ElementsAre(Pair("Layer-7 Access Control app", wait_verdict))
    );

    query_intelligence_routine();

    EXPECT_THAT(
        WaitTransactionEvent().performNamedQuery(),
        ElementsAre(Pair("Layer-7 Access Control app", drop_verdict))
    );

    verifyReport(report, "1.2.3.4", "Prevent");
    
    EXPECT_THAT(HttpRequestHeaderEvent(header1).query(), ElementsAre(inspect_verdict));
    EXPECT_THAT(HttpRequestHeaderEvent(header2).query(), ElementsAre(inspect_verdict));
    EXPECT_THAT(HttpRequestHeaderEvent(header3).query(), ElementsAre(drop_verdict));

    verifyReport(report, "1.2.3.4", "Prevent");
}

TEST_F(Layer7AccessControlTest, AcceptOnDetect)
{
    stringstream ss_conf(detect_settings + policy);
    Singleton::Consume<Config::I_Config>::from(config)->loadConfiguration(ss_conf);
    
    string malicious_intelligence_response = loadIntelligenceResponse("data/malicious_intelligence_response.json");

    EXPECT_CALL(
        messaging_mock,
        sendMessage(true, _, _, _, _, _, _, MessageTypeTag::INTELLIGENCE)
    ).WillOnce(Return(malicious_intelligence_response));

    EXPECT_CALL(
        mock_ml,
        addOneTimeRoutine(_, _, "Check IP reputation", _))
        .WillOnce(DoAll(SaveArg<1>(&query_intelligence_routine), Return(0))
    );
    EXPECT_CALL(mock_ml, yield(A<bool>())).Times(1);

    registerTransactionData();
    ctx.registerValue<string>(HttpTransactionData::source_identifier, "1.2.3.4");
    const HttpHeader header1{ Buffer("Content-Type"), Buffer("application/json"), 0 };
    const HttpHeader header2{ Buffer("date"), Buffer("Sun, 26 Mar 2023 18:45:22 GMT"), 1 };
    const HttpHeader header3{ Buffer("x-forwarded-for"), Buffer("1.2.3.4"), 2, true};

    Report report;
    EXPECT_CALL(mock_logging, sendLog(_)).WillOnce(SaveArg<0>(&report));

    EXPECT_THAT(HttpRequestHeaderEvent(header1).query(), ElementsAre(inspect_verdict));
    EXPECT_THAT(HttpRequestHeaderEvent(header2).query(), ElementsAre(inspect_verdict));

    EXPECT_THAT(
        HttpRequestHeaderEvent(header3).performNamedQuery(),
        ElementsAre(Pair("Layer-7 Access Control app", wait_verdict))
    );

    query_intelligence_routine();

    EXPECT_THAT(
        WaitTransactionEvent().performNamedQuery(),
        ElementsAre(Pair("Layer-7 Access Control app", accept_verdict))
    );

    verifyReport(report, "1.2.3.4", "Detect");
}

TEST_F(Layer7AccessControlTest, FallbackToSourceIPAndDrop)
{
    stringstream ss_conf(prevent_settings + policy);
    Singleton::Consume<Config::I_Config>::from(config)->loadConfiguration(ss_conf);

    string malicious_intelligence_response = loadIntelligenceResponse("data/malicious_intelligence_response.json");

    EXPECT_CALL(
        messaging_mock,
        sendMessage(true, _, _, _, _, _, _, MessageTypeTag::INTELLIGENCE)
    ).WillOnce(Return(malicious_intelligence_response));

    EXPECT_CALL(
        mock_ml,
        addOneTimeRoutine(_, _, "Check IP reputation", _))
        .WillOnce(DoAll(SaveArg<1>(&query_intelligence_routine), Return(0))
    );
    EXPECT_CALL(mock_ml, yield(A<bool>())).Times(1);

    registerTransactionData();
    const HttpHeader header1{ Buffer("Content-Type"), Buffer("application/json"), 0 };
    const HttpHeader header2{ Buffer("date"), Buffer("Sun, 26 Mar 2023 18:45:22 GMT"), 1, true };

    Report report;
    EXPECT_CALL(mock_logging, sendLog(_)).WillOnce(SaveArg<0>(&report));

    EXPECT_THAT(HttpRequestHeaderEvent(header1).query(), ElementsAre(inspect_verdict));

    EXPECT_THAT(
        HttpRequestHeaderEvent(header2).performNamedQuery(),
        ElementsAre(Pair("Layer-7 Access Control app", wait_verdict))
    );

    query_intelligence_routine();

    EXPECT_THAT(
        WaitTransactionEvent().performNamedQuery(),
        ElementsAre(Pair("Layer-7 Access Control app", drop_verdict))
    );

    verifyReport(report, "", "Prevent");
}

TEST_F(Layer7AccessControlTest, AcceptOnDisabled)
{
    stringstream ss_conf(disabled_settings + policy);
    Singleton::Consume<Config::I_Config>::from(config)->loadConfiguration(ss_conf);

    registerTransactionData();
    ctx.registerValue<string>(HttpTransactionData::source_identifier, "1.2.3.4");
    const HttpHeader header1{ Buffer("Content-Type"), Buffer("application/json"), 0 };
    const HttpHeader header2{ Buffer("date"), Buffer("Sun, 26 Mar 2023 18:45:22 GMT"), 1 };
    const HttpHeader header3{ Buffer("x-forwarded-for"), Buffer("1.2.3.4"), 2, true};

    EXPECT_THAT(HttpRequestHeaderEvent(header1).query(), ElementsAre(accept_verdict));
}
