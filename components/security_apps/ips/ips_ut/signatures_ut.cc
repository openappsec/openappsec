#include "ips_signatures.h"
#include "ips_common_types.h"

#include <sstream>
#include <memory>
#include "cptest.h"

#include "keyword_comp.h"
#include "environment.h"
#include "agent_details.h"
#include "mock/mock_logging.h"
#include "time_proxy.h"
#include "config.h"
#include "config_component.h"
#include "i_keywords_rule.h"
#include "mock/mock_mainloop.h"
#include "generic_rulebase/generic_rulebase.h"
#include "generic_rulebase/parameters_config.h"
#include "generic_rulebase/generic_rulebase_context.h"
#include "encryptor.h"
#include "mock/mock_table.h"

using namespace testing;
using namespace std;

namespace IPSHelper
{
extern bool has_deobfuscation;
} // namespace IPSHelper

MATCHER_P(IsLog, IteratableFields, "")
{
    stringstream ss;
    {
        cereal::JSONOutputArchive ar(ss);
        ar(arg);
    }
    for (const auto &field : IteratableFields) {
        if (ss.str().find(field) == string::npos) return false;
    }

    return true;
}

class MockAgg : Singleton::Provide<I_FirstTierAgg>::SelfInterface
{
    shared_ptr<PMHook>
    getHook(const string &, const set<PMPattern> &pats) override
    {
        auto hook = make_shared<PMHook>();
        hook->prepare(pats);
        return hook;
    }
};

class SignatureTest : public Test
{
public:
    SignatureTest()
    {
        IPSHelper::has_deobfuscation = true;
        generic_rulebase.preload();
        EXPECT_CALL(logs, getCurrentLogId()).Times(AnyNumber());
        ON_CALL(table, getState(_)).WillByDefault(Return(&ips_state));
        {
            stringstream ss;
            ss << "[" << signature1 << "]";
            cereal::JSONInputArchive ar(ss);
            single_signature.load(ar);
        }
        {
            stringstream ss;
            ss << "[" << signature3 << "]";
            cereal::JSONInputArchive ar(ss);
            single_signature2.load(ar);
        }
        {
            stringstream ss;
            ss << "[" << signature1 << ", " << signature2 << ", " << signature3 << "]";
            cereal::JSONInputArchive ar(ss);
            multiple_signatures.load(ar);
        }
        {
            stringstream ss;
            ss << "[" << signature_performance_very_low << ", " << signature_performance_low << "]";
            cereal::JSONInputArchive ar(ss);
            performance_signatures1.load(ar);
        }
        {
            stringstream ss;
            ss << "["  << signature_performance_medium_low << ", " << signature_performance_medium << "]";
            cereal::JSONInputArchive ar(ss);
            performance_signatures2.load(ar);
        }
        {
            stringstream ss;
            ss << "[" << signature_performance_medium_high << ", " << signature_performance_high << "]";
            cereal::JSONInputArchive ar(ss);
            performance_signatures3.load(ar);
        }
        {
            stringstream ss;
            ss << "[" << signature_high_confidance << ", " << signature_medium_confidance << "]";
            cereal::JSONInputArchive ar(ss);
            high_medium_confidance_signatures.load(ar);
        }
    }

    ~SignatureTest()
    {
        if (gen_ctx != nullptr) {
            gen_ctx->deactivate();
            gen_ctx.reset();
        }
    }

    void
    loadExceptions()
    {
        env.preload();
        env.init();

        BasicRuleConfig::preload();
        registerExpectedConfiguration<ParameterException>("rulebase", "exception");

        string test_config(
            "{"
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
            "                   \"op\": \"or\","
            "                   \"items\": [{"
            "                       \"type\": \"condition\","
            "                       \"op\": \"equals\","
            "                       \"key\": \"protectionName\","
            "                       \"value\": [\"Test1\"]"
            "                    }, {"
            "                       \"type\": \"condition\","
            "                       \"op\": \"equals\","
            "                       \"key\": \"protectionName\","
            "                       \"value\": [\"Test2\"]"
            "                    }, {"
            "                       \"type\": \"condition\","
            "                       \"op\": \"equals\","
            "                       \"key\": \"sourceIdentifier\","
            "                       \"value\": [\"1.1.1.1\"]"
            "                    }]"
            "                 },"
            "                \"behavior\": {"
            "                    \"key\": \"action\","
            "                    \"value\": \"accept\""
            "                }"
            "            }"
            "        ]"
            "    }"
            "}"
        );

        istringstream ss(test_config);
        auto i_config = Singleton::Consume<Config::I_Config>::from(config);
        i_config->loadConfiguration(ss);

        gen_ctx = make_unique<GenericRulebaseContext>();
        gen_ctx->activate();
    }

    void
    load(const IPSSignaturesResource &policy, const string &severity, const string &confidence)
    {
        setResource(policy, "IPS", "protections");
        stringstream ss;
        ss << "{";
        ss << "\"ruleName\": \"rule1\", \"assetName\": \"asset1\", \"practiceName\": \"practice1\",";
        ss << "\"assetId\": \"1-1-1\", \"practiceId\": \"2-2-2\",";
        ss << "\"defaultAction\" : " << "\"Detect\",";
        ss << "\"rules\": [";
        ss << "{";
        ss << "\"action\": \"Prevent\",";
        ss << "\"performanceImpact\": \"High or lower\",";
        ss << "\"severityLevel\": \"" << severity << "\",";
        ss << "\"confidenceLevel\": \"" << confidence << "\"";
        ss << "}";
        ss << "]";
        ss << "}";
        cereal::JSONInputArchive ar(ss);
        sigs.load(ar);
    }

    bool
    checkData(const string &data, const string &ctx_name = "HTTP_REQUEST_BODY")
    {
        ParsedContext body(data, ctx_name, 0);
        ScopedContext ctx;
        ctx.registerValue<string>(I_KeywordsRule::getKeywordsRuleTag(), ctx_name);
        ctx.registerValue(body.getName(), body.getBuffer());
        return sigs.isMatchedPrevent(body.getName(), body.getBuffer());
    }

    template <typename ...Strings>
    void
    expectLog(const string &field, Strings ...more_fields)
    {
        vector<string> all_fields;
        all_fields.push_back(field);
        expectLog(all_fields, more_fields...);
    }

    template <typename ...Strings>
    void
    expectLog(vector<string> all_fields, const string &field, Strings ...more_fields)
    {
        all_fields.push_back(field);
        expectLog(all_fields, more_fields...);
    }


    void
    expectLog(vector<string> all_fields)
    {
        EXPECT_CALL(logs, sendLog(IsLog(all_fields)));
    }

    IPSSignatures sigs;
    IPSSignaturesResource single_signature;
    IPSSignaturesResource single_signature2;
    IPSSignaturesResource multiple_signatures;
    IPSSignaturesResource high_medium_confidance_signatures;
    IPSSignaturesResource performance_signatures1;
    IPSSignaturesResource performance_signatures2;
    IPSSignaturesResource performance_signatures3;
    NiceMock<MockTable> table;
    MockAgg mock_agg;

private:
    GenericRulebase generic_rulebase;
    unique_ptr<GenericRulebaseContext> gen_ctx;
    NiceMock<MockMainLoop> mock_mainloop;
    KeywordComp keywords;
    TimeProxyComponent time;
    ::Environment env;
    ConfigComponent config;
    Encryptor encryptor;
    AgentDetails details;
    StrictMock<MockLogging> logs;
    IPSEntry ips_state;

    string signature1 =
        "{"
            "\"protectionMetadata\": {"
                "\"protectionName\": \"Test1\","
                "\"maintrainId\": \"101\","
                "\"severity\": \"Medium High\","
                "\"confidenceLevel\": \"Low\","
                "\"performanceImpact\": \"Medium High\","
                "\"lastUpdate\": \"20210420\","
                "\"tags\": [\"Protection_Type_Scanning_Tool\"],"
                "\"cveList\": []"
            "},"
            "\"detectionRules\": {"
                "\"type\": \"simple\","
                "\"SSM\": \"\","
                "\"keywords\": \"data: \\\"fff\\\";\","
                "\"context\": [\"HTTP_REQUEST_BODY\", \"HTTP_RESPONSE_BODY\"]"
            "}"
        "}";
    string signature2 =
        "{"
            "\"protectionMetadata\": {"
                "\"protectionName\": \"Test2\","
                "\"maintrainId\": \"102\","
                "\"severity\": \"Low\","
                "\"confidenceLevel\": \"Low\","
                "\"performanceImpact\": \"Low\","
                "\"lastUpdate\": \"20210420\","
                "\"tags\": [\"Vul_Type_SQL_Injection\"],"
                "\"cveList\": []"
            "},"
            "\"detectionRules\": {"
                "\"type\": \"simple\","
                "\"SSM\": \"ddd\","
                "\"keywords\": \"data: \\\"ddd\\\";\","
                "\"context\": [\"HTTP_REQUEST_BODY\"]"
            "}"
        "}";
    string signature3 =
        "{"
            "\"protectionMetadata\": {"
                "\"protectionName\": \"Test3\","
                "\"maintrainId\": \"102\","
                "\"severity\": \"High\","
                "\"confidenceLevel\": \"Low\","
                "\"performanceImpact\": \"Low\","
                "\"lastUpdate\": \"20210420\","
                "\"tags\": [\"Protection_Type_Scanning_Tool\", \"Vul_Type_SQL_Injection\"],"
                "\"cveList\": []"
            "},"
            "\"detectionRules\": {"
                "\"type\": \"simple\","
                "\"SSM\": \"ggg\","
                "\"keywords\": \"\","
                "\"context\": [\"HTTP_REQUEST_BODY\"]"
            "}"
        "}";

    string signature_high_confidance =
        "{"
            "\"protectionMetadata\": {"
                "\"protectionName\": \"Test3\","
                "\"maintrainId\": \"103\","
                "\"severity\": \"Low\","
                "\"confidenceLevel\": \"High\","
                "\"performanceImpact\": \"Low\","
                "\"lastUpdate\": \"20210420\","
                "\"tags\": [],"
                "\"cveList\": []"
            "},"
            "\"detectionRules\": {"
                "\"type\": \"simple\","
                "\"SSM\": \"\","
                "\"keywords\": \"data: \\\"hhh\\\";\","
                "\"context\": [\"HTTP_REQUEST_BODY\"]"
            "}"
        "}";

    string signature_medium_confidance =
        "{"
            "\"protectionMetadata\": {"
                "\"protectionName\": \"Test4\","
                "\"maintrainId\": \"104\","
                "\"severity\": \"Low\","
                "\"confidenceLevel\": \"Medium\","
                "\"performanceImpact\": \"Low\","
                "\"lastUpdate\": \"20210420\","
                "\"tags\": [],"
                "\"cveList\": []"
        "},"
            "\"detectionRules\": {"
                "\"type\": \"simple\","
                "\"SSM\": \"mmm\","
                "\"keywords\": \"data: \\\"mmm\\\";\","
                "\"context\": [\"HTTP_REQUEST_BODY\"]"
            "}"
        "}";

    string signature_performance_very_low =
        "{"
            "\"protectionMetadata\": {"
                "\"protectionName\": \"Test1\","
                "\"maintrainId\": \"101\","
                "\"severity\": \"Medium High\","
                "\"confidenceLevel\": \"Low\","
                "\"performanceImpact\": \"Very Low\","
                "\"lastUpdate\": \"20210420\","
                "\"tags\": [],"
                "\"cveList\": []"
            "},"
            "\"detectionRules\": {"
                "\"type\": \"simple\","
                "\"SSM\": \"\","
                "\"keywords\": \"data: \\\"aaa\\\";\","
                "\"context\": [\"HTTP_REQUEST_BODY\", \"HTTP_RESPONSE_BODY\"]"
            "}"
        "}";

    string signature_performance_low =
        "{"
            "\"protectionMetadata\": {"
                "\"protectionName\": \"Test1\","
                "\"maintrainId\": \"101\","
                "\"severity\": \"Medium High\","
                "\"confidenceLevel\": \"Low\","
                "\"performanceImpact\": \"Low\","
                "\"lastUpdate\": \"20210420\","
                "\"tags\": [],"
                "\"cveList\": []"
            "},"
            "\"detectionRules\": {"
                "\"type\": \"simple\","
                "\"SSM\": \"\","
                "\"keywords\": \"data: \\\"bbb\\\";\","
                "\"context\": [\"HTTP_REQUEST_BODY\", \"HTTP_RESPONSE_BODY\"]"
            "}"
        "}";

    string signature_performance_medium_low =
        "{"
            "\"protectionMetadata\": {"
                "\"protectionName\": \"Test1\","
                "\"maintrainId\": \"101\","
                "\"severity\": \"Medium High\","
                "\"confidenceLevel\": \"Low\","
                "\"performanceImpact\": \"Medium Low\","
                "\"lastUpdate\": \"20210420\","
                "\"tags\": [],"
                "\"cveList\": []"
            "},"
            "\"detectionRules\": {"
                "\"type\": \"simple\","
                "\"SSM\": \"\","
                "\"keywords\": \"data: \\\"ccc\\\";\","
                "\"context\": [\"HTTP_REQUEST_BODY\", \"HTTP_RESPONSE_BODY\"]"
            "}"
        "}";

    string signature_performance_medium =
        "{"
            "\"protectionMetadata\": {"
                "\"protectionName\": \"Test1\","
                "\"maintrainId\": \"101\","
                "\"severity\": \"Medium High\","
                "\"confidenceLevel\": \"Low\","
                "\"performanceImpact\": \"Medium\","
                "\"lastUpdate\": \"20210420\","
                "\"tags\": [],"
                "\"cveList\": []"
            "},"
            "\"detectionRules\": {"
                "\"type\": \"simple\","
                "\"SSM\": \"\","
                "\"keywords\": \"data: \\\"ddd\\\";\","
                "\"context\": [\"HTTP_REQUEST_BODY\", \"HTTP_RESPONSE_BODY\"]"
            "}"
        "}";

    string signature_performance_medium_high =
        "{"
            "\"protectionMetadata\": {"
                "\"protectionName\": \"Test1\","
                "\"maintrainId\": \"101\","
                "\"severity\": \"Medium High\","
                "\"confidenceLevel\": \"Low\","
                "\"performanceImpact\": \"Medium High\","
                "\"lastUpdate\": \"20210420\","
                "\"tags\": [],"
                "\"cveList\": []"
            "},"
            "\"detectionRules\": {"
                "\"type\": \"simple\","
                "\"SSM\": \"\","
                "\"keywords\": \"data: \\\"eee\\\";\","
                "\"context\": [\"HTTP_REQUEST_BODY\", \"HTTP_RESPONSE_BODY\"]"
            "}"
        "}";

    string signature_performance_high =
        "{"
            "\"protectionMetadata\": {"
                "\"protectionName\": \"Test1\","
                "\"maintrainId\": \"101\","
                "\"severity\": \"Medium High\","
                "\"confidenceLevel\": \"Low\","
                "\"performanceImpact\": \"High\","
                "\"lastUpdate\": \"20210420\","
                "\"tags\": [],"
                "\"cveList\": []"
            "},"
            "\"detectionRules\": {"
                "\"type\": \"simple\","
                "\"SSM\": \"\","
                "\"keywords\": \"data: \\\"fff\\\";\","
                "\"context\": [\"HTTP_REQUEST_BODY\", \"HTTP_RESPONSE_BODY\"]"
            "}"
        "}";
};

TEST_F(SignatureTest, basic_load_of_signatures)
{
    EXPECT_TRUE(sigs.isEmpty());
    load(single_signature, "Low or above", "Low");
    EXPECT_FALSE(sigs.isEmpty());
    EXPECT_TRUE(sigs.isEmpty("NO_CONTEXT"));
    EXPECT_FALSE(sigs.isEmpty("HTTP_REQUEST_BODY"));
}

TEST_F(SignatureTest, single_signature_matching_override)
{
    load(single_signature, "Low or above", "Low");

    expectLog("\"protectionId\": \"Test1\"", "\"eventSeverity\": \"High\"");

    EXPECT_TRUE(checkData("fffddd"));

    loadExceptions();

    expectLog("\"protectionId\": \"Test1\"", "\"eventSeverity\": \"Info\"");

    EXPECT_FALSE(checkData("fffddd"));
}

TEST_F(SignatureTest, source_idetifier_exception)
{
    load(single_signature2, "Low or above", "Low");

    loadExceptions();

    expectLog("\"protectionId\": \"Test3\"", "\"eventSeverity\": \"Critical\"");

    EXPECT_TRUE(checkData("gggddd"));

    ScopedContext ctx;
    ctx.registerValue<string>("sourceIdentifiers", "1.1.1.1");

    expectLog("\"protectionId\": \"Test3\"", "\"eventSeverity\": \"Info\"");

    EXPECT_FALSE(checkData("gggddd"));
}

TEST_F(SignatureTest, single_signature_matching)
{
    load(single_signature, "Low or above", "Low");

    EXPECT_FALSE(checkData("ggg"));

    EXPECT_FALSE(checkData("ddd"));

    expectLog("\"protectionId\": \"Test1\"", "\"eventSeverity\": \"High\"");

    EXPECT_TRUE(checkData("fffddd"));
}

TEST_F(SignatureTest, context_signature_matching)
{
    load(single_signature, "Low or above", "Low");

    expectLog("\"protectionId\": \"Test1\"", "\"eventSeverity\": \"High\"");
    EXPECT_TRUE(checkData("fff", "HTTP_REQUEST_BODY"));

    expectLog("\"protectionId\": \"Test1\"", "\"eventSeverity\": \"High\"");
    EXPECT_TRUE(checkData("fff", "HTTP_RESPONSE_BODY"));

    EXPECT_FALSE(checkData("fff", "HTTP_COMPLETE_URL_DECODED"));
}

TEST_F(SignatureTest, id_to_log_test)
{
    load(single_signature, "Low or above", "Low");

    expectLog("\"protectionId\": \"Test1\"");

    EXPECT_TRUE(checkData("fffddd"));
}

TEST_F(SignatureTest, multiple_signatures_matching)
{
    load(multiple_signatures, "Low or above", "Low");
    EXPECT_FALSE(checkData("hhh"));

    expectLog("\"protectionId\": \"Test2\"", "\"eventSeverity\": \"High\"");
    EXPECT_TRUE(checkData("ddd"));

    expectLog("\"protectionId\": \"Test1\"", "\"eventSeverity\": \"High\"");
    EXPECT_TRUE(checkData("fff"));

    expectLog("\"protectionId\": \"Test3\"", "\"eventSeverity\": \"Critical\"");
    EXPECT_TRUE(checkData("ggg"));

    // Only one signature is caught
    expectLog("\"protectionId\": \"Test2\"", "\"eventSeverity\": \"High\"");
    EXPECT_TRUE(checkData("fffdddggg"));
}

TEST_F(SignatureTest, severity_to_log_test)
{
    load(multiple_signatures, "Low or above", "Low");

    expectLog("\"matchedSignatureSeverity\": \"Medium High\"");
    EXPECT_TRUE(checkData("fff"));

    expectLog("\"matchedSignatureSeverity\": \"Low\"");
    EXPECT_TRUE(checkData("ddd"));

    expectLog("\"matchedSignatureSeverity\": \"High\"");
    EXPECT_TRUE(checkData("ggg"));
}

TEST_F(SignatureTest, incident_type)
{
    load(multiple_signatures, "Low or above", "Low");

    expectLog("\"waapIncidentType\": \"Scanning Tool\"");
    EXPECT_TRUE(checkData("fff"));

    expectLog("\"waapIncidentType\": \"SQL Injection\"");
    EXPECT_TRUE(checkData("ddd"));

    expectLog("\"waapIncidentType\": \"SQL Injection\"");
    EXPECT_TRUE(checkData("ggg"));
}

TEST_F(SignatureTest, performance_to_log_very_low)
{
    load(performance_signatures1, "Low or above", "Low");

    EXPECT_FALSE(checkData("ggg"));

    expectLog("\"matchedSignaturePerformance\": \"Very Low\"");

    EXPECT_TRUE(checkData("aaa"));

    expectLog("\"matchedSignaturePerformance\": \"Low\"");

    EXPECT_TRUE(checkData("bbb"));
}

TEST_F(SignatureTest, performance_to_log_medium_low)
{
    load(performance_signatures2, "Low or above", "Low");

    EXPECT_FALSE(checkData("ggg"));

    expectLog("\"matchedSignaturePerformance\": \"Medium Low\"");

    EXPECT_TRUE(checkData("ccc"));

    expectLog("\"matchedSignaturePerformance\": \"Medium\"");

    EXPECT_TRUE(checkData("ddd"));
}

TEST_F(SignatureTest, performance_to_log_medium_high)
{
    load(performance_signatures3, "Low or above", "Low");

    EXPECT_FALSE(checkData("ggg"));

    expectLog("\"matchedSignaturePerformance\": \"Medium High\"");

    EXPECT_TRUE(checkData("eee"));

    expectLog("\"matchedSignaturePerformance\": \"High\"");

    EXPECT_TRUE(checkData("fff"));
}

TEST_F(SignatureTest, high_confidance_signatures_matching)
{
    load(high_medium_confidance_signatures, "Low or above", "High");
    EXPECT_FALSE(checkData("ggg"));

    expectLog("\"protectionId\": \"Test3\"", "\"matchedSignatureConfidence\": \"High\"");
    EXPECT_TRUE(checkData("hhh"));

    expectLog("\"protectionId\": \"Test4\"", "\"matchedSignatureConfidence\": \"Medium\"");
    EXPECT_FALSE(checkData("mmm"));
}
