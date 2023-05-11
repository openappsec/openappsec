#include "ips_entry.h"

#include <sstream>

#include "ips_signatures.h"
#include "cptest.h"
#include "keyword_comp.h"
#include "config.h"
#include "config_component.h"
#include "environment.h"
#include "agent_details.h"
#include "mock/mock_logging.h"
#include "mock/mock_time_get.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_table.h"
#include "generic_rulebase/generic_rulebase.h"

using namespace std;
using namespace testing;

ostream &
operator<<(ostream &os, const ParsedContextReply &action)
{
    return os << (action==ParsedContextReply::ACCEPT ? "ACCEPT" : "DROP");
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

class EntryTest : public Test
{
public:
    EntryTest()
    {
        ON_CALL(table, getState(_)).WillByDefault(Return(ptr));
    }

    void
    loadSignatures(const string &sigs)
    {
        {
            stringstream ss;
            ss << "[" << sigs << "]";
            cereal::JSONInputArchive ar(ss);
            IPSSignaturesResource resource;
            resource.load(ar);
            setResource(resource, "IPS", "protections");
        }
        {
            stringstream ss;
            ss << "{";
            ss << "\"context\": \"\",";
            ss << "\"ruleName\": \"rule1\",";
            ss << "\"assetName\": \"asset1\",";
            ss << "\"assetId\": \"1-1-1\",";
            ss << "\"practiceId\": \"2-2-2\",";
            ss << "\"practiceName\": \"practice1\",";
            ss << "\"defaultAction\": \"Detect\",";
            ss << "\"rules\": [";
            ss << "{";
            ss << "\"action\": \"Prevent\",";
            ss << "\"performanceImpact\": \"High or lower\",";
            ss << "\"severityLevel\": \"Low or above\",";
            ss << "\"confidenceLevel\": \"Low\"";
            ss << "}";
            ss << "]";
            ss << "}";
            cereal::JSONInputArchive ar(ss);
            IPSSignatures signatures;
            signatures.load(ar);
            setConfiguration(signatures, "IPS", "IpsProtections");
        }
    }

    void
    loadSnortSignatures(const string &sigs)
    {
        {
            stringstream ss;
            ss << "[{ \"modificationTime\": \"22/02/08\", \"name\": \"rules1\", \"protections\": [" << sigs << "] }]";
            cereal::JSONInputArchive ar(ss);
            SnortSignaturesResource resource;
            resource.load(ar);
            setResource(resource, "IPSSnortSigs", "protections");
        }
        {
            stringstream ss;
            ss << "{";
            ss << "\"context\": \"\",";
            ss << "\"assetName\": \"asset1\",";
            ss << "\"assetId\": \"1-1-1\",";
            ss << "\"practiceId\": \"2-2-2\",";
            ss << "\"practiceName\": \"practice1\",";
            ss << "\"files\": [ \"rules1\" ],";
            ss << "\"mode\": \"Prevent\"";
            ss << "}";
            cereal::JSONInputArchive ar(ss);
            SnortSignatures signatures;
            signatures.load(ar);
            setConfiguration(signatures, "IPSSnortSigs", "SnortProtections");
        }
    }

    ParsedContextReply
    repondToContext(const string &buf_str, const string &name)
    {
        Buffer buf(buf_str);
        ScopedContext ctx;
        ctx.registerValue(name, buf);
        return entry.respond(ParsedContext(buf, name, 0));
    }

    IPSEntry entry;
    TableOpaqueBase *ptr = &entry;

private:
    NiceMock<MockMainLoop> mock_mainloop;
    NiceMock<MockTimeGet> time;
    ::Environment env;
    GenericRulebase generic_rulebase;
    ConfigComponent conf;
    KeywordComp keywords;
    AgentDetails details;
    NiceMock<MockLogging> logs;
    NiceMock<MockTable> table;
    MockAgg mock_agg;
};

TEST_F(EntryTest, basic_inherited_functions)
{
    EXPECT_EQ(IPSEntry::name(), "IPS");
    EXPECT_EQ(IPSEntry::currVer(), 0);
    EXPECT_EQ(IPSEntry::minVer(), 0);
    EXPECT_NE(IPSEntry::prototype(), nullptr);
    EXPECT_EQ(entry.getListenerName(), IPSEntry::name());

    stringstream ss;
    {
        cereal::JSONOutputArchive ar(ss);
        entry.serialize(ar, 0);
    }
    EXPECT_EQ(ss.str(), "");

    // Just make sure it doesn't crush
    entry.upon(ParsedContext(Buffer(), "Nothing", 0));
}

TEST_F(EntryTest, check_listenning)
{
    EXPECT_TRUE(Listener<ParsedContext>::empty());
    ptr->uponEnteringContext();
    EXPECT_FALSE(Listener<ParsedContext>::empty());
    ptr->uponLeavingContext();
    EXPECT_TRUE(Listener<ParsedContext>::empty());
}

TEST_F(EntryTest, check_signature_invoking)
{
    EXPECT_EQ(repondToContext("ddd", "HTTP_REQUEST_BODY"), ParsedContextReply::ACCEPT);
    EXPECT_EQ(repondToContext("ddd", "HTTP_RESPONSE_BODY"), ParsedContextReply::ACCEPT);

    string signature =
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
                "\"keywords\": \"data: \\\"ddd\\\";\","
                "\"context\": [\"HTTP_REQUEST_BODY\"]"
            "}"
        "}";
    loadSignatures(signature);

    EXPECT_EQ(repondToContext("ddd", "HTTP_REQUEST_BODY"), ParsedContextReply::DROP);
    EXPECT_EQ(repondToContext("ddd", "HTTP_RESPONSE_BODY"), ParsedContextReply::ACCEPT);
}

TEST_F(EntryTest, check_snort_signature_invoking)
{
    EXPECT_EQ(repondToContext("ddd", "HTTP_REQUEST_BODY"), ParsedContextReply::ACCEPT);
    EXPECT_EQ(repondToContext("ddd", "HTTP_RESPONSE_BODY"), ParsedContextReply::ACCEPT);

    string signature =
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
                "\"keywords\": \"data: \\\"ddd\\\";\","
                "\"context\": [\"HTTP_REQUEST_BODY\"]"
            "}"
        "},"
        "{"
            "\"protectionMetadata\": {"
                "\"protectionName\": \"Bad sig\","
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
                "\"keywords\": \"data: jjjj;\","
                "\"context\": [\"HTTP_REQUEST_BODY\"]"
            "}"
        "}";
    loadSnortSignatures(signature);

    EXPECT_EQ(repondToContext("ddd", "HTTP_REQUEST_BODY"), ParsedContextReply::DROP);
    EXPECT_EQ(repondToContext("ddd", "HTTP_RESPONSE_BODY"), ParsedContextReply::ACCEPT);
}

TEST_F(EntryTest, flags_test)
{
    EXPECT_FALSE(entry.isFlagSet("CONTEXT_A"));
    EXPECT_FALSE(entry.isFlagSet("CONTEXT_B"));
    entry.setFlag("CONTEXT_A");
    EXPECT_TRUE(entry.isFlagSet("CONTEXT_A"));
    EXPECT_FALSE(entry.isFlagSet("CONTEXT_B"));
    entry.unsetFlag("CONTEXT_A");
    EXPECT_FALSE(entry.isFlagSet("CONTEXT_A"));
    EXPECT_FALSE(entry.isFlagSet("CONTEXT_B"));
}

TEST_F(EntryTest, get_buffer_test)
{
    repondToContext("ddd", "HTTP_REQUEST_BODY");
    EXPECT_EQ(entry.getBuffer("HTTP_REQUEST_BODY"), Buffer("ddd"));
    EXPECT_EQ(entry.getBuffer("HTTP_REQUEST_HEADER"), Buffer());
}

TEST_F(EntryTest, get_and_set_transaction_data)
{
    EXPECT_FALSE(entry.getTransactionData(Buffer("transaction_key")).ok());
    entry.setTransactionData(Buffer("transaction_key"), Buffer("transaction_value"));
    ASSERT_TRUE(entry.getTransactionData(Buffer("transaction_key")).ok());
    EXPECT_EQ(entry.getTransactionData(Buffer("transaction_key")).unpack(), Buffer("transaction_value"));
}
