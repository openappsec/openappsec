#include "intelligence_is_v2/query_request_v2.h"

#include "cptest.h"

using namespace std;
using namespace testing;

USE_DEBUG_FLAG(D_INTELLIGENCE);

TEST(QueryRequestTestV2, QueryTest)
{
    QueryRequest request(Condition::EQUALS, "phase", "testing", true);
    request.addCondition(Condition::EQUALS, "user1", "Omry");
    request.addCondition(Condition::EQUALS, "user2", "Max");

    string output_json =
    "{\n"
    "    \"limit\": 20,\n"
    "    \"fullResponse\": true,\n"
    "    \"query\": {\n"
    "        \"operator\": \"and\",\n"
    "        \"operands\": [\n"
    "            {\n"
    "                \"operator\": \"equals\",\n"
    "                \"key\": \"mainAttributes.phase\",\n"
    "                \"value\": \"testing\"\n"
    "            },\n"
    "            {\n"
    "                \"operator\": \"equals\",\n"
    "                \"key\": \"mainAttributes.user1\",\n"
    "                \"value\": \"Omry\"\n"
    "            },\n"
    "            {\n"
    "                \"operator\": \"equals\",\n"
    "                \"key\": \"mainAttributes.user2\",\n"
    "                \"value\": \"Max\"\n"
    "            }\n"
    "        ]\n"
    "    }\n"
    "}";


    stringstream out;
    {
        cereal::JSONOutputArchive out_ar(out);
        request.saveToJson(out_ar);
    }
    EXPECT_EQ(out.str(), output_json);

    QueryRequest request2(Condition::GREATER_THAN, "prev_time", 1676887025952, true);
    request2.addCondition(Condition::LESS_THAN, "curr_time", 1676887025958);

    string output_json2=
    "{\n"
    "    \"limit\": 20,\n"
    "    \"fullResponse\": true,\n"
    "    \"query\": {\n"
    "        \"operator\": \"and\",\n"
    "        \"operands\": [\n"
    "            {\n"
    "                \"operator\": \"greaterThan\",\n"
    "                \"key\": \"mainAttributes.prev_time\",\n"
    "                \"value\": 1676887025952\n"
    "            },\n"
    "            {\n"
    "                \"operator\": \"lessThan\",\n"
    "                \"key\": \"mainAttributes.curr_time\",\n"
    "                \"value\": 1676887025958\n"
    "            }\n"
    "        ]\n"
    "    }\n"
    "}";


    stringstream out2;
    {
        cereal::JSONOutputArchive out_ar2(out2);
        request2.saveToJson(out_ar2);
    }
    EXPECT_EQ(out2.str(), output_json2);
}

TEST(QueryRequestTestV2, AttributesTest)
{
    QueryRequest request(Condition::EQUALS, "phase", "testing", true);
    SerializableAttributesMap request_attributes_map1 = request.getRequestedAttributes();

    EXPECT_TRUE(request_attributes_map1.isRequestedAttributesMapEmpty());

    request.setRequestedAttr("countryName");
    SerializableAttributesMap request_attributes_map2 = request.getRequestedAttributes();

    EXPECT_EQ(request_attributes_map2.getAttributeByKey("attributes.countryName"), 500);

    request.setRequestedAttr("reputationSeverity", 30);
    SerializableAttributesMap request_attributes_map3 = request.getRequestedAttributes();

    EXPECT_EQ(request_attributes_map3.getAttributeByKey("attributes.reputationSeverity"), 30);

    string output_json =
    "{\n"
    "    \"limit\": 20,\n"
    "    \"fullResponse\": true,\n"
    "    \"query\": {\n"
    "        \"operator\": \"equals\",\n"
    "        \"key\": \"mainAttributes.phase\",\n"
    "        \"value\": \"testing\"\n"
    "    },\n"
    "    \"requestedAttributes\": [\n"
    "        {\n"
    "            \"key\": \"attributes.reputationSeverity\",\n"
    "            \"minConfidence\": 30\n"
    "        },\n"
    "        {\n"
    "            \"key\": \"attributes.countryName\",\n"
    "            \"minConfidence\": 500\n"
    "        }\n"
    "    ]\n"
    "}";

    stringstream out;
    {
        cereal::JSONOutputArchive out_ar(out);
        request.saveToJson(out_ar);
    }
    EXPECT_EQ(out.str(), output_json);
}

TEST(QueryRequestTestV2, AndQueryTest)
{
    QueryRequest request1(Condition::EQUALS, "phase", "testing1", true);
    QueryRequest request2(Condition::EQUALS, "phase", "testing2", true);
    QueryRequest and_request = request1 && request2;

    stringstream out;
    {
        cereal::JSONOutputArchive out_ar(out);
        and_request.saveToJson(out_ar);
    }

    string output_json =
        "{\n"
        "    \"limit\": 20,\n"
        "    \"fullResponse\": true,\n"
        "    \"query\": {\n"
        "        \"operator\": \"and\",\n"
        "        \"operands\": [\n"
        "            {\n"
        "                \"operator\": \"equals\",\n"
        "                \"key\": \"mainAttributes.phase\",\n"
        "                \"value\": \"testing1\"\n"
        "            },\n"
        "            {\n"
        "                \"operator\": \"equals\",\n"
        "                \"key\": \"mainAttributes.phase\",\n"
        "                \"value\": \"testing2\"\n"
        "            }\n"
        "        ]\n"
        "    }\n"
        "}";
    EXPECT_EQ(out.str(), output_json);
}

TEST(QueryRequestTestV2, OrQueryTest)
{
    QueryRequest request1(Condition::EQUALS, "phase", "testing1", true);
    QueryRequest request2(Condition::EQUALS, "phase", "testing2", true);
    QueryRequest and_request = request1 || request2;

    stringstream out;
    {
        cereal::JSONOutputArchive out_ar(out);
        and_request.saveToJson(out_ar);
    }

    string output_json =
        "{\n"
        "    \"limit\": 20,\n"
        "    \"fullResponse\": true,\n"
        "    \"query\": {\n"
        "        \"operator\": \"or\",\n"
        "        \"operands\": [\n"
        "            {\n"
        "                \"operator\": \"equals\",\n"
        "                \"key\": \"mainAttributes.phase\",\n"
        "                \"value\": \"testing1\"\n"
        "            },\n"
        "            {\n"
        "                \"operator\": \"equals\",\n"
        "                \"key\": \"mainAttributes.phase\",\n"
        "                \"value\": \"testing2\"\n"
        "            }\n"
        "        ]\n"
        "    }\n"
        "}";
    EXPECT_EQ(out.str(), output_json);
}

TEST(QueryRequestTestV2, AndQueryTestThree)
{
    QueryRequest request1(Condition::EQUALS, "phase", "testing1", true);
    QueryRequest request2(Condition::EQUALS, "phase", "testing2", true);
    QueryRequest request3(Condition::EQUALS, "phase", "testing3", true);
    QueryRequest and_request_1_2 = request1 && (request2 && request3);
    QueryRequest and_request_2_1 = (request1 && request2) && request3;

    stringstream out_1_2;
    {
        cereal::JSONOutputArchive out_1_2_ar(out_1_2);
        and_request_1_2.saveToJson(out_1_2_ar);
    }

    stringstream out_2_1;
    {
        cereal::JSONOutputArchive out_2_1_ar(out_2_1);
        and_request_2_1.saveToJson(out_2_1_ar);
    }

    string output_json =
        "{\n"
        "    \"limit\": 20,\n"
        "    \"fullResponse\": true,\n"
        "    \"query\": {\n"
        "        \"operator\": \"and\",\n"
        "        \"operands\": [\n"
        "            {\n"
        "                \"operator\": \"equals\",\n"
        "                \"key\": \"mainAttributes.phase\",\n"
        "                \"value\": \"testing1\"\n"
        "            },\n"
        "            {\n"
        "                \"operator\": \"equals\",\n"
        "                \"key\": \"mainAttributes.phase\",\n"
        "                \"value\": \"testing2\"\n"
        "            },\n"
        "            {\n"
        "                \"operator\": \"equals\",\n"
        "                \"key\": \"mainAttributes.phase\",\n"
        "                \"value\": \"testing3\"\n"
        "            }\n"
        "        ]\n"
        "    }\n"
        "}";
    EXPECT_EQ(out_1_2.str(), output_json);
    EXPECT_EQ(out_2_1.str(), output_json);
}

TEST(QueryRequestTestV2, OrQueryTestThree)
{
    QueryRequest request1(Condition::EQUALS, "phase", "testing1", true);
    QueryRequest request2(Condition::EQUALS, "phase", "testing2", true);
    QueryRequest request3(Condition::EQUALS, "phase", "testing3", true);
    QueryRequest or_request_1_2 = request1 || (request2 || request3);
    QueryRequest or_request_2_1 = (request1 || request2) || request3;

    stringstream out_1_2;
    {
        cereal::JSONOutputArchive out_1_2_ar(out_1_2);
        or_request_1_2.saveToJson(out_1_2_ar);
    }

    stringstream out_2_1;
    {
        cereal::JSONOutputArchive out_2_1_ar(out_2_1);
        or_request_2_1.saveToJson(out_2_1_ar);
    }

    string output_json =
        "{\n"
        "    \"limit\": 20,\n"
        "    \"fullResponse\": true,\n"
        "    \"query\": {\n"
        "        \"operator\": \"or\",\n"
        "        \"operands\": [\n"
        "            {\n"
        "                \"operator\": \"equals\",\n"
        "                \"key\": \"mainAttributes.phase\",\n"
        "                \"value\": \"testing1\"\n"
        "            },\n"
        "            {\n"
        "                \"operator\": \"equals\",\n"
        "                \"key\": \"mainAttributes.phase\",\n"
        "                \"value\": \"testing2\"\n"
        "            },\n"
        "            {\n"
        "                \"operator\": \"equals\",\n"
        "                \"key\": \"mainAttributes.phase\",\n"
        "                \"value\": \"testing3\"\n"
        "            }\n"
        "        ]\n"
        "    }\n"
        "}";
    EXPECT_EQ(out_1_2.str(), output_json);
    EXPECT_EQ(out_2_1.str(), output_json);
}

TEST(QueryRequestTestV2, AndWithConditionQueryTest)
{
    QueryRequest request1(Condition::EQUALS, "phase", "testing1", true);
    QueryRequest request2(Condition::EQUALS, "phase", "testing2", true);
    QueryRequest and_with_cond_request = request1 && request2;
    and_with_cond_request.addCondition(Condition::EQUALS, "user1", "Oren");

    stringstream out;
    {
        cereal::JSONOutputArchive out_ar(out);
        and_with_cond_request.saveToJson(out_ar);
    }

    string output_json =
        "{\n"
        "    \"limit\": 20,\n"
        "    \"fullResponse\": true,\n"
        "    \"query\": {\n"
        "        \"operator\": \"and\",\n"
        "        \"operands\": [\n"
        "            {\n"
        "                \"operator\": \"equals\",\n"
        "                \"key\": \"mainAttributes.phase\",\n"
        "                \"value\": \"testing1\"\n"
        "            },\n"
        "            {\n"
        "                \"operator\": \"equals\",\n"
        "                \"key\": \"mainAttributes.phase\",\n"
        "                \"value\": \"testing2\"\n"
        "            },\n"
        "            {\n"
        "                \"operator\": \"equals\",\n"
        "                \"key\": \"mainAttributes.user1\",\n"
        "                \"value\": \"Oren\"\n"
        "            }\n"
        "        ]\n"
        "    }\n"
        "}";
    EXPECT_EQ(out.str(), output_json);
}

TEST(QueryRequestTestV2, SemiComplexQueryTest)
{
    QueryRequest request1(Condition::EQUALS, "phase", "testing1", true);
    QueryRequest request2(Condition::EQUALS, "phase", "testing2", true);
    QueryRequest request3(Condition::EQUALS, "CountryCode", "USA", true);
    QueryRequest semi_complex_query_request = (request1 || request2) && request3;

    stringstream out;
    {
        cereal::JSONOutputArchive out_ar(out);
        semi_complex_query_request.saveToJson(out_ar);
    }

    string output_json =
        "{\n"
        "    \"limit\": 20,\n"
        "    \"fullResponse\": true,\n"
        "    \"query\": {\n"
        "        \"operator\": \"and\",\n"
        "        \"operands\": [\n"
        "            {\n"
        "                \"operator\": \"or\",\n"
        "                \"operands\": [\n"
        "                    {\n"
        "                        \"operator\": \"equals\",\n"
        "                        \"key\": \"mainAttributes.phase\",\n"
        "                        \"value\": \"testing1\"\n"
        "                    },\n"
        "                    {\n"
        "                        \"operator\": \"equals\",\n"
        "                        \"key\": \"mainAttributes.phase\",\n"
        "                        \"value\": \"testing2\"\n"
        "                    }\n"
        "                ]\n"
        "            },\n"
        "            {\n"
        "                \"operator\": \"equals\",\n"
        "                \"key\": \"mainAttributes.CountryCode\",\n"
        "                \"value\": \"USA\"\n"
        "            }\n"
        "        ]\n"
        "    }\n"
        "}";
    EXPECT_EQ(out.str(), output_json);
}

TEST(QueryRequestTestV2, ComplexQueryTest)
{
    QueryRequest request1(Condition::EQUALS, "phase", "testing1", true);
    QueryRequest request2(Condition::EQUALS, "phase", "testing2", true);
    QueryRequest request3(Condition::EQUALS, "CountryCode", "USA", true);
    QueryRequest request4(Condition::EQUALS, "CountryCode", "IL", true);
    QueryRequest request5 = request1 && request2;
    QueryRequest request6 = request3 || request4;
    QueryRequest complex_query_request = request5 || request6;

    stringstream out;
    {
        cereal::JSONOutputArchive out_ar(out);
        complex_query_request.saveToJson(out_ar);
    }
    string output_json =
        "{\n"
        "    \"limit\": 20,\n"
        "    \"fullResponse\": true,\n"
        "    \"query\": {\n"
        "        \"operator\": \"or\",\n"
        "        \"operands\": [\n"
        "            {\n"
        "                \"operator\": \"and\",\n"
        "                \"operands\": [\n"
        "                    {\n"
        "                        \"operator\": \"equals\",\n"
        "                        \"key\": \"mainAttributes.phase\",\n"
        "                        \"value\": \"testing1\"\n"
        "                    },\n"
        "                    {\n"
        "                        \"operator\": \"equals\",\n"
        "                        \"key\": \"mainAttributes.phase\",\n"
        "                        \"value\": \"testing2\"\n"
        "                    }\n"
        "                ]\n"
        "            },\n"
        "            {\n"
        "                \"operator\": \"or\",\n"
        "                \"operands\": [\n"
        "                    {\n"
        "                        \"operator\": \"equals\",\n"
        "                        \"key\": \"mainAttributes.CountryCode\",\n"
        "                        \"value\": \"USA\"\n"
        "                    },\n"
        "                    {\n"
        "                        \"operator\": \"equals\",\n"
        "                        \"key\": \"mainAttributes.CountryCode\",\n"
        "                        \"value\": \"IL\"\n"
        "                    }\n"
        "                ]\n"
        "            }\n"
        "        ]\n"
        "    }\n"
        "}";
    complex_query_request.addCondition(Condition::EQUALS, "user1", "Oren");
    stringstream out_with_new_condition;
    {
        cereal::JSONOutputArchive out_ar(out_with_new_condition);
        complex_query_request.saveToJson(out_ar);
    }
    string output_json_with_condition =
    "{\n"
    "    \"limit\": 20,\n"
    "    \"fullResponse\": true,\n"
    "    \"query\": {\n"
    "        \"operator\": \"or\",\n"
    "        \"operands\": [\n"
    "            {\n"
    "                \"operator\": \"and\",\n"
    "                \"operands\": [\n"
    "                    {\n"
    "                        \"operator\": \"equals\",\n"
    "                        \"key\": \"mainAttributes.phase\",\n"
    "                        \"value\": \"testing1\"\n"
    "                    },\n"
    "                    {\n"
    "                        \"operator\": \"equals\",\n"
    "                        \"key\": \"mainAttributes.phase\",\n"
    "                        \"value\": \"testing2\"\n"
    "                    }\n"
    "                ]\n"
    "            },\n"
    "            {\n"
    "                \"operator\": \"or\",\n"
    "                \"operands\": [\n"
    "                    {\n"
    "                        \"operator\": \"equals\",\n"
    "                        \"key\": \"mainAttributes.CountryCode\",\n"
    "                        \"value\": \"USA\"\n"
    "                    },\n"
    "                    {\n"
    "                        \"operator\": \"equals\",\n"
    "                        \"key\": \"mainAttributes.CountryCode\",\n"
    "                        \"value\": \"IL\"\n"
    "                    }\n"
    "                ]\n"
    "            },\n"
    "            {\n"
    "                \"operator\": \"equals\",\n"
    "                \"key\": \"mainAttributes.user1\",\n"
    "                \"value\": \"Oren\"\n"
    "            }\n"
    "        ]\n"
    "    }\n"
    "}";
    EXPECT_EQ(out_with_new_condition.str(), output_json_with_condition);
}

TEST(QueryRequestTestV2, OneLinerComplexQueryTest)
{
    QueryRequest complex_query_request = (
        (
            QueryRequest(Condition::EQUALS, "phase", "testing1", true) &&
            QueryRequest(Condition::EQUALS, "phase", "testing2", true)
        ) || (
            QueryRequest(Condition::EQUALS, "CountryCode", "USA", true) ||
            QueryRequest(Condition::EQUALS, "CountryCode", "IL", true)
        )
    );

    stringstream out;
    {
        cereal::JSONOutputArchive out_ar(out);
        complex_query_request.saveToJson(out_ar);
    }
    string output_json =
        "{\n"
        "    \"limit\": 20,\n"
        "    \"fullResponse\": true,\n"
        "    \"query\": {\n"
        "        \"operator\": \"or\",\n"
        "        \"operands\": [\n"
        "            {\n"
        "                \"operator\": \"and\",\n"
        "                \"operands\": [\n"
        "                    {\n"
        "                        \"operator\": \"equals\",\n"
        "                        \"key\": \"mainAttributes.phase\",\n"
        "                        \"value\": \"testing1\"\n"
        "                    },\n"
        "                    {\n"
        "                        \"operator\": \"equals\",\n"
        "                        \"key\": \"mainAttributes.phase\",\n"
        "                        \"value\": \"testing2\"\n"
        "                    }\n"
        "                ]\n"
        "            },\n"
        "            {\n"
        "                \"operator\": \"or\",\n"
        "                \"operands\": [\n"
        "                    {\n"
        "                        \"operator\": \"equals\",\n"
        "                        \"key\": \"mainAttributes.CountryCode\",\n"
        "                        \"value\": \"USA\"\n"
        "                    },\n"
        "                    {\n"
        "                        \"operator\": \"equals\",\n"
        "                        \"key\": \"mainAttributes.CountryCode\",\n"
        "                        \"value\": \"IL\"\n"
        "                    }\n"
        "                ]\n"
        "            }\n"
        "        ]\n"
        "    }\n"
        "}";
    EXPECT_EQ(out.str(), output_json);
}

TEST(QueryRequestTestV2, CrossTenantAssetDBTest)
{
    QueryRequest request(Condition::EQUALS, "class", "risk", true);

    request.setObjectType(ObjectType::CONFIGURATION);
    request.setCrossTenantAssetDB(true);

    string output_json =
        "{\n"
        "    \"limit\": 20,\n"
        "    \"fullResponse\": true,\n"
        "    \"query\": {\n"
        "        \"operator\": \"equals\",\n"
        "        \"key\": \"mainAttributes.class\",\n"
        "        \"value\": \"risk\"\n"
        "    },\n"
        "    \"objectType\": \"configuration\",\n"
        "    \"queryTypes\": {\n"
        "        \"queryCrossTenantAssetDB\": true\n"
        "    }\n"
        "}";

    stringstream out;
    {
        cereal::JSONOutputArchive out_ar(out);
        request.saveToJson(out_ar);
    }
    EXPECT_EQ(out.str(), output_json);
}

TEST(QueryRequestTestV2, IllegalObjectTypeTest)
{
    QueryRequest request(Condition::EQUALS, "class", "risk", true);
    stringstream debug_output;
    Debug::setNewDefaultStdout(&debug_output);
    Debug::setUnitTestFlag(D_INTELLIGENCE, Debug::DebugLevel::TRACE);

    request.setObjectType(static_cast<ObjectType>(static_cast<int>(ObjectType::COUNT) + 1));
    request.setCrossTenantAssetDB(true);

    string output_json =
        "{\n"
        "    \"limit\": 20,\n"
        "    \"fullResponse\": true,\n"
        "    \"query\": {\n"
        "        \"operator\": \"equals\",\n"
        "        \"key\": \"mainAttributes.class\",\n"
        "        \"value\": \"risk\"\n"
        "    },\n"
        "    \"queryTypes\": {\n"
        "        \"queryCrossTenantAssetDB\": true\n"
        "    }\n"
        "}";

    stringstream out;
    {
        cereal::JSONOutputArchive out_ar(out);
        request.saveToJson(out_ar);
    }
    EXPECT_EQ(out.str(), output_json);

    string debug_str = "Illegal Object Type.";
    EXPECT_THAT(debug_output.str(), HasSubstr(debug_str));
    Debug::setNewDefaultStdout(&cout);
}

TEST(QueryRequestTestV2, UninitializedObjectTypeTest)
{
    QueryRequest request(Condition::EQUALS, "class", "risk", true);
    stringstream debug_output;
    Debug::setNewDefaultStdout(&debug_output);
    Debug::setUnitTestFlag(D_INTELLIGENCE, Debug::DebugLevel::TRACE);

    request.setCrossTenantAssetDB(true);

    string output_json =
        "{\n"
        "    \"limit\": 20,\n"
        "    \"fullResponse\": true,\n"
        "    \"query\": {\n"
        "        \"operator\": \"equals\",\n"
        "        \"key\": \"mainAttributes.class\",\n"
        "        \"value\": \"risk\"\n"
        "    },\n"
        "    \"queryTypes\": {\n"
        "        \"queryCrossTenantAssetDB\": true\n"
        "    }\n"
        "}";

    stringstream out;
    {
        cereal::JSONOutputArchive out_ar(out);
        request.saveToJson(out_ar);
    }
    EXPECT_EQ(out.str(), output_json);

    string debug_str = "uninitialized";
    EXPECT_THAT(debug_output.str(), HasSubstr(debug_str));
    Debug::setNewDefaultStdout(&cout);
}
