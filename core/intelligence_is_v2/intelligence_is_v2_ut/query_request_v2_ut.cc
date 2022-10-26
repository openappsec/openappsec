#include "intelligence_is_v2/query_request_v2.h"

#include "cptest.h"

using namespace std;
using namespace testing;

TEST(QueryRequestTestV2, QueryTest)
{
    QueryRequest request(Condition::EQUALS, "phase", "testing", true);
    SerializableQueryFilter request_query1 = request.getQuery();
    vector<SerializableQueryCondition> request_operands1 = request_query1.getConditionOperands();
    SerializableQueryCondition request_condition = *request_operands1.begin();

    EXPECT_EQ(request_query1.getOperator(), Operator::NONE);
    EXPECT_EQ(request_condition.getKey(), "mainAttributes.phase");
    EXPECT_EQ(request_condition.getValue(), "testing");

    request.addCondition(Condition::EQUALS, "user1", "Omry");
    request.addCondition(Condition::EQUALS, "user2", "Max");
    SerializableQueryFilter request_query2 = request.getQuery();
    vector<SerializableQueryCondition> request_operands2 = request_query2.getConditionOperands();

    vector<SerializableQueryCondition>::iterator it = request_operands2.begin();
    it++;

    EXPECT_EQ(request_query2.getOperator(), Operator::AND);
    EXPECT_EQ(it->getKey(), "mainAttributes.user1");
    EXPECT_EQ(it->getValue(), "Omry");

    it++;
    EXPECT_EQ(it->getKey(), "mainAttributes.user2");
    EXPECT_EQ(it->getValue(), "Max");

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
