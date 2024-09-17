#include <sstream>
namespace Intelligence { class Response; }
std::ostream & operator<<(std::ostream &os, const Intelligence::Response &);

#include "intelligence_comp_v2.h"

#include "config.h"
#include "config_component.h"
#include "cptest.h"
#include "mock/mock_intelligence.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_messaging.h"
#include "mock/mock_rest_api.h"
#include "mock/mock_time_get.h"
#include "mock/mock_agent_details.h"
#include "read_attribute_v2.h"
#include "singleton.h"

using namespace std;
using namespace testing;
using namespace chrono;
using namespace Intelligence_IS_V2;

USE_DEBUG_FLAG(D_METRICS);
USE_DEBUG_FLAG(D_INTELLIGENCE);


class IntelligenceComponentTestV2
        :
    public Test,
    Singleton::Consume<I_Intelligence_IS_V2>
{
public:
    IntelligenceComponentTestV2()
    {
        debug_output.clear();
        Debug::setNewDefaultStdout(&debug_output);
        Debug::setUnitTestFlag(D_METRICS, Debug::DebugLevel::TRACE);
        Debug::setUnitTestFlag(D_INTELLIGENCE, Debug::DebugLevel::TRACE);
        setConfiguration<bool>(false, string("metric"), string("fogMetricSendEnable"));

        EXPECT_CALL(
            mock_ml,
            addRecurringRoutine(I_MainLoop::RoutineType::System, chrono::microseconds(600000000), _, _, _)
        ).WillRepeatedly(DoAll(SaveArg<2>(&routine), Return(0)));

        EXPECT_CALL(
            mock_ml,
            addRecurringRoutine(I_MainLoop::RoutineType::System, chrono::microseconds(720000000), _, _, _)
        ).WillRepeatedly(Return(0));

        EXPECT_CALL(mock_agent_details, getAgentId()).WillRepeatedly(Return("dummy_agent_id"));
        EXPECT_CALL(mock_agent_details, getTenantId()).WillRepeatedly(Return("dummy_tenant_id"));

        EXPECT_CALL(
            mock_rest,
            mockRestCall(_, "new-invalidation/source/invalidation", _)
        ).WillRepeatedly(Return(true));

        conf.preload();
        intelligence.preload();
        intelligence.init();
    }

    ~IntelligenceComponentTestV2()
    {
        Debug::setNewDefaultStdout(&cout);
    }

    stringstream debug_output;
    StrictMock<MockMainLoop> mock_ml;
    StrictMock<MockRestApi> mock_rest;
    StrictMock<MockAgentDetails> mock_agent_details;
    NiceMock<MockTimeGet> mock_time;
    ::Environment env;
    ConfigComponent conf;
    StrictMock<MockMessaging> messaging_mock;
    IntelligenceComponentV2 intelligence;
    I_MainLoop::Routine routine;
};

class IntelligenceComponentMockTest : public Test, Singleton::Consume<I_Intelligence_IS_V2>
{
public:
    IntelligenceComponentMockTest()
    {
        debug_output.clear();
        Debug::setNewDefaultStdout(&debug_output);
        Debug::setUnitTestFlag(D_METRICS, Debug::DebugLevel::TRACE);
        Debug::setUnitTestFlag(D_INTELLIGENCE, Debug::DebugLevel::TRACE);
        setConfiguration<bool>(false, string("metric"), string("fogMetricSendEnable"));

        conf.preload();
    }

    ~IntelligenceComponentMockTest()
    {
        Debug::setNewDefaultStdout(&cout);
    }

    ::Environment env;
    ConfigComponent conf;
    stringstream debug_output;
    StrictMock<MockIntelligence> intelligence_mock;
};

class Profile
{
public:
    Profile() {}

    DataString getUser() const{ return user;}
    DataString getPhase() const{ return phase;}

    template <typename Archive>
    void
    serialize(Archive &ar)
    {
        try {
            ReadAttribute<DataString>("user", user).serialize(ar);
        } catch (const exception &e) {}
        try {
            ReadAttribute<DataString>("phase", phase).serialize(ar);
        } catch (const exception &e) {}
    }

private:
    DataString user;
    DataString phase;
};

TEST_F(IntelligenceComponentMockTest, getResponseErrorTest)
{
    I_Intelligence_IS_V2 *intell = Singleton::Consume<I_Intelligence_IS_V2>::by<IntelligenceComponentTestV2>();
    QueryRequest request(Condition::EQUALS, "category", "cloud", true);

    Maybe<Intelligence::Response> res_error = genError("Test error");
    EXPECT_CALL(intelligence_mock, getResponse(_, _, _, _)
    ).WillOnce(Return(res_error));

    auto maybe_ans = intell->queryIntelligence<Profile>(request);
    EXPECT_FALSE(maybe_ans.ok());
}

TEST_F(IntelligenceComponentMockTest, getResponseTest)
{
    I_Intelligence_IS_V2 *intell = Singleton::Consume<I_Intelligence_IS_V2>::by<IntelligenceComponentTestV2>();
    QueryRequest request(Condition::EQUALS, "category", "cloud", true);

    string response_str(
        "{\n"
        "  \"assetCollections\": [\n"
        "    {\n"
        "      \"schemaVersion\": 1,\n"
        "      \"assetType\": \"workload-cloud-fake-online-test\",\n"
        "      \"assetTypeSchemaVersion\": 1,\n"
        "      \"permissionType\": \"tenant\",\n"
        "      \"permissionGroupId\": \"fake-online-test-group\",\n"
        "      \"name\": \"fake-online-test-asset\",\n"
        "      \"class\": \"workload\",\n"
        "      \"category\": \"cloud\",\n"
        "      \"family\": \"fake-online-test\",\n"
        "      \"mainAttributes\": {\n"
        "          \"ipv4Addresses\": \"1.1.1.1\",\n"
        "          \"phase\": \"testing\"\n"
        "      },\n"
        "      \"sources\": [\n"
        "        {\n"
        "          \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229aa00\",\n"
        "          \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7aaa00\",\n"
        "          \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd1\",\n"
        "          \"ttl\": 120,\n"
        "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "          \"confidence\": 500,\n"
        "          \"attributes\": {\n"
        "            \"phase\": \"testing\",\n"
        "            \"user\": \"Omry\",\n"
        "            \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    }\n"
        "  ],\n"
        "  \"status\": \"done\",\n"
        "  \"totalNumAssets\": 2,\n"
        "  \"cursor\": \"start\"\n"
        "}\n"
    );

    Intelligence::Response response(response_str, 1, false);

    EXPECT_CALL(intelligence_mock, getResponse(_, _, _, _)
    ).WillOnce(Return(response));

    auto maybe_ans = intell->queryIntelligence<Profile>(request);
    EXPECT_TRUE(maybe_ans.ok());
    auto vec = maybe_ans.unpack();
    EXPECT_EQ(vec.size(), 1u);
    auto iter = vec.begin();
    EXPECT_EQ(iter->getData().begin()->getUser().toString(), "Omry");
    EXPECT_EQ(iter->getData().begin()->getPhase().toString(), "testing");
}

TEST_F(IntelligenceComponentMockTest, bulkOnlineIntelligenceMockTest)
{
    I_Intelligence_IS_V2 *intell = Singleton::Consume<I_Intelligence_IS_V2>::by<IntelligenceComponentMockTest>();
    vector<QueryRequest> requests;
    requests.emplace_back(Condition::EQUALS, "category", "whatever", true);
    requests.emplace_back(Condition::EQUALS, "category", "cloud", true);
    requests.emplace_back(Condition::EQUALS, "category", "nothing", true);
    requests.emplace_back(Condition::EQUALS, "category", "iot", true);

    string response_str(
        "{\n"
        "  \"errors\": [\n"
        "    {\n"
        "      \"index\": 0,\n"
        "      \"statusCode\": 400,\n"
        "      \"message\": \"Bad request. Error: Invalid cursor\"\n"
        "    },"
        "    {\n"
        "      \"index\": 2,\n"
        "      \"statusCode\": 405,\n"
        "      \"message\": \"Bad request. Error: Something else\"\n"
        "    }"
        "  ],\n" // errors
        "  \"queriesResponse\": [\n"
        "    {\n"
        "      \"index\": 1,\n"
        "      \"response\": {\n"
        "        \"assetCollections\": [\n"
        "          {\n"
        "            \"schemaVersion\": 1,\n"
        "            \"assetType\": \"workload-cloud-ip\",\n"
        "            \"assetTypeSchemaVersion\": 1,\n"
        "            \"permissionType\": \"tenant\",\n"
        "            \"permissionGroupId\": \"some-group-id\",\n"
        "            \"name\": \"[1.1.1.1]\",\n"
        "            \"class\": \"workload\",\n"
        "            \"category\": \"cloud\",\n"
        "            \"family\": \"ip\",\n"
        "            \"group\": \"\",\n"
        "            \"order\": \"\",\n"
        "            \"kind\": \"\",\n"
        "            \"mainAttributes\": {\n"
        "               \"ipv4Addresses\": [\n"
        "                   \"1.1.1.1\",\n"
        "                   \"2.2.2.2\"\n"
        "               ],\n"
        "               \"phase\": \"testing\"\n"
        "            },\n"  // mainAttributes
        "            \"sources\": [\n"
        "               {\n"
        "                 \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229aa00\",\n"
        "                 \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7aaa00\",\n"
        "                 \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd1\",\n"
        "                 \"ttl\": 120,\n"
        "                 \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "                 \"confidence\": 500,\n"
        "                 \"attributes\": {\n"
        "                   \"color\": \"red\",\n"
        "                   \"user\": \"Omry\",\n"
        "                   \"phase\": \"testing\",\n"
        "                   \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
        "                 }\n"
        "               },\n" // source 1
        "               {\n"
        "                 \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229bb11\",\n"
        "                 \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7bbb11\",\n"
        "                 \"assetId\": \"cb068860528cb6bfb000cc35e79f11aeefed2\",\n"
        "                 \"ttl\": 120,\n"
        "                 \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "                 \"confidence\": 600,\n"
        "                 \"attributes\": {\n"
        "                   \"color\": \"white\",\n"
        "                   \"user\": \"Max\",\n"
        "                   \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
        "                  }\n"
        "               }\n" // source 2
        "            ]\n" // sources
        "          }\n" // asset 1
        "        ],\n" // asset collection
        "        \"status\": \"done\",\n"
        "        \"totalNumAssets\": 2,\n"
        "        \"cursor\": \"start\"\n"
        "      }\n" // response
        "    },\n" // queryresponse 1
        "    {\n"
        "      \"index\": 3,\n"
        "      \"response\": {\n"
        "        \"assetCollections\": [\n"
        "          {\n"
        "            \"schemaVersion\": 1,\n"
        "            \"assetType\": \"workload-cloud-ip\",\n"
        "            \"assetTypeSchemaVersion\": 1,\n"
        "            \"permissionType\": \"tenant\",\n"
        "            \"permissionGroupId\": \"some-group-id\",\n"
        "            \"name\": \"[2.2.2.2]\",\n"
        "            \"class\": \"workload\",\n"
        "            \"category\": \"iot\",\n"
        "            \"family\": \"ip\",\n"
        "            \"group\": \"\",\n"
        "            \"order\": \"\",\n"
        "            \"kind\": \"\",\n"
        "            \"mainAttributes\": {\n"
        "               \"ipv4Addresses\": [\n"
        "                   \"1.1.1.1\",\n"
        "                   \"2.2.2.2\"\n"
        "               ],\n"
        "               \"phase\": \"testing\"\n"
        "            },\n"  // mainAttributes
        "            \"sources\": [\n"
        "               {\n"
        "                 \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229aa00\",\n"
        "                 \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7aaa00\",\n"
        "                 \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd1\",\n"
        "                 \"ttl\": 120,\n"
        "                 \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "                 \"confidence\": 500,\n"
        "                 \"attributes\": {\n"
        "                   \"color\": \"red\",\n"
        "                   \"user\": \"Omry2\",\n"
        "                   \"phase\": \"testing2\",\n"
        "                   \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
        "                 }\n"
        "               },\n" // source 1
        "               {\n"
        "                 \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229bb11\",\n"
        "                 \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7bbb11\",\n"
        "                 \"assetId\": \"cb068860528cb6bfb000cc35e79f11aeefed2\",\n"
        "                 \"ttl\": 120,\n"
        "                 \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "                 \"confidence\": 600,\n"
        "                 \"attributes\": {\n"
        "                   \"color\": \"white\",\n"
        "                   \"user\": \"Max\",\n"
        "                   \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
        "                  }\n"
        "               }\n" // source 2
        "            ]\n" // sources
        "          }\n" // asset 1
        "        ],\n" // asset collection
        "        \"status\": \"done\",\n"
        "        \"totalNumAssets\": 2,\n"
        "        \"cursor\": \"start\"\n"
        "      }\n" // response
        "    }\n" // queryresponse 1
        "  ]\n" // queryresponses
        "}\n"
    );
    Intelligence::Response response(response_str, 4, true);

    EXPECT_CALL(intelligence_mock, getResponse(_, _, _, _, _)
    ).WillOnce(Return(response));

    auto maybe_ans = intell->queryIntelligence<Profile>(requests);
    EXPECT_TRUE(maybe_ans.ok());
    auto vec = maybe_ans.unpack();
    EXPECT_EQ(vec.size(), 4u);
    EXPECT_FALSE(vec[0].ok());
    EXPECT_TRUE(vec[1].ok());
    EXPECT_FALSE(vec[2].ok());
    EXPECT_TRUE(vec[3].ok());

    auto assets1_vec = vec[1].unpack();
    EXPECT_EQ(assets1_vec.size(), 1u);
    auto iter = assets1_vec.begin();
    EXPECT_EQ(iter->getData().begin()->getUser().toString(), "Omry");
    EXPECT_EQ(iter->getData().begin()->getPhase().toString(), "testing");

    auto assets3_vec = vec[3].unpack();
    EXPECT_EQ(assets1_vec.size(), 1u);
    iter = assets3_vec.begin();
    EXPECT_EQ(iter->getData().begin()->getUser().toString(), "Omry2");
    EXPECT_EQ(iter->getData().begin()->getPhase().toString(), "testing2");
}

TEST_F(IntelligenceComponentTestV2, fakeOnlineIntelligenceTest)
{
    I_Intelligence_IS_V2 *intell = Singleton::Consume<I_Intelligence_IS_V2>::by<IntelligenceComponentTestV2>();
    QueryRequest request(Condition::EQUALS, "category", "cloud", true);

    string response_str(
    "{\n"
    "  \"assetCollections\": [\n"
    "    {\n"
    "      \"schemaVersion\": 1,\n"
    "      \"assetType\": \"workload-cloud-fake-online-test\",\n"
    "      \"assetTypeSchemaVersion\": 1,\n"
    "      \"permissionType\": \"tenant\",\n"
    "      \"permissionGroupId\": \"fake-online-test-group\",\n"
    "      \"name\": \"fake-online-test-asset\",\n"
    "      \"class\": \"workload\",\n"
    "      \"category\": \"cloud\",\n"
    "      \"family\": \"fake-online-test\",\n"
    "      \"mainAttributes\": {\n"
    "          \"ipv4Addresses\": \"1.1.1.1\",\n"
    "          \"phase\": \"testing\"\n"
    "      },\n"
    "      \"sources\": [\n"
    "        {\n"
    "          \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229aa00\",\n"
    "          \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7aaa00\",\n"
    "          \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd1\",\n"
    "          \"ttl\": 120,\n"
    "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
    "          \"confidence\": 500,\n"
    "          \"attributes\": {\n"
    "            \"phase\": \"testing\",\n"
    "            \"user\": \"Omry\",\n"
    "            \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
    "          }\n"
    "        }\n"
    "      ]\n"
    "    }\n"
    "  ],\n"
    "  \"status\": \"done\",\n"
    "  \"totalNumAssets\": 2,\n"
    "  \"cursor\": \"start\"\n"
    "}\n"
    );

    EXPECT_CALL(mock_rest, getListeningPort()).WillOnce(Return(8888));

    MessageMetadata md;
    EXPECT_CALL(messaging_mock, sendSyncMessage(HTTPMethod::POST, _, _, MessageCategory::INTELLIGENCE, _)
    ).WillOnce(DoAll(SaveArg<4>(&md), Return(HTTPResponse(HTTPStatusCode::HTTP_OK, response_str))));

    auto maybe_ans = intell->queryIntelligence<Profile>(request);
    EXPECT_TRUE(maybe_ans.ok());
    auto vec = maybe_ans.unpack();
    EXPECT_EQ(vec.size(), 1u);
    auto iter = vec.begin();
    EXPECT_EQ(iter->getData().begin()->getUser().toString(), "Omry");
    EXPECT_EQ(iter->getData().begin()->getPhase().toString(), "testing");
    EXPECT_FALSE(md.getConnectionFlags().isSet(MessageConnectionConfig::UNSECURE_CONN));
}

TEST_F(IntelligenceComponentTestV2, fakeLocalIntelligenceTest)
{
    stringstream configuration;
    configuration << "{";
    configuration << "  \"agentSettings\":[";
    configuration << "    {\"key\":\"agent.config.useLocalIntelligence\",\"id\":\"id1\",\"value\":\"true\"}";
    configuration << "  ],";
    configuration << "  \"intelligence\":{";
    configuration << "    \"local intelligence server ip\":\"127.0.0.1\",";
    configuration << "    \"local intelligence server primary port\":9090";
    configuration << "  }";
    configuration << "}";
    Singleton::Consume<Config::I_Config>::from(conf)->loadConfiguration(configuration);

    I_Intelligence_IS_V2 *intell = Singleton::Consume<I_Intelligence_IS_V2>::by<IntelligenceComponentTestV2>();
    QueryRequest request(Condition::EQUALS, "category", "cloud", true);


    string response_str(
    "{\n"
    "  \"assetCollections\": [\n"
    "    {\n"
    "      \"schemaVersion\": 1,\n"
    "      \"assetType\": \"workload-cloud-fake-online-test\",\n"
    "      \"assetTypeSchemaVersion\": 1,\n"
    "      \"permissionType\": \"tenant\",\n"
    "      \"permissionGroupId\": \"fake-online-test-group\",\n"
    "      \"name\": \"fake-online-test-asset\",\n"
    "      \"class\": \"workload\",\n"
    "      \"category\": \"cloud\",\n"
    "      \"family\": \"fake-online-test\",\n"
    "      \"mainAttributes\": {\n"
    "          \"ipv4Addresses\": \"1.1.1.1\",\n"
    "          \"phase\": \"testing\"\n"
    "      },\n"
    "      \"sources\": [\n"
    "        {\n"
    "          \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229aa00\",\n"
    "          \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7aaa00\",\n"
    "          \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd1\",\n"
    "          \"ttl\": 120,\n"
    "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
    "          \"confidence\": 500,\n"
    "          \"attributes\": {\n"
    "            \"phase\": \"testing\",\n"
    "            \"user\": \"Omry\",\n"
    "            \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
    "          }\n"
    "        }\n"
    "      ]\n"
    "    }\n"
    "  ],\n"
    "  \"status\": \"done\",\n"
    "  \"totalNumAssets\": 2,\n"
    "  \"cursor\": \"start\"\n"
    "}\n"
    );

    MessageMetadata md;

    EXPECT_CALL(mock_rest, getListeningPort()).WillOnce(Return(8888));

    EXPECT_CALL(messaging_mock, sendSyncMessage(HTTPMethod::POST, _, _, MessageCategory::INTELLIGENCE, _)
    ).WillOnce(DoAll(SaveArg<4>(&md), Return(HTTPResponse(HTTPStatusCode::HTTP_OK, response_str))));

    auto maybe_ans = intell->queryIntelligence<Profile>(request);
    EXPECT_TRUE(maybe_ans.ok());

    EXPECT_EQ(md.getHostName(), "127.0.0.1");
    EXPECT_TRUE(md.getConnectionFlags().isSet(MessageConnectionConfig::UNSECURE_CONN));
}

TEST_F(IntelligenceComponentTestV2, multiAssetsIntelligenceTest)
{
    I_Intelligence_IS_V2 *intell = Singleton::Consume<I_Intelligence_IS_V2>::by<IntelligenceComponentTestV2>();
    QueryRequest request(Condition::EQUALS, "category", "cloud", true);

    string response_str1(
    "{\n"
        "  \"assetCollections\": [\n"
        "    {\n"
        "      \"schemaVersion\": 1,\n"
        "      \"assetType\": \"workload-cloud-fake-online-test\",\n"
        "      \"assetTypeSchemaVersion\": 1,\n"
        "      \"permissionType\": \"tenant\",\n"
        "      \"permissionGroupId\": \"fake-online-test-group\",\n"
        "      \"name\": \"fake-online-test-asset-1\",\n"
        "      \"class\": \"workload\",\n"
        "      \"category\": \"cloud\",\n"
        "      \"family\": \"fake-online-test\",\n"
        "      \"mainAttributes\": {\n"
        "          \"ipv4Addresses\": \"1.1.1.1\",\n"
        "          \"phase\": \"testing\"\n"
        "      },\n"
        "      \"sources\": [\n"
        "        {\n"
        "          \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229aa00\",\n"
        "          \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7aaa00\",\n"
        "          \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd0\",\n"
        "          \"ttl\": 120,\n"
        "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "          \"confidence\": 500,\n"
        "          \"attributes\": {\n"
        "            \"phase\": \"fake online test1\",\n"
        "            \"user\": \"Omry\",\n"
        "            \"owners\": { \"names\": [ { \"name1\": \"no\", \"name2\": \"one\" } ] }\n"
        "          }\n"
        "        },\n"
        "        {\n"
        "          \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229aa01\",\n"
        "          \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7aaa01\",\n"
        "          \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd1\",\n"
        "          \"ttl\": 120,\n"
        "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "          \"confidence\": 500,\n"
        "          \"attributes\": {\n"
        "            \"phase\": \"fake online test1\",\n"
        "            \"user\": \"Max\",\n"
        "            \"owners\": { \"names\": [ { \"name1\": \"every\", \"name2\": \"one\" } ] }\n"
        "          }\n"
        "        },\n"
        "        {\n"
        "          \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229aa01\",\n"
        "          \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7aaa01\",\n"
        "          \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd1\",\n"
        "          \"ttl\": 120,\n"
        "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "          \"confidence\": 500,\n"
        "          \"attributes\": {\n"
        "            \"phase\": \"fake online test1\",\n"
        "            \"user\": \"Roy\",\n"
        "            \"owners\": { \"names\": [ { \"name1\": \"Aviv\", \"name2\": \"Cochavi\" } ] }\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    },\n"
        "    {\n"
        "      \"schemaVersion\": 1,\n"
        "      \"assetType\": \"workload-cloud-fake-online-test\",\n"
        "      \"assetTypeSchemaVersion\": 1,\n"
        "      \"permissionType\": \"tenant\",\n"
        "      \"permissionGroupId\": \"fake-online-test-group\",\n"
        "      \"name\": \"fake-online-test-asset-2\",\n"
        "      \"class\": \"workload\",\n"
        "      \"category\": \"cloud\",\n"
        "      \"family\": \"fake-online-test\",\n"
        "      \"mainAttributes\": {\n"
        "          \"ipv4Addresses\": \"1.1.1.2\",\n"
        "          \"phase\": \"testing\"\n"
        "      },\n"
        "      \"sources\": [\n"
        "        {\n"
        "          \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229aa02\",\n"
        "          \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7aaa02\",\n"
        "          \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd2\",\n"
        "          \"ttl\": 120,\n"
        "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "          \"confidence\": 500,\n"
        "          \"attributes\": {\n"
        "            \"phase\": \"fake online test2\",\n"
        "            \"user\": \"Daniel\",\n"
        "            \"owners\": { \"names\": [ { \"name1\": \"Omry\", \"name2\": \"David\" } ] }\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    },\n"
        "    {\n"
        "      \"schemaVersion\": 1,\n"
        "      \"assetType\": \"workload-cloud-fake-online-test\",\n"
        "      \"assetTypeSchemaVersion\": 1,\n"
        "      \"permissionType\": \"tenant\",\n"
        "      \"permissionGroupId\": \"fake-online-test-group\",\n"
        "      \"name\": \"fake-online-test-asset-2\",\n"
        "      \"class\": \"workload\",\n"
        "      \"category\": \"cloud\",\n"
        "      \"family\": \"fake-online-test\",\n"
        "      \"mainAttributes\": {\n"
        "          \"ipv4Addresses\": \"1.1.1.3\",\n"
        "          \"phase\": \"testing\"\n"
        "      },\n"
        "      \"sources\": [\n"
        "        {\n"
        "          \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229aa03\",\n"
        "          \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7aaa03\",\n"
        "          \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd3\",\n"
        "          \"ttl\": 120,\n"
        "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "          \"confidence\": 500,\n"
        "          \"attributes\": {\n"
        "            \"phase\": \"fake online test3\",\n"
        "            \"user\": \"Oren\",\n"
        "            \"owners\": { \"names\": [ { \"name1\": \"Omry\", \"name2\": \"David\" } ] }\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    }\n"
        "  ],\n"
        "  \"status\": \"done\",\n"
        "  \"totalNumAssets\": 2\n"
    "}\n"
    );

    EXPECT_CALL(mock_rest, getListeningPort()).WillOnce(Return(8888));

    EXPECT_CALL(messaging_mock, sendSyncMessage(HTTPMethod::POST, _, _, MessageCategory::INTELLIGENCE, _)
    ).WillOnce(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, response_str1)));

    auto maybe_ans = intell->queryIntelligence<Profile>(request);
    EXPECT_TRUE(maybe_ans.ok());
    auto vec = maybe_ans.unpack();
    EXPECT_EQ(vec.size(), 3u);

    auto iter = vec.begin();

    auto asset_sources_vec = iter->getData();
    auto data_it = asset_sources_vec.begin();
    EXPECT_EQ(data_it->getUser().toString(), "Omry");
    EXPECT_EQ(data_it->getPhase().toString(), "fake online test1");

    data_it++;
    EXPECT_EQ(data_it->getUser().toString(), "Max");
    EXPECT_EQ(data_it->getPhase().toString(), "fake online test1");

    data_it++;
    EXPECT_EQ(data_it->getUser().toString(), "Roy");
    EXPECT_EQ(data_it->getPhase().toString(), "fake online test1");

    iter++;
    EXPECT_EQ(iter->getData().begin()->getUser().toString(), "Daniel");
    EXPECT_EQ(iter->getData().begin()->getPhase().toString(), "fake online test2");

    iter++;
    EXPECT_EQ(iter->getData().begin()->getUser().toString(), "Oren");
    EXPECT_EQ(iter->getData().begin()->getPhase().toString(), "fake online test3");
}

TEST_F(IntelligenceComponentTestV2, inProgressQueryTest)
{
    I_Intelligence_IS_V2 *intell = Singleton::Consume<I_Intelligence_IS_V2>::by<IntelligenceComponentTestV2>();
    QueryRequest request(Condition::EQUALS, "category", "cloud", true);

    string in_progress_response_str(
    "{\n"
        "  \"assetCollections\": [\n"
        "    {\n"
        "      \"schemaVersion\": 1,\n"
        "      \"assetType\": \"workload-cloud-fake-online-test\",\n"
        "      \"assetTypeSchemaVersion\": 1,\n"
        "      \"permissionType\": \"tenant\",\n"
        "      \"permissionGroupId\": \"fake-online-test-group\",\n"
        "      \"name\": \"fake-online-test-asset\",\n"
        "      \"class\": \"workload\",\n"
        "      \"category\": \"cloud\",\n"
        "      \"family\": \"fake-online-test\",\n"
        "      \"mainAttributes\": {\n"
        "          \"ipv4Addresses\": \"1.1.1.1\",\n"
        "          \"phase\": \"testing\"\n"
        "      },\n"
        "      \"sources\": [\n"
        "        {\n"
        "          \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229aa00\",\n"
        "          \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7aaa00\",\n"
        "          \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd1\",\n"
        "          \"ttl\": 120,\n"
        "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "          \"confidence\": 500,\n"
        "          \"attributes\": {\n"
        "            \"phase\": \"fake online test\",\n"
        "            \"user\": \"Omry\",\n"
        "            \"owners\": { \"names\": [ { \"name1\": \"no\", \"name2\": \"one\" } ] }\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    }\n"
        "  ],\n"
        "  \"status\": \"inProgress\",\n"
        "  \"totalNumAssets\": 1,\n"
        "  \"cursor\": \"start\"\n"
    "}\n"
    );

    string done_response_str(
    "{\n"
        "  \"assetCollections\": [\n"
        "    {\n"
        "      \"schemaVersion\": 1,\n"
        "      \"assetType\": \"workload-cloud-fake-online-test\",\n"
        "      \"assetTypeSchemaVersion\": 1,\n"
        "      \"permissionType\": \"tenant\",\n"
        "      \"permissionGroupId\": \"fake-online-test-group\",\n"
        "      \"name\": \"fake-online-test-asset\",\n"
        "      \"class\": \"workload\",\n"
        "      \"category\": \"cloud\",\n"
        "      \"family\": \"fake-online-test\",\n"
        "      \"mainAttributes\": {\n"
        "          \"ipv4Addresses\": \"1.1.1.1\",\n"
        "          \"phase\": \"testing\"\n"
        "      },\n"
        "      \"sources\": [\n"
        "        {\n"
        "          \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229aa00\",\n"
        "          \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7aaa00\",\n"
        "          \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd1\",\n"
        "          \"ttl\": 120,\n"
        "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "          \"confidence\": 500,\n"
        "          \"attributes\": {\n"
        "            \"phase\": \"fake online test\",\n"
        "            \"user\": \"Omry\",\n"
        "            \"owners\": { \"names\": [ { \"name1\": \"no\", \"name2\": \"one\" } ] }\n"
        "          }\n"
        "        },\n"
        "        {\n"
        "          \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229bb11\",\n"
        "          \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7bbb11\",\n"
        "          \"assetId\": \"cb068860528cb6bfb000cc35e79f11aeefed2\",\n"
        "          \"ttl\": 120,\n"
        "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "          \"confidence\": 600,\n"
        "          \"attributes\": {\n"
        "            \"phase\": \"fake online test\",\n"
        "            \"user\": \"Max\",\n"
        "            \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    }\n"
        "  ],\n"
        "  \"status\": \"done\",\n"
        "  \"totalNumAssets\": 2\n"
    "}\n"
    );

    EXPECT_CALL(mock_rest, getListeningPort()).Times(2).WillRepeatedly(Return(8888));

    EXPECT_CALL(messaging_mock, sendSyncMessage(HTTPMethod::POST, _, _, MessageCategory::INTELLIGENCE, _)
    ).WillOnce(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, in_progress_response_str))
    ).WillOnce(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, done_response_str)));

    EXPECT_CALL(
        mock_ml,
        yield(true)
    );

    auto maybe_ans = intell->queryIntelligence<Profile>(request);
    EXPECT_TRUE(maybe_ans.ok());
    auto vec = maybe_ans.unpack();
    EXPECT_EQ(vec.size(), 1u);
    vector<AssetReply<Profile>>::iterator assets_iter = vec.begin();
    vector<SerializableAssetSource<Profile>>::const_iterator sources_iter = assets_iter->getSources().begin();
    EXPECT_EQ(sources_iter->getAttributes().begin()->getUser().toString(), "Omry");
    sources_iter++;
    EXPECT_EQ(sources_iter->getAttributes().begin()->getUser().toString(), "Max");
}

TEST_F(IntelligenceComponentTestV2, pagingQueryTest)
{
    I_Intelligence_IS_V2 *intell = Singleton::Consume<I_Intelligence_IS_V2>::by<IntelligenceComponentTestV2>();
    QueryRequest request(Condition::EQUALS, "category", "cloud", true);
    request.activatePaging();

    string paging_done_response_str(
    "{\n"
        "  \"assetCollections\": [\n"
        "    {\n"
        "      \"schemaVersion\": 1,\n"
        "      \"assetType\": \"workload-cloud-fake-online-test\",\n"
        "      \"assetTypeSchemaVersion\": 1,\n"
        "      \"permissionType\": \"tenant\",\n"
        "      \"permissionGroupId\": \"fake-online-test-group\",\n"
        "      \"name\": \"fake-online-test-asset\",\n"
        "      \"class\": \"workload\",\n"
        "      \"category\": \"cloud\",\n"
        "      \"family\": \"fake-online-test\",\n"
        "      \"mainAttributes\": {\n"
        "          \"ipv4Addresses\": \"1.1.1.1\",\n"
        "          \"phase\": \"testing\"\n"
        "      },\n"
        "      \"sources\": [\n"
        "        {\n"
        "          \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229aa00\",\n"
        "          \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7aaa00\",\n"
        "          \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd1\",\n"
        "          \"ttl\": 120,\n"
        "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "          \"confidence\": 500,\n"
        "          \"attributes\": {\n"
        "            \"phase\": \"fake online test\",\n"
        "            \"user\": \"Omry\",\n"
        "            \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
        "          }\n"
        "        },\n"
        "        {\n"
        "          \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229bb11\",\n"
        "          \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7bbb11\",\n"
        "          \"assetId\": \"cb068860528cb6bfb000cc35e79f11aeefed2\",\n"
        "          \"ttl\": 120,\n"
        "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "          \"confidence\": 600,\n"
        "          \"attributes\": {\n"
        "            \"phase\": \"fake online test\",\n"
        "            \"user\": \"Max\",\n"
        "            \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    }\n"
        "  ],\n"
        "  \"status\": \"done\",\n"
        "  \"totalNumAssets\": 2,\n"
        "  \"cursor\": \"abcd\"\n"
    "}\n"
    );

    string paging_in_progress_response_str1(
    "{\n"
        "  \"assetCollections\": [\n"
        "    {\n"
        "      \"schemaVersion\": 1,\n"
        "      \"assetType\": \"workload-cloud-fake-online-test\",\n"
        "      \"assetTypeSchemaVersion\": 1,\n"
        "      \"permissionType\": \"tenant\",\n"
        "      \"permissionGroupId\": \"fake-online-test-group\",\n"
        "      \"name\": \"fake-online-test-asset1\",\n"
        "      \"class\": \"workload\",\n"
        "      \"category\": \"cloud\",\n"
        "      \"family\": \"fake-online-test1\",\n"
        "      \"mainAttributes\": {\n"
        "          \"ipv4Addresses\": \"1.1.1.1\",\n"
        "          \"phase\": \"testing\"\n"
        "      },\n"
        "      \"sources\": [\n"
        "        {\n"
        "          \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229aa00\",\n"
        "          \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7aaa00\",\n"
        "          \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd1\",\n"
        "          \"ttl\": 120,\n"
        "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "          \"confidence\": 500,\n"
        "          \"attributes\": {\n"
        "            \"phase\": \"fake online test1\",\n"
        "            \"user\": \"Omry\",\n"
        "            \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    }\n"
        "  ],\n"
        "  \"status\": \"inProgress\",\n"
        "  \"totalNumAssets\": 2,\n"
        "  \"cursor\": \"abcd\"\n"
    "}\n"
    );

    string paging_in_progress_response_str2(
    "{\n"
        "  \"assetCollections\": [\n"
        "    {\n"
        "      \"schemaVersion\": 1,\n"
        "      \"assetType\": \"workload-cloud-fake-online-test\",\n"
        "      \"assetTypeSchemaVersion\": 1,\n"
        "      \"permissionType\": \"tenant\",\n"
        "      \"permissionGroupId\": \"fake-online-test-group\",\n"
        "      \"name\": \"fake-online-test-asset1\",\n"
        "      \"class\": \"workload\",\n"
        "      \"category\": \"cloud\",\n"
        "      \"family\": \"fake-online-test1\",\n"
        "      \"mainAttributes\": {\n"
        "          \"ipv4Addresses\": \"1.1.1.1\",\n"
        "          \"phase\": \"testing\"\n"
        "      },\n"
        "      \"sources\": [\n"
        "        {\n"
        "          \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229aa00\",\n"
        "          \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7aaa00\",\n"
        "          \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd1\",\n"
        "          \"ttl\": 120,\n"
        "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "          \"confidence\": 500,\n"
        "          \"attributes\": {\n"
        "            \"phase\": \"fake online test1\",\n"
        "            \"user\": \"Omry\",\n"
        "            \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    },\n"
        "    {\n"
        "      \"schemaVersion\": 1,\n"
        "      \"assetType\": \"workload-cloud-fake-online-test\",\n"
        "      \"assetTypeSchemaVersion\": 1,\n"
        "      \"permissionType\": \"tenant\",\n"
        "      \"permissionGroupId\": \"fake-online-test-group\",\n"
        "      \"name\": \"fake-online-test-asset2\",\n"
        "      \"class\": \"workload\",\n"
        "      \"category\": \"cloud\",\n"
        "      \"family\": \"fake-online-test2\",\n"
        "      \"mainAttributes\": {\n"
        "          \"ipv4Addresses\": \"1.1.1.2\",\n"
        "          \"phase\": \"testing\"\n"
        "      },\n"
        "      \"sources\": [\n"
        "        {\n"
        "          \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229aa00\",\n"
        "          \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7aaa00\",\n"
        "          \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd1\",\n"
        "          \"ttl\": 120,\n"
        "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "          \"confidence\": 500,\n"
        "          \"attributes\": {\n"
        "            \"phase\": \"fake online test2\",\n"
        "            \"user\": \"Max\",\n"
        "            \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    }\n"
        "  ],\n"
        "  \"status\": \"done\",\n"
        "  \"totalNumAssets\": 2,\n"
        "  \"cursor\": \"efgh\"\n"
    "}\n"
    );

    EXPECT_CALL(mock_rest, getListeningPort()).Times(3).WillRepeatedly(Return(8888));

    EXPECT_CALL(messaging_mock, sendSyncMessage(HTTPMethod::POST, _, _, MessageCategory::INTELLIGENCE, _)
    ).WillOnce(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, paging_in_progress_response_str1)));

    request.setAssetsLimit(2);
    EXPECT_EQ(request.getAssetsLimit(), 2u);
    auto maybe_ans1 = intell->queryIntelligence<Profile>(request);
    EXPECT_TRUE(maybe_ans1.ok());
    auto vec1 = maybe_ans1.unpack();
    EXPECT_EQ(vec1.size(), 1u);
    EXPECT_EQ(request.isPagingFinished(), false);

    EXPECT_CALL(messaging_mock, sendSyncMessage(HTTPMethod::POST, _, _, MessageCategory::INTELLIGENCE, _)
    ).WillOnce(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, paging_in_progress_response_str2)));

    auto maybe_ans2 = intell->queryIntelligence<Profile>(request);
    EXPECT_TRUE(maybe_ans2.ok());
    auto vec2 = maybe_ans2.unpack();
    EXPECT_EQ(vec2.size(), 2u);
    EXPECT_EQ(request.isPagingFinished(), false);

    EXPECT_CALL(messaging_mock, sendSyncMessage(HTTPMethod::POST, _, _, MessageCategory::INTELLIGENCE, _)
    ).WillOnce(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, paging_done_response_str)));

    auto maybe_ans3 = intell->queryIntelligence<Profile>(request);
    if (!maybe_ans3.ok()) cout << maybe_ans3.getErr() + "\n";
    EXPECT_TRUE(maybe_ans3.ok());
    auto vec3 = maybe_ans3.unpack();
    EXPECT_EQ(vec3.size(), 1u);
    EXPECT_EQ(request.isPagingFinished(), true);

    vector<AssetReply<Profile>>::iterator assets_iter = vec3.begin();
    vector<SerializableAssetSource<Profile>>::const_iterator sources_iter = assets_iter->getSources().begin();
    EXPECT_EQ(sources_iter->getAttributes().begin()->getUser().toString(), "Omry");
}

TEST_F(IntelligenceComponentTestV2, bulkOnlineIntelligenceTest)
{
    I_Intelligence_IS_V2 *intell = Singleton::Consume<I_Intelligence_IS_V2>::by<IntelligenceComponentTestV2>();
    vector<QueryRequest> requests;
    requests.emplace_back(Condition::EQUALS, "category", "whatever", true);
    requests.emplace_back(Condition::EQUALS, "category", "cloud", true);
    requests.emplace_back(Condition::EQUALS, "category", "nothing", true);
    requests.emplace_back(Condition::EQUALS, "category", "iot", true);

    string response_str(
        "{\n"
        "  \"errors\": [\n"
        "    {\n"
        "      \"index\": 0,\n"
        "      \"statusCode\": 400,\n"
        "      \"message\": \"Bad request. Error: Invalid cursor\"\n"
        "    },"
        "    {\n"
        "      \"index\": 2,\n"
        "      \"statusCode\": 405,\n"
        "      \"message\": \"Bad request. Error: Something else\"\n"
        "    }"
        "  ],\n" // errors
        "  \"queriesResponse\": [\n"
        "    {\n"
        "      \"index\": 1,\n"
        "      \"response\": {\n"
        "        \"assetCollections\": [\n"
        "          {\n"
        "            \"schemaVersion\": 1,\n"
        "            \"assetType\": \"workload-cloud-ip\",\n"
        "            \"assetTypeSchemaVersion\": 1,\n"
        "            \"permissionType\": \"tenant\",\n"
        "            \"permissionGroupId\": \"some-group-id\",\n"
        "            \"name\": \"[1.1.1.1]\",\n"
        "            \"class\": \"workload\",\n"
        "            \"category\": \"cloud\",\n"
        "            \"family\": \"ip\",\n"
        "            \"group\": \"\",\n"
        "            \"order\": \"\",\n"
        "            \"kind\": \"\",\n"
        "            \"mainAttributes\": {\n"
        "               \"ipv4Addresses\": [\n"
        "                   \"1.1.1.1\",\n"
        "                   \"2.2.2.2\"\n"
        "               ],\n"
        "               \"phase\": \"testing\"\n"
        "            },\n"  // mainAttributes
        "            \"sources\": [\n"
        "               {\n"
        "                 \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229aa00\",\n"
        "                 \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7aaa00\",\n"
        "                 \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd1\",\n"
        "                 \"ttl\": 120,\n"
        "                 \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "                 \"confidence\": 500,\n"
        "                 \"attributes\": {\n"
        "                   \"color\": \"red\",\n"
        "                   \"user\": \"Omry\",\n"
        "                   \"phase\": \"testing\",\n"
        "                   \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
        "                 }\n"
        "               },\n" // source 1
        "               {\n"
        "                 \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229bb11\",\n"
        "                 \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7bbb11\",\n"
        "                 \"assetId\": \"cb068860528cb6bfb000cc35e79f11aeefed2\",\n"
        "                 \"ttl\": 120,\n"
        "                 \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "                 \"confidence\": 600,\n"
        "                 \"attributes\": {\n"
        "                   \"color\": \"white\",\n"
        "                   \"user\": \"Max\",\n"
        "                   \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
        "                  }\n"
        "               }\n" // source 2
        "            ]\n" // sources
        "          }\n" // asset 1
        "        ],\n" // asset collection
        "        \"status\": \"done\",\n"
        "        \"totalNumAssets\": 2,\n"
        "        \"cursor\": \"start\"\n"
        "      }\n" // response
        "    },\n" // queryresponse 1
        "    {\n"
        "      \"index\": 3,\n"
        "      \"response\": {\n"
        "        \"assetCollections\": [\n"
        "          {\n"
        "            \"schemaVersion\": 1,\n"
        "            \"assetType\": \"workload-cloud-ip\",\n"
        "            \"assetTypeSchemaVersion\": 1,\n"
        "            \"permissionType\": \"tenant\",\n"
        "            \"permissionGroupId\": \"some-group-id\",\n"
        "            \"name\": \"[2.2.2.2]\",\n"
        "            \"class\": \"workload\",\n"
        "            \"category\": \"iot\",\n"
        "            \"family\": \"ip\",\n"
        "            \"group\": \"\",\n"
        "            \"order\": \"\",\n"
        "            \"kind\": \"\",\n"
        "            \"mainAttributes\": {\n"
        "               \"ipv4Addresses\": [\n"
        "                   \"1.1.1.1\",\n"
        "                   \"2.2.2.2\"\n"
        "               ],\n"
        "               \"phase\": \"testing\"\n"
        "            },\n"  // mainAttributes
        "            \"sources\": [\n"
        "               {\n"
        "                 \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229aa00\",\n"
        "                 \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7aaa00\",\n"
        "                 \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd1\",\n"
        "                 \"ttl\": 120,\n"
        "                 \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "                 \"confidence\": 500,\n"
        "                 \"attributes\": {\n"
        "                   \"color\": \"red\",\n"
        "                   \"user\": \"Omry2\",\n"
        "                   \"phase\": \"testing2\",\n"
        "                   \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
        "                 }\n"
        "               },\n" // source 1
        "               {\n"
        "                 \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229bb11\",\n"
        "                 \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7bbb11\",\n"
        "                 \"assetId\": \"cb068860528cb6bfb000cc35e79f11aeefed2\",\n"
        "                 \"ttl\": 120,\n"
        "                 \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "                 \"confidence\": 600,\n"
        "                 \"attributes\": {\n"
        "                   \"color\": \"white\",\n"
        "                   \"user\": \"Max\",\n"
        "                   \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
        "                  }\n"
        "               }\n" // source 2
        "            ]\n" // sources
        "          }\n" // asset 1
        "        ],\n" // asset collection
        "        \"status\": \"done\",\n"
        "        \"totalNumAssets\": 2,\n"
        "        \"cursor\": \"start\"\n"
        "      }\n" // response
        "    }\n" // queryresponse 1
        "  ]\n" // queryresponses
        "}\n"
    );
    Debug::setNewDefaultStdout(&cout);

    EXPECT_CALL(mock_rest, getListeningPort()).WillOnce(Return(8888));
    EXPECT_CALL(messaging_mock, sendSyncMessage(HTTPMethod::POST, _, _, MessageCategory::INTELLIGENCE, _)
    ).WillOnce(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, response_str)));

    auto maybe_ans = intell->queryIntelligence<Profile>(requests);
    EXPECT_TRUE(maybe_ans.ok());
    auto vec = maybe_ans.unpack();
    EXPECT_EQ(vec.size(), 4u);
    EXPECT_FALSE(vec[0].ok());
    EXPECT_TRUE(vec[1].ok());
    EXPECT_FALSE(vec[2].ok());
    EXPECT_TRUE(vec[3].ok());

    auto assets1_vec = vec[1].unpack();
    EXPECT_EQ(assets1_vec.size(), 1u);
    auto iter = assets1_vec.begin();
    EXPECT_EQ(iter->getData().begin()->getUser().toString(), "Omry");
    EXPECT_EQ(iter->getData().begin()->getPhase().toString(), "testing");

    auto assets3_vec = vec[3].unpack();
    EXPECT_EQ(assets1_vec.size(), 1u);
    iter = assets3_vec.begin();
    EXPECT_EQ(iter->getData().begin()->getUser().toString(), "Omry2");
    EXPECT_EQ(iter->getData().begin()->getPhase().toString(), "testing2");
}

TEST_F(IntelligenceComponentTestV2, ignoreInProgressQueryTest_2)
{
    string paging_in_progress_response_str(
    "{\n"
        "  \"assetCollections\": [\n"
        "    {\n"
        "      \"schemaVersion\": 1,\n"
        "      \"assetType\": \"workload-cloud-fake-online-test\",\n"
        "      \"assetTypeSchemaVersion\": 1,\n"
        "      \"permissionType\": \"tenant\",\n"
        "      \"permissionGroupId\": \"fake-online-test-group\",\n"
        "      \"name\": \"fake-online-test-asset1\",\n"
        "      \"class\": \"workload\",\n"
        "      \"category\": \"cloud\",\n"
        "      \"family\": \"fake-online-test1\",\n"
        "      \"mainAttributes\": {\n"
        "          \"deAssetId\": \"C0:3F:0E:A5:59:64_e1ea0005-6362-4a66-99bd-7f30932a2527\"\n"
        "      },\n"
        "      \"sources\": [\n"
        "        {\n"
        "          \"tenantId\": \"e1ea0005-6362-4a66-99bd-7f30932a2527\",\n"
        "          \"sourceId\": \"fog-app-msrv-iot-assets\",\n"
        "          \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd1\",\n"
        "          \"ttl\": 120,\n"
        "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "          \"confidence\": 500,\n"
        "          \"attributes\": {\n"
        "            \"phase\": \"fake online test1\",\n"
        "            \"user\": \"Omry\",\n"
        "            \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    },\n"
        "    {\n"
        "      \"schemaVersion\": 1,\n"
        "      \"assetType\": \"workload-cloud-fake-online-test\",\n"
        "      \"assetTypeSchemaVersion\": 1,\n"
        "      \"permissionType\": \"tenant\",\n"
        "      \"permissionGroupId\": \"fake-online-test-group\",\n"
        "      \"name\": \"fake-online-test-asset2\",\n"
        "      \"class\": \"workload\",\n"
        "      \"category\": \"cloud\",\n"
        "      \"family\": \"fake-online-test2\",\n"
        "      \"mainAttributes\": {\n"
        "          \"deAssetId\": \"20:F8:5E:2F:6D:4C_e1ea0005-6362-4a66-99bd-7f30932a2527\"\n"
        "      },\n"
        "      \"sources\": [\n"
        "        {\n"
        "          \"tenantId\": \"e1ea0005-6362-4a66-99bd-7f30932a2527\",\n"
        "          \"sourceId\": \"fog-app-msrv-iot-assets\",\n"
        "          \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd2\",\n"
        "          \"ttl\": 120,\n"
        "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "          \"confidence\": 500,\n"
        "          \"attributes\": {\n"
        "            \"phase\": \"fake online test2\",\n"
        "            \"user\": \"Max\",\n"
        "            \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    }\n"
        "  ],\n"
        "  \"status\": \"inProgress\",\n"
        "  \"totalNumAssets\": 2,\n"
        "  \"cursor\": \"efgh\"\n"
    "}\n"
    );

    string paging_done_response_str(
    "{\n"
        "  \"assetCollections\": [\n"
        "    {\n"
        "      \"schemaVersion\": 1,\n"
        "      \"assetType\": \"workload-cloud-fake-online-test\",\n"
        "      \"assetTypeSchemaVersion\": 1,\n"
        "      \"permissionType\": \"tenant\",\n"
        "      \"permissionGroupId\": \"fake-online-test-group\",\n"
        "      \"name\": \"fake-online-test-asset1\",\n"
        "      \"class\": \"workload\",\n"
        "      \"category\": \"cloud\",\n"
        "      \"family\": \"fake-online-test1\",\n"
        "      \"mainAttributes\": {\n"
        "          \"deAssetId\": \"C0:3F:0E:A5:59:64_e1ea0005-6362-4a66-99bd-7f30932a2527\"\n"
        "      },\n"
        "      \"sources\": [\n"
        "        {\n"
        "          \"tenantId\": \"e1ea0005-6362-4a66-99bd-7f30932a2527\",\n"
        "          \"sourceId\": \"fog-app-msrv-iot-assets\",\n"
        "          \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd1\",\n"
        "          \"ttl\": 120,\n"
        "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "          \"confidence\": 500,\n"
        "          \"attributes\": {\n"
        "            \"phase\": \"fake online test1\",\n"
        "            \"user\": \"Omry\",\n"
        "            \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    },\n"
        "    {\n"
        "      \"schemaVersion\": 1,\n"
        "      \"assetType\": \"workload-cloud-fake-online-test\",\n"
        "      \"assetTypeSchemaVersion\": 1,\n"
        "      \"permissionType\": \"tenant\",\n"
        "      \"permissionGroupId\": \"fake-online-test-group\",\n"
        "      \"name\": \"fake-online-test-asset2\",\n"
        "      \"class\": \"workload\",\n"
        "      \"category\": \"cloud\",\n"
        "      \"family\": \"fake-online-test2\",\n"
        "      \"mainAttributes\": {\n"
        "          \"deAssetId\": \"20:F8:5E:2F:6D:4C_e1ea0005-6362-4a66-99bd-7f30932a2527\"\n"
        "      },\n"
        "      \"sources\": [\n"
        "        {\n"
        "          \"tenantId\": \"e1ea0005-6362-4a66-99bd-7f30932a2527\",\n"
        "          \"sourceId\": \"fog-app-msrv-iot-assets\",\n"
        "          \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd2\",\n"
        "          \"ttl\": 120,\n"
        "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "          \"confidence\": 500,\n"
        "          \"attributes\": {\n"
        "            \"phase\": \"fake online test2\",\n"
        "            \"user\": \"Max\",\n"
        "            \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    }\n"
        "  ],\n"
        "  \"status\": \"done\",\n"
        "  \"totalNumAssets\": 2,\n"
        "  \"cursor\": \"efgh\"\n"
    "}\n"
    );

    EXPECT_CALL(mock_rest, getListeningPort()).Times(2).WillRepeatedly(Return(8888));

    EXPECT_CALL(messaging_mock, sendSyncMessage(HTTPMethod::POST, _, _, MessageCategory::INTELLIGENCE, _))
        .WillOnce(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, paging_in_progress_response_str)))
        .WillOnce(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, paging_done_response_str)));

    I_Intelligence_IS_V2 *intell = Singleton::Consume<I_Intelligence_IS_V2>::by<IntelligenceComponentTestV2>();
    QueryRequest request(Condition::EQUALS, "category", "cloud", true, AttributeKeyType::NONE);
    request.activatePaging();
    request.setAssetsLimit(10);
    vector<string> objects_ids;
    do {
        auto object_result = intell->queryIntelligence<Profile>(request, true);
        if (!object_result.ok()) {
            if (object_result.getErr() == "Query intelligence response with InProgress status") continue;
            break;
        }

        if ((*object_result).empty()) break;

        for (const AssetReply<Profile> &current_object : *object_result) {
            if (current_object.getMainAttributes().empty()) {
                continue;
            }
            const string &id = current_object.getMainAttributes().begin()->second[0];
            objects_ids.push_back(id);
        }
    } while (!request.isPagingFinished());

    EXPECT_EQ(objects_ids.size(), 2u);
}

TEST_F(IntelligenceComponentTestV2, foghealthy)
{
    Debug::setUnitTestFlag(D_INTELLIGENCE, Debug::DebugLevel::TRACE);
    I_Intelligence_IS_V2 *intell = Singleton::Consume<I_Intelligence_IS_V2>::by<IntelligenceComponentTestV2>();

    HTTPResponse fog_res(
        HTTPStatusCode::HTTP_OK,
        string(
            "{"
            "    \"up\": true,"
            "    \"timestamp\":\"\""
            "}"
        )
    );

    EXPECT_CALL(
        messaging_mock,
        sendSyncMessage(HTTPMethod::GET, "/access-manager/health/live", _, MessageCategory::INTELLIGENCE, _)
    ).WillOnce(Return(fog_res));

    EXPECT_TRUE(intell->isIntelligenceHealthy());
}

TEST_F(IntelligenceComponentTestV2, localIntelligenceHealthy)
{
    Debug::setUnitTestFlag(D_INTELLIGENCE, Debug::DebugLevel::TRACE);
    stringstream configuration;
    configuration << "{";
    configuration << "  \"agentSettings\":[";
    configuration << "    {\"key\":\"agent.config.useLocalIntelligence\",\"id\":\"id1\",\"value\":\"true\"}";
    configuration << "  ],";
    configuration << "  \"intelligence\":{";
    configuration << "    \"local intelligence server ip\":\"127.0.0.1\",";
    configuration << "    \"local intelligence server primary port\":9090";
    configuration << "  }";
    configuration << "}";
    Singleton::Consume<Config::I_Config>::from(conf)->loadConfiguration(configuration);

    I_Intelligence_IS_V2 *intell = Singleton::Consume<I_Intelligence_IS_V2>::by<IntelligenceComponentTestV2>();

    string localHealthy(
            "{\n"
            "  \"healthy\": true\n"
            "}\n"
    );

    EXPECT_CALL(
        messaging_mock,
        sendSyncMessage(HTTPMethod::GET, "/show-health", _, MessageCategory::INTELLIGENCE, _)
    ).WillOnce(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, localHealthy)));

    EXPECT_CALL(mock_rest, getListeningPort()).Times(1).WillRepeatedly(Return(8888));

    EXPECT_TRUE(intell->isIntelligenceHealthy());
}
