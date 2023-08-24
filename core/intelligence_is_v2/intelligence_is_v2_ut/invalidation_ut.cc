#include "intelligence_invalidation.h"

#include "cptest.h"
#include "mock/mock_messaging.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_time_get.h"
#include "mock/mock_rest_api.h"
#include "mock/mock_agent_details.h"
#include "intelligence_comp_v2.h"
#include "config_component.h"

using namespace std;
using namespace Intelligence;
using namespace testing;

static const string invalidation_uri = "/api/v2/intelligence/invalidation";

TEST(InvalidationBasic, SettersAndGetters)
{
    Invalidation invalidation("aaa");

    EXPECT_EQ(invalidation.getClassifier(ClassifierType::CLASS), "aaa");
    EXPECT_EQ(invalidation.getClassifier(ClassifierType::CATEGORY), "");
    EXPECT_EQ(invalidation.getClassifier(ClassifierType::FAMILY), "");
    EXPECT_EQ(invalidation.getClassifier(ClassifierType::GROUP), "");
    EXPECT_EQ(invalidation.getClassifier(ClassifierType::ORDER), "");
    EXPECT_EQ(invalidation.getClassifier(ClassifierType::KIND), "");

    EXPECT_FALSE(invalidation.getStringAttr("attr1").ok());
    EXPECT_FALSE(invalidation.getStringSetAttr("attr2").ok());
    EXPECT_FALSE(invalidation.getSourceId().ok());
    EXPECT_FALSE(invalidation.getObjectType().ok());

    set<string> vals = { "2", "3" };

    invalidation
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setStringAttr("attr1", "1")
        .setStringSetAttr("attr2", vals)
        .setSourceId("id")
        .setObjectType(Intelligence::ObjectType::ASSET);

    EXPECT_EQ(invalidation.getClassifier(ClassifierType::CATEGORY), "bbb");
    EXPECT_EQ(invalidation.getClassifier(ClassifierType::FAMILY), "ccc");
    EXPECT_EQ(invalidation.getStringAttr("attr1").unpack(), "1");
    EXPECT_EQ(invalidation.getStringSetAttr("attr2").unpack(), vals);
    EXPECT_EQ(invalidation.getSourceId().unpack(), "id");
    EXPECT_EQ(invalidation.getObjectType().unpack(), Intelligence::ObjectType::ASSET);
}

TEST(InvalidationBasic, Matching)
{
    set<string> vals = { "2", "3" };
    auto base_invalidation = Invalidation("aaa")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setStringAttr("attr1", "1")
        .setStringSetAttr("attr2", vals);


    auto matching_invalidation = Invalidation("aaa")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::GROUP, "ddd")
        .setStringAttr("attr1", "1")
        .setStringSetAttr("attr2", vals)
        .setStringAttr("attr3", "6")
        .setSourceId("id")
        .setObjectType(Intelligence::ObjectType::ASSET);

    EXPECT_TRUE(base_invalidation.matches(matching_invalidation));

    auto missing_attr_invalidation = Invalidation("aaa")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::GROUP, "ddd")
        .setStringAttr("attr1", "1")
        .setStringAttr("attr2", "2")
        .setStringAttr("attr3", "6")
        .setSourceId("id")
        .setObjectType(Intelligence::ObjectType::ASSET);

    EXPECT_FALSE(base_invalidation.matches(missing_attr_invalidation));

    set<string> vals2 = { "1", "5" };
    auto has_extra_value_invalidation = Invalidation("aaa")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::GROUP, "ddd")
        .setStringSetAttr("attr1", vals2)
        .setStringSetAttr("attr2", vals)
        .setStringAttr("attr3", "6")
        .setSourceId("id")
        .setObjectType(Intelligence::ObjectType::ASSET);

    EXPECT_TRUE(base_invalidation.matches(has_extra_value_invalidation));
}

class IntelligenceInvalidation : public Test
{
public:
    IntelligenceInvalidation() : i_intelligence(Singleton::Consume<I_Intelligence_IS_V2>::from(intelligence))
    {
        EXPECT_CALL(
            mock_ml,
            addRecurringRoutine(I_MainLoop::RoutineType::System, chrono::microseconds(7200000000), _, _, _)
        ).WillRepeatedly(Return(0));

        EXPECT_CALL(
            mock_ml,
            addRecurringRoutine(I_MainLoop::RoutineType::System, _, _, "Sending intelligence invalidation", _)
        ).WillRepeatedly(DoAll(SaveArg<2>(&routine), Return(0)));

        EXPECT_CALL(
            mock_rest,
            mockRestCall(_, "new-invalidation/source/invalidation", _)
        ).WillRepeatedly(
            WithArg<2>(Invoke(this, &IntelligenceInvalidation::saveRestServerCB))
        );

        EXPECT_CALL(
            mock_rest,
            getListeningPort()
        ).WillRepeatedly(Return(7000));

        conf.preload();
        intelligence.preload();
        intelligence.init();
    }

    bool
    saveRestServerCB(const unique_ptr<RestInit> &p)
    {
        mock_invalidation = p->getRest();
        return true;
    }

    StrictMock<MockMessaging> messaging_mock;
    StrictMock<MockMainLoop> mock_ml;
    NiceMock<MockTimeGet> mock_time;
    NiceMock<MockAgentDetails> mock_details;
    StrictMock<MockRestApi> mock_rest;
    ConfigComponent conf;
    ::Environment env;
    IntelligenceComponentV2 intelligence;
    I_Intelligence_IS_V2 *i_intelligence;
    function<void(const Invalidation &)> callback =
        [this] (const Invalidation &incoming) { recieved_invalidations.push_back(incoming); };
    vector<Invalidation> recieved_invalidations;
    unique_ptr<ServerRest> mock_invalidation;
    I_MainLoop::Routine routine;
};

TEST_F(IntelligenceInvalidation, sending_incomplete_invalidation)
{
    auto invalidation = Invalidation("aaa")
        .setStringAttr("attr2", "2")
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setObjectType(Intelligence::ObjectType::ASSET);

    EXPECT_FALSE(invalidation.report(i_intelligence));
}

TEST_F(IntelligenceInvalidation, sending_public_invalidation)
{
    auto invalidation = Invalidation("aaa")
        .setStringAttr("attr2", "2")
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    string invalidation_json;
    EXPECT_CALL(
        messaging_mock,
        sendMessage(false, _, I_Messaging::Method::POST, invalidation_uri, _, _, true, MessageTypeTag::INTELLIGENCE)
    ).WillOnce(DoAll(SaveArg<1>(&invalidation_json), Return(string())));
    EXPECT_TRUE(invalidation.report(i_intelligence));

    string expected_json =
        "{ \"invalidations\": [ { "
        "\"class\": \"aaa\", "
        "\"category\": \"bbb\", "
        "\"family\": \"ccc\", "
        "\"objectType\": \"asset\", "
        "\"sourceId\": \"id\", "
        "\"mainAttributes\": [ { \"attr2\": \"2\" } ]"
        " } ] }";
    EXPECT_EQ(invalidation_json, expected_json);
}

TEST_F(IntelligenceInvalidation, sending_private_invalidation)
{
    auto invalidation = Invalidation("aaa")
        .setStringAttr("attr2", "2")
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);


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

    string invalidation_json;
    EXPECT_CALL(
        messaging_mock,
        sendMessage(false, _, I_Messaging::Method::POST, "127.0.0.1", 9090, _, invalidation_uri, _, _, _)
    ).WillOnce(DoAll(SaveArg<1>(&invalidation_json), Return(string())));
    EXPECT_TRUE(invalidation.report(i_intelligence));

    string expected_json =
        "{ \"invalidations\": [ { "
        "\"class\": \"aaa\", "
        "\"category\": \"bbb\", "
        "\"family\": \"ccc\", "
        "\"objectType\": \"asset\", "
        "\"sourceId\": \"id\", "
        "\"mainAttributes\": [ { \"attr2\": \"2\" } ]"
        " } ] }";
    EXPECT_EQ(invalidation_json, expected_json);
}

TEST_F(IntelligenceInvalidation, register_for_invalidation)
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

    auto invalidation = Invalidation("aaa")
        .setStringAttr("attr2", "2")
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    string body;
    EXPECT_CALL(
        messaging_mock,
        sendMessage(_, _, _, "127.0.0.1", 9090, _, "/api/v2/intelligence/invalidation/register", _, _, _)
    ).WillOnce(DoAll(
        SaveArg<1>(&body),
        Return(string())
    ));

    EXPECT_NE(i_intelligence->registerInvalidation(invalidation, callback), 0);

    EXPECT_THAT(body, HasSubstr("\"url\": \"http://127.0.0.1:7000/set-new-invalidation\""));
    EXPECT_THAT(body, HasSubstr("\"apiVersion\": \"v2\", \"communicationType\": \"sync\""));
    EXPECT_THAT(body, HasSubstr("\"mainAttributes\": [ { \"attr2\": \"2\" } ]"));
}

TEST_F(IntelligenceInvalidation, invalidation_callback)
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

    auto invalidation = Invalidation("aaa")
        .setStringAttr("attr2", "2")
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    EXPECT_CALL(
        messaging_mock,
        sendMessage(_, _, _, "127.0.0.1", 9090, _, "/api/v2/intelligence/invalidation/register", _, _, _)
    ).WillOnce(Return(string()));

    EXPECT_NE(i_intelligence->registerInvalidation(invalidation, callback), 0);

    set<string> vals = { "1", "5", "2" };
    auto invalidation2 = Invalidation("aaa")
        .setStringSetAttr("attr2", vals)
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    stringstream json;
    json << invalidation2.genObject();
    mock_invalidation->performRestCall(json);

    EXPECT_EQ(recieved_invalidations.size(), 1);
    EXPECT_EQ(recieved_invalidations[0].getStringSetAttr("attr2").unpack(), vals);
}

TEST_F(IntelligenceInvalidation, delete_invalidation_callback)
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

    auto invalidation = Invalidation("aaa")
        .setStringAttr("attr2", "2")
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    EXPECT_CALL(
        messaging_mock,
        sendMessage(_, _, _, "127.0.0.1", 9090, _, "/api/v2/intelligence/invalidation/register", _, _, _)
    ).WillOnce(Return(string()));

    auto callback_id = i_intelligence->registerInvalidation(invalidation, callback);
    i_intelligence->unregisterInvalidation(*callback_id);

    set<string> vals = { "1", "5", "2" };
    auto invalidation2 = Invalidation("aaa")
        .setStringSetAttr("attr2", vals)
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    stringstream json;
    json << invalidation2.genObject();
    mock_invalidation->performRestCall(json);

    EXPECT_EQ(recieved_invalidations.size(), 0);
}

TEST_F(IntelligenceInvalidation, invalidation_short_handling)
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

    auto invalidation = Invalidation("aaa")
        .setStringAttr("attr2", "2")
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    EXPECT_CALL(
        messaging_mock,
        sendMessage(_, _, _, "127.0.0.1", 9090, _, "/api/v2/intelligence/invalidation/register", _, _, _)
    ).WillOnce(Return(string()));
    invalidation.startListening(i_intelligence, callback);

    invalidation.stopListening(i_intelligence);

    set<string> vals = { "1", "5", "2" };
    auto invalidation2 = Invalidation("aaa")
        .setStringSetAttr("attr2", vals)
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    stringstream json;
    json << invalidation2.genObject();
    mock_invalidation->performRestCall(json);

    EXPECT_EQ(recieved_invalidations.size(), 0);
}

TEST_F(IntelligenceInvalidation, routine_registration)
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

    routine();

    auto invalidation = Invalidation("aaa")
        .setStringAttr("attr2", "2")
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    EXPECT_CALL(
        messaging_mock,
        sendMessage(_, _, _, "127.0.0.1", 9090, _, "/api/v2/intelligence/invalidation/register", _, _, _)
    ).WillOnce(Return(string()));

    i_intelligence->registerInvalidation(invalidation, callback);

    string body;
    EXPECT_CALL(
        messaging_mock,
        sendMessage(_, _, _, "127.0.0.1", 9090, _, "/api/v2/intelligence/invalidation/register", _, _, _)
    ).WillOnce(DoAll(
        SaveArg<1>(&body),
        Return(string())
    ));

    routine();

    EXPECT_THAT(body, HasSubstr("\"url\": \"http://127.0.0.1:7000/set-new-invalidation\""));
    EXPECT_THAT(body, HasSubstr("\"apiVersion\": \"v2\", \"communicationType\": \"sync\""));
    EXPECT_THAT(body, HasSubstr("\"mainAttributes\": [ { \"attr2\": \"2\" } ]"));
}
