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


TEST(StringAttributesBasic, SettersAndGetters)
{
    StrAttributes string_attributes;

    EXPECT_TRUE(string_attributes.isEmpty());
    EXPECT_FALSE(string_attributes.getStringAttr("attr1").ok());
    EXPECT_FALSE(string_attributes.getStringSetAttr("attr2").ok());

    set<string> vals = { "2", "3" };
    string_attributes
        .addStringAttr("attr1", "1")
        .addStringSetAttr("attr2", vals);

    EXPECT_FALSE(string_attributes.isEmpty());
    EXPECT_EQ(string_attributes.getStringAttr("attr1").unpack(), "1");
    EXPECT_EQ(string_attributes.getStringSetAttr("attr2").unpack(), vals);
}

TEST(StringAttributesBasic, attr_schema)
{
    set<string> vals = { "2", "3" };
    auto string_attributes = StrAttributes()
        .addStringAttr("attr1", "1")
        .addStringSetAttr("attr2", vals);
    stringstream ss;
    string_attributes.performOutputingSchema(ss, 0);
    string expected_schema =
        "{\n"
        "    \"attr1\": \"1\",\n"
        "    \"attr2\": [\n"
        "        \"2\",\n"
        "        \"3\"\n"
        "    ]\n"
        "}";
    EXPECT_EQ(ss.str(), expected_schema);
}

TEST(StringAttributesBasic, Matching)
{
    set<string> vals = { "2", "3" };
    auto base_string_attributes = StrAttributes()
        .addStringAttr("attr1", "1")
        .addStringAttr("attr2", "2")
        .addStringAttr("attr3", "3")
        .addStringSetAttr("attr4", vals);

    auto matching_string_attributes = StrAttributes()
        .addStringAttr("attr1", "1")
        .addStringAttr("attr2", "2")
        .addStringAttr("attr3", "3")
        .addStringSetAttr("attr4", vals)
        .addStringAttr("attr5", "6")
        .addStringSetAttr("attr6", vals);

    EXPECT_TRUE(base_string_attributes.matches(matching_string_attributes));

    auto not_matching_string_attributes = StrAttributes()
        .addStringAttr("attr1", "1")
        .addStringAttr("attr2", "2")
        .addStringSetAttr("attr4", vals)
        .addStringAttr("attr3", "6");

    EXPECT_FALSE(base_string_attributes.matches(not_matching_string_attributes));

    auto missing_attr_string_attributes = StrAttributes()
        .addStringAttr("attr1", "1")
        .addStringSetAttr("attr2", vals);

    EXPECT_FALSE(base_string_attributes.matches(missing_attr_string_attributes));

    set<string> vals2 = { "1", "5", "2", "3" };
    auto has_extra_value_string_attributes = StrAttributes()
        .addStringAttr("attr1", "1")
        .addStringAttr("attr2", "2")
        .addStringAttr("attr3", "3")
        .addStringSetAttr("attr4", vals2);

    EXPECT_TRUE(base_string_attributes.matches(has_extra_value_string_attributes));
}

TEST(StringAttributesBasic, genObject)
{
    set<string> vals = { "2", "3" };
    auto string_attributes = StrAttributes()
        .addStringAttr("attr1", "1")
        .addStringSetAttr("attr2", vals);

    string expected_json = "{ \"attr1\": \"1\", \"attr2\": [ \"2\", \"3\" ] }";
    EXPECT_EQ(string_attributes.genObject().unpack(), expected_json);
}

TEST(InvalidationBasic, SettersAndGetters)
{
    Invalidation invalidation("aaa");

    EXPECT_EQ(invalidation.getClassifier(ClassifierType::CLASS), "aaa");
    EXPECT_EQ(invalidation.getClassifier(ClassifierType::CATEGORY), "");
    EXPECT_EQ(invalidation.getClassifier(ClassifierType::FAMILY), "");
    EXPECT_EQ(invalidation.getClassifier(ClassifierType::GROUP), "");
    EXPECT_EQ(invalidation.getClassifier(ClassifierType::ORDER), "");
    EXPECT_EQ(invalidation.getClassifier(ClassifierType::KIND), "");

    EXPECT_TRUE(invalidation.getMainAttributes().empty());
    EXPECT_TRUE(invalidation.getAttributes().empty());
    EXPECT_FALSE(invalidation.getSourceId().ok());
    EXPECT_FALSE(invalidation.getObjectType().ok());
    EXPECT_FALSE(invalidation.getInvalidationType().ok());

    set<string> main_vals = { "2", "3" };
    set<string> vals = { "5", "6" };

    auto main_attr = StrAttributes()
        .addStringAttr("main_attr1", "1")
        .addStringSetAttr("main_attr2", main_vals);

    auto attr = StrAttributes()
        .addStringAttr("attr1", "4")
        .addStringSetAttr("attr2", vals);

    invalidation
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .addMainAttr(main_attr)
        .addAttr(attr)
        .setSourceId("id")
        .setObjectType(Intelligence::ObjectType::ASSET)
        .setInvalidationType(InvalidationType::DELETE);

    EXPECT_EQ(invalidation.getClassifier(ClassifierType::CATEGORY), "bbb");
    EXPECT_EQ(invalidation.getClassifier(ClassifierType::FAMILY), "ccc");
    EXPECT_EQ(invalidation.getMainAttributes().begin()->getStringAttr("main_attr1").unpack(), "1");
    EXPECT_EQ(invalidation.getMainAttributes().begin()->getStringSetAttr("main_attr2").unpack(), main_vals);
    EXPECT_EQ(invalidation.getAttributes().begin()->getStringAttr("attr1").unpack(), "4");
    EXPECT_EQ(invalidation.getAttributes().begin()->getStringSetAttr("attr2").unpack(), vals);
    EXPECT_EQ(invalidation.getSourceId().unpack(), "id");
    EXPECT_EQ(invalidation.getObjectType().unpack(), Intelligence::ObjectType::ASSET);
    EXPECT_EQ(invalidation.getInvalidationType().unpack(), InvalidationType::DELETE);
}

TEST(InvalidationBasic, Matching)
{
    set<string> main_vals = { "2", "3" };
    set<string> vals = { "5", "6" };

    auto main_attr = StrAttributes()
        .addStringAttr("main_attr1", "1")
        .addStringSetAttr("main_attr2", main_vals);

    auto attr = StrAttributes()
        .addStringAttr("attr1", "4")
        .addStringSetAttr("attr2", vals);

    auto base_invalidation = Invalidation("aaa")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .addMainAttr(main_attr)
        .addAttr(attr);

    auto matching_main_attr = StrAttributes()
        .addStringAttr("main_attr1", "1")
        .addStringSetAttr("main_attr2", main_vals)
        .addStringAttr("main_attr3", "6");

    auto matching_attr = StrAttributes()
        .addStringAttr("attr1", "4")
        .addStringSetAttr("attr2", vals)
        .addStringAttr("attr3", "7");

    auto matching_invalidation = Invalidation("aaa")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::GROUP, "ddd")
        .addMainAttr(matching_main_attr)
        .addAttr(matching_attr)
        .setSourceId("id")
        .setObjectType(Intelligence::ObjectType::ASSET)
        .setInvalidationType(InvalidationType::ADD);

    EXPECT_TRUE(base_invalidation.matches(matching_invalidation));

    auto missing_attr_main = StrAttributes()
        .addStringAttr("main_attr1", "1")
        .addStringAttr("main_attr2", "2")
        .addStringAttr("main_attr3", "6");

    auto missing_attr_invalidation_main = Invalidation("aaa")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::GROUP, "ddd")
        .addMainAttr(missing_attr_main)
        .addAttr(matching_attr)
        .setSourceId("id")
        .setObjectType(Intelligence::ObjectType::ASSET);

    EXPECT_FALSE(base_invalidation.matches(missing_attr_invalidation_main));

    auto missing_attr = StrAttributes()
        .addStringAttr("attr1", "4")
        .addStringAttr("attr2", "2")
        .addStringAttr("attr3", "7");

    auto missing_attr_invalidation = Invalidation("aaa")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::GROUP, "ddd")
        .addMainAttr(matching_main_attr)
        .addAttr(missing_attr)
        .setSourceId("id")
        .setObjectType(Intelligence::ObjectType::ASSET);

    EXPECT_FALSE(base_invalidation.matches(missing_attr_invalidation));

    set<string> vals2 = { "1", "5" };
    auto extra_value_main_attr = StrAttributes()
        .addStringSetAttr("main_attr1", vals2)
        .addStringSetAttr("main_attr2", main_vals)
        .addStringAttr("main_attr3", "6");

    auto has_extra_value_invalidation = Invalidation("aaa")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::GROUP, "ddd")
        .addMainAttr(extra_value_main_attr)
        .addAttr(matching_attr)
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

        ON_CALL(mock_details, getFogDomain()).WillByDefault(Return(Maybe<string>(string("fog_domain.com"))));
        ON_CALL(mock_details, getFogPort()).WillByDefault(Return(Maybe<uint16_t>(443)));

        conf.preload();
        intelligence.preload();
        intelligence.init();
        main_attr.addStringAttr("attr2", "2");
        attr.addStringAttr("attr3", "3");
    }

    bool
    saveRestServerCB(const unique_ptr<RestInit> &p)
    {
        mock_invalidation = p->getRest();
        return true;
    }

    StrAttributes main_attr;
    StrAttributes attr;
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
        .addMainAttr(main_attr)
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setObjectType(Intelligence::ObjectType::ASSET);

    EXPECT_FALSE(invalidation.report(i_intelligence));
}

TEST_F(IntelligenceInvalidation, sending_public_invalidation)
{
    auto invalidation = Invalidation("aaa")
        .addMainAttr(main_attr)
        .addAttr(attr)
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    string invalidation_json;
    MessageMetadata md;
    EXPECT_CALL(
        messaging_mock,
        sendSyncMessage(HTTPMethod::POST, invalidation_uri, _, MessageCategory::INTELLIGENCE, _)
    ).WillOnce(DoAll(
        SaveArg<2>(&invalidation_json),
        SaveArg<4>(&md),
        Return(HTTPResponse(HTTPStatusCode::HTTP_OK, ""))
    ));

    EXPECT_TRUE(invalidation.report(i_intelligence));

    string expected_json =
        "{ \"invalidations\": [ { "
        "\"class\": \"aaa\", "
        "\"category\": \"bbb\", "
        "\"family\": \"ccc\", "
        "\"objectType\": \"asset\", "
        "\"sourceId\": \"id\", "
        "\"mainAttributes\": [ { \"attr2\": \"2\" } ], "
        "\"attributes\": [ { \"attr3\": \"3\" } ]"
        " } ] }";
    EXPECT_EQ(invalidation_json, expected_json);
    EXPECT_FALSE(md.getConnectionFlags().isSet(MessageConnectionConfig::UNSECURE_CONN));
}

TEST_F(IntelligenceInvalidation, multiple_assets_invalidation)
{
    auto main_attr_2 = StrAttributes()
        .addStringAttr("attr2", "22")
        .addStringSetAttr("attr3", {"33", "44"});

    auto invalidation = Invalidation("aaa")
        .addMainAttr(main_attr)
        .addMainAttr(main_attr_2)
        .addAttr(attr)
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    string invalidation_json;
    EXPECT_CALL(
        messaging_mock,
        sendSyncMessage(HTTPMethod::POST, invalidation_uri, _, MessageCategory::INTELLIGENCE, _)
    ).WillOnce(DoAll(
        SaveArg<2>(&invalidation_json),
        Return(HTTPResponse(HTTPStatusCode::HTTP_OK, ""))
    ));

    EXPECT_TRUE(invalidation.report(i_intelligence));

    string expected_json =
        "{ \"invalidations\": [ { "
        "\"class\": \"aaa\", "
        "\"category\": \"bbb\", "
        "\"family\": \"ccc\", "
        "\"objectType\": \"asset\", "
        "\"sourceId\": \"id\", "
        "\"mainAttributes\": [ { \"attr2\": \"2\" }, { \"attr2\": \"22\", \"attr3\": [ \"33\", \"44\" ] } ], "
        "\"attributes\": [ { \"attr3\": \"3\" } ]"
        " } ] }";
    EXPECT_EQ(invalidation_json, expected_json);
}

TEST_F(IntelligenceInvalidation, sending_private_invalidation)
{
    auto invalidation = Invalidation("aaa")
        .addMainAttr(main_attr)
        .addAttr(attr)
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
    MessageMetadata md;
    EXPECT_CALL(
        messaging_mock,
        sendSyncMessage(HTTPMethod::POST, invalidation_uri, _, MessageCategory::INTELLIGENCE, _)
    ).WillOnce(DoAll(
        SaveArg<2>(&invalidation_json),
        SaveArg<4>(&md),
        Return(HTTPResponse(HTTPStatusCode::HTTP_OK, ""))
    ));

    EXPECT_TRUE(invalidation.report(i_intelligence));

    string expected_json =
        "{ \"invalidations\": [ { "
        "\"class\": \"aaa\", "
        "\"category\": \"bbb\", "
        "\"family\": \"ccc\", "
        "\"objectType\": \"asset\", "
        "\"sourceId\": \"id\", "
        "\"mainAttributes\": [ { \"attr2\": \"2\" } ], "
        "\"attributes\": [ { \"attr3\": \"3\" } ]"
        " } ] }";
    EXPECT_EQ(invalidation_json, expected_json);
    EXPECT_TRUE(md.getConnectionFlags().isSet(MessageConnectionConfig::UNSECURE_CONN));
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
        .addMainAttr(main_attr)
        .addAttr(attr)
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    string body;
    MessageMetadata md;
    EXPECT_CALL(
        messaging_mock,
        sendSyncMessage(_, "/api/v2/intelligence/invalidation/register", _, _, _)
    ).WillOnce(DoAll(
        SaveArg<2>(&body),
        SaveArg<4>(&md),
        Return(HTTPResponse(HTTPStatusCode::HTTP_OK, ""))
    ));

    EXPECT_NE(i_intelligence->registerInvalidation(invalidation, callback), 0);

    EXPECT_THAT(body, HasSubstr("\"url\": \"http://127.0.0.1:7000/set-new-invalidation\""));
    EXPECT_THAT(body, HasSubstr("\"apiVersion\": \"v2\", \"communicationType\": \"sync\""));
    EXPECT_THAT(body, HasSubstr("\"mainAttributes\": [ { \"attr2\": \"2\" } ]"));
    EXPECT_THAT(body, HasSubstr("\"attributes\": [ { \"attr3\": \"3\" } ]"));
    EXPECT_TRUE(md.getConnectionFlags().isSet(MessageConnectionConfig::UNSECURE_CONN));
}

TEST_F(IntelligenceInvalidation, register_for_multiple_assets_invalidation)
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

    auto multiple_assets_main_attr1 = StrAttributes()
        .addStringAttr("attr2", "22");
    auto multiple_assets_main_attr2 = StrAttributes()
        .addStringAttr("attr2", "222");
    auto multiple_assets_main_attr3 = StrAttributes()
        .addStringAttr("attr2", "2222")
        .addStringSetAttr("attr3", {"3333", "4444"});
    auto invalidation = Invalidation("aaa")
        .addMainAttr(multiple_assets_main_attr1)
        .addMainAttr(multiple_assets_main_attr2)
        .addMainAttr(multiple_assets_main_attr3)
        .addAttr(attr)
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    string body;
    EXPECT_CALL(
        messaging_mock,
        sendSyncMessage(_, "/api/v2/intelligence/invalidation/register", _, _, _)
    ).WillOnce(DoAll(
        SaveArg<2>(&body),
        Return(HTTPResponse(HTTPStatusCode::HTTP_OK, ""))
    ));

    EXPECT_NE(i_intelligence->registerInvalidation(invalidation, callback), 0);

    EXPECT_THAT(
        body,
        HasSubstr(
            "\"mainAttributes\": [ "
            "{ \"attr2\": \"22\" }, "
            "{ \"attr2\": \"222\" }, "
            "{ \"attr2\": \"2222\", \"attr3\": [ \"3333\", \"4444\" ] } "
            "]"
        )
    );
}

TEST_F(IntelligenceInvalidation, register_incomplit_invalidation)
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
        .addMainAttr(main_attr)
        .addAttr(attr)
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setObjectType(Intelligence::ObjectType::ASSET);

    EXPECT_FALSE(i_intelligence->registerInvalidation(invalidation, callback).ok());
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
        .addMainAttr(main_attr)
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    EXPECT_CALL(
        messaging_mock,
        sendSyncMessage(_, "/api/v2/intelligence/invalidation/register", _, _, _)
    ).WillOnce(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, "")));

    EXPECT_NE(i_intelligence->registerInvalidation(invalidation, callback), 0);

    set<string> vals = { "1", "5", "2" };
    auto test_main_attr = StrAttributes()
        .addStringSetAttr("attr2", vals);
    auto invalidation2 = Invalidation("aaa")
        .addMainAttr(test_main_attr)
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    stringstream json;
    json << invalidation2.genObject();
    mock_invalidation->performRestCall(json);

    EXPECT_EQ(recieved_invalidations.size(), 1u);
    EXPECT_EQ(recieved_invalidations[0].getMainAttributes().begin()->getStringSetAttr("attr2").unpack(), vals);
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
        .addMainAttr(main_attr)
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    EXPECT_CALL(
        messaging_mock,
        sendSyncMessage(_, "/api/v2/intelligence/invalidation/register", _, _, _)
    ).WillOnce(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, "")));

    auto callback_id = i_intelligence->registerInvalidation(invalidation, callback);
    i_intelligence->unregisterInvalidation(*callback_id);

    auto invalidation2 = Invalidation("aaa")
        .addMainAttr(main_attr)
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    stringstream json;
    json << invalidation2.genObject();
    mock_invalidation->performRestCall(json);

    EXPECT_EQ(recieved_invalidations.size(), 0u);
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
        .addMainAttr(main_attr)
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    EXPECT_CALL(
        messaging_mock,
        sendSyncMessage(_, "/api/v2/intelligence/invalidation/register", _, _, _)
    ).WillOnce(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, "")));

    invalidation.startListening(i_intelligence, callback);

    invalidation.stopListening(i_intelligence);

    auto invalidation2 = Invalidation("aaa")
        .addMainAttr(main_attr)
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    stringstream json;
    json << invalidation2.genObject();
    mock_invalidation->performRestCall(json);

    EXPECT_EQ(recieved_invalidations.size(), 0u);
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
        .addMainAttr(main_attr)
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    EXPECT_CALL(
        messaging_mock,
        sendSyncMessage(_, "/api/v2/intelligence/invalidation/register", _, _, _)
    ).WillOnce(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, "")));

    i_intelligence->registerInvalidation(invalidation, callback);

    string body;
    EXPECT_CALL(
        messaging_mock,
        sendSyncMessage(_, "/api/v2/intelligence/invalidation/register", _, _, _)
    ).WillOnce(DoAll(
        SaveArg<2>(&body),
        Return(HTTPResponse(HTTPStatusCode::HTTP_OK, ""))
    ));

    routine();

    EXPECT_THAT(body, HasSubstr("\"url\": \"http://127.0.0.1:7000/set-new-invalidation\""));
    EXPECT_THAT(body, HasSubstr("\"apiVersion\": \"v2\", \"communicationType\": \"sync\""));
    EXPECT_THAT(body, HasSubstr("\"mainAttributes\": [ { \"attr2\": \"2\" } ]"));
}

TEST_F(IntelligenceInvalidation, invalidation_flow_with_multiple_assets)
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

    auto base_main_attr2 = StrAttributes()
        .addStringAttr("attr3", "3");
    auto invalidation_to_register = Invalidation("aaa")
        .addMainAttr(main_attr)
        .addMainAttr(base_main_attr2)
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    EXPECT_CALL(
        messaging_mock,
        sendSyncMessage(_, "/api/v2/intelligence/invalidation/register", _, _, _)
    ).WillOnce(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, "")));

    invalidation_to_register.startListening(i_intelligence, callback);
    auto stop_listening = make_scope_exit([&] { invalidation_to_register.stopListening(i_intelligence); });

    auto not_matching_main_attributes = StrAttributes()
        .addStringAttr("attr3", "4");

    auto not_matching_invalidation = Invalidation("aaa")
        .addMainAttr(not_matching_main_attributes)
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    stringstream json1;
    json1 << not_matching_invalidation.genObject();
    mock_invalidation->performRestCall(json1);

    EXPECT_EQ(recieved_invalidations.size(), 0u);

    auto matching_second_main_attribute = StrAttributes()
        .addStringAttr("attr3", "3");

    auto matching_invalidation = Invalidation("aaa")
        .addMainAttr(matching_second_main_attribute)
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    stringstream json2;
    json2 << matching_invalidation.genObject();
    mock_invalidation->performRestCall(json2);

    EXPECT_EQ(recieved_invalidations.size(), 1u);
}

TEST_F(IntelligenceInvalidation, invalidation_cb_match_2_registred_assets)
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

    auto base_main_attr2 = StrAttributes()
        .addStringAttr("attr3", "3");
    auto invalidation_to_register = Invalidation("aaa")
        .addMainAttr(main_attr)
        .addMainAttr(base_main_attr2)
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    EXPECT_CALL(
        messaging_mock,
        sendSyncMessage(_, "/api/v2/intelligence/invalidation/register", _, _, _)
    ).Times(2).WillRepeatedly(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, "")));

    invalidation_to_register.startListening(i_intelligence, callback);
    auto stop_listening = make_scope_exit([&] { invalidation_to_register.stopListening(i_intelligence); });

    auto matching_second_main_attribute = StrAttributes()
        .addStringAttr("attr3", "3");

    auto matching_invalidation = Invalidation("aaa")
        .addMainAttr(matching_second_main_attribute)
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);


    auto invalidation_2_to_register = Invalidation("aaa")
        .addMainAttr(base_main_attr2)
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    invalidation_2_to_register.startListening(i_intelligence, callback);
    auto stop_listening_2 = make_scope_exit([&] { invalidation_2_to_register.stopListening(i_intelligence); });

    stringstream json;
    json << matching_invalidation.genObject();
    mock_invalidation->performRestCall(json);

    EXPECT_EQ(recieved_invalidations.size(), 2u);
}

TEST_F(IntelligenceInvalidation, invalidation_cb_match_by_registration_id)
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

    auto base_main_attr2 = StrAttributes()
        .addStringAttr("attr3", "3");
    auto invalidation_to_register = Invalidation("aaa")
        .addMainAttr(main_attr)
        .addMainAttr(base_main_attr2)
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    EXPECT_CALL(
        messaging_mock,
        sendSyncMessage(_, "/api/v2/intelligence/invalidation/register", _, _, _)
    ).Times(2).WillRepeatedly(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, "")));

    invalidation_to_register.startListening(i_intelligence, callback);
    auto stop_listening = make_scope_exit([&] { invalidation_to_register.stopListening(i_intelligence); });

    auto matching_second_main_attribute = StrAttributes()
        .addStringAttr("attr3", "3");

    auto matching_invalidation = Invalidation("aaa")
        .addMainAttr(matching_second_main_attribute)
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);


    auto invalidation_2_to_register = Invalidation("aaa")
        .addMainAttr(base_main_attr2)
        .setSourceId("id")
        .setClassifier(ClassifierType::FAMILY, "ccc")
        .setClassifier(ClassifierType::CATEGORY, "bbb")
        .setObjectType(Intelligence::ObjectType::ASSET);

    invalidation_2_to_register.startListening(i_intelligence, callback);
    auto registration_id = invalidation_2_to_register.getRegistrationID();
    auto stop_listening_2 = make_scope_exit([&] { invalidation_2_to_register.stopListening(i_intelligence); });

    string modifiedJsonString = matching_invalidation.genObject().substr(2);
    stringstream json;
    json << "{ \"invalidationRegistrationId\": \""<< *registration_id << "\", " << modifiedJsonString;
    cout << json.str() << endl;
    mock_invalidation->performRestCall(json);

    EXPECT_EQ(recieved_invalidations.size(), 1u);
}
