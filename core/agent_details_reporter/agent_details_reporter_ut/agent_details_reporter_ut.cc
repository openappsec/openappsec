#include "agent_details_reporter.h"

#include <string>

#include "cptest.h"
#include "config.h"
#include "config_component.h"
#include "mock/mock_messaging.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_rest_api.h"
#include "environment.h"
#include "agent_details_report.h"

using namespace std;
using namespace testing;

class AgentReporterTest : public Test
{
public:
    AgentReporterTest()
    {
        env.preload();
        context.registerFunc<bool>("Is Orchestrator", [this](){ return is_server_mode; });
        context.activate();
        EXPECT_CALL(
            mock_mainloop,
            addRecurringRoutine(
                I_MainLoop::RoutineType::Offline,
                chrono::microseconds(chrono::seconds(30)),
                _,
                "Report agent details attributes",
                false
            )
        ).WillOnce(DoAll(SaveArg<2>(&periodic_report), Return(1)));

        agent_details_reporter_comp.preload();

        string config_json =
            "{\n"
            "    \"Agent details\": {\n"
            "        \"Attributes persistence file path\": [\n"
            "            {\n"
            "                \"value\": \"" + persistence_attr_file.fname + "\"\n"
            "            }\n"
            "        ]\n"
            "    }\n"
            "}";

        istringstream ss(config_json);
        Singleton::Consume<Config::I_Config>::from(config_comp)->loadConfiguration(ss);

        EXPECT_CALL(mock_rest, mockRestCall(RestAction::ADD, "agent-details-attr", _)).WillOnce(
            WithArg<2>(Invoke(this, &AgentReporterTest::saveRestServerCB))
        );

        agent_details_reporter_comp.init();
        report = Singleton::Consume<I_AgentDetailsReporter>::from(agent_details_reporter_comp);
    }

    ~AgentReporterTest()
    {
        context.deactivate();
    }

    bool
    saveRestServerCB(const unique_ptr<RestInit> &p)
    {
        add_details_rest_cb = p->getRest();
        return true;
    }

    ::Environment env;
    StrictMock<MockMainLoop> mock_mainloop;
    StrictMock<MockMessaging> mock_messaging;
    StrictMock<MockRestApi> mock_rest;
    I_MainLoop::Routine periodic_report;
    I_AgentDetailsReporter *report;
    CPTestTempfile persistence_attr_file;
    Context context;
    bool is_server_mode = true;
    ConfigComponent config_comp;
    AgentDetailsReporter agent_details_reporter_comp;
    unique_ptr<ServerRest> add_details_rest_cb;
};

TEST_F(AgentReporterTest, dataReport)
{
    string custom_data = "Linux version 24.00.15F";
    EXPECT_CALL(
        mock_messaging,
        mockSendPersistentMessage(
            _,
            "{\n"
            "    \"additionalMetaData\": {\n"
            "        \"custom_data\": \"Linux version 24.00.15F\"\n"
            "    }"
            "\n}",
            I_Messaging::Method::PATCH,
            "/agents",
            _,
            _,
            MessageTypeTag::GENERIC
        )
    ).WillOnce(Return(string()));
    AgentDataReport() << AgentReportField(custom_data);;
}

TEST_F(AgentReporterTest, labeledDataReport)
{
    string data = "Linux version 24.00.15F";
    EXPECT_CALL(
        mock_messaging,
        mockSendPersistentMessage(
            _,
            "{\n"
            "    \"additionalMetaData\": {\n"
            "        \"this_is_custom_label\": \"Linux version 24.00.15F\"\n"
            "    }"
            "\n}",
            I_Messaging::Method::PATCH,
            "/agents",
            _,
            _,
            MessageTypeTag::GENERIC
        )
    ).WillOnce(Return(string()));
    AgentDataReport() << AgentReportFieldWithLabel("this_is_custom_label", data);
}

TEST_F(AgentReporterTest, multiDataReport)
{
    string custom_data = "Linux version 24.00.15F";
    string data_to_report = "Agent Version 95.95.95.00A";

    EXPECT_CALL(
        mock_messaging,
        mockSendPersistentMessage(
            _,
            "{\n"
            "    \"additionalMetaData\": {\n"
            "        \"custom_data\": \"Linux version 24.00.15F\",\n"
            "        \"this_is_custom_label\": \"Agent Version 95.95.95.00A\"\n"
            "    }"
            "\n}",
            I_Messaging::Method::PATCH,
            "/agents",
            _,
            _,
            MessageTypeTag::GENERIC
        )
    ).WillOnce(Return(string()));

    AgentDataReport()
        << AgentReportField(custom_data)
        << AgentReportFieldWithLabel("this_is_custom_label", data_to_report);
}

TEST_F(AgentReporterTest, multiDataReportWithRegistrationData)
{
    string custom_data = "Linux version 24.00.15F";
    string data_to_report = "Agent Version 95.95.95.00A";

    EXPECT_CALL(
        mock_messaging,
        mockSendPersistentMessage(
            _,
            "{\n"
            "    \"additionalMetaData\": {\n"
            "        \"custom_data\": \"Linux version 24.00.15F\",\n"
            "        \"this_is_custom_label\": \"Agent Version 95.95.95.00A\"\n"
            "    },\n"
            "    \"agentVersion\": \"1.15.9\",\n"
            "    \"policyVersion\": \"ccc\",\n"
            "    \"platform\": \"bbb\",\n"
            "    \"architecture\": \"aaa\"\n"
            "}",
            I_Messaging::Method::PATCH,
            "/agents",
            _,
            _,
            MessageTypeTag::GENERIC
        )
    ).WillOnce(Return(string()));

    AgentDataReport agent_data;
    agent_data
        << AgentReportField(custom_data)
        << AgentReportFieldWithLabel("this_is_custom_label", data_to_report);

    agent_data.setPolicyVersion("ccc");
    agent_data.setPlatform("bbb");
    agent_data.setArchitecture("aaa");
    agent_data.setAgentVersion("1.15.9");
}

TEST_F(AgentReporterTest, basicAttrTest)
{
    EXPECT_CALL(
        mock_messaging,
        mockSendPersistentMessage(
            _,
            "{\n"
            "    \"additionalMetaData\": {}\n"
            "}",
            I_Messaging::Method::PATCH,
            "/agents",
            _,
            _,
            MessageTypeTag::GENERIC
        )
    ).WillOnce(Return(string()));

    {
        AgentDataReport agent_data;
    }

    EXPECT_CALL(
        mock_messaging,
        mockSendPersistentMessage(
            _,
            "{\n"
            "    \"additionalMetaData\": {},\n"
            "    \"attributes\": {\n"
            "        \"1\": \"2\",\n"
            "        \"a\": \"1\",\n"
            "        \"c\": \"d\"\n"
            "    }\n"
            "}",
            I_Messaging::Method::PATCH,
            "/agents",
            _,
            _,
            MessageTypeTag::GENERIC
        )
    ).WillOnce(Return(string()));

    EXPECT_TRUE(report->addAttr("a", "b"));
    EXPECT_TRUE(report->addAttr({{"c", "d"}, {"1", "2"}, {"delete", "me"}}));
    EXPECT_FALSE(report->addAttr("a", "d"));
    EXPECT_TRUE(report->addAttr("a", "1", true));
    report->deleteAttr("delete");
    {
        AgentDataReport agent_data;
    }

    EXPECT_CALL(
        mock_messaging,
        mockSendPersistentMessage(
            _,
            "{\n"
            "    \"additionalMetaData\": {}\n"
            "}",
            I_Messaging::Method::PATCH,
            "/agents",
            _,
            _,
            MessageTypeTag::GENERIC
        )
    ).WillOnce(Return(string()));

    {
        AgentDataReport agent_data;
    }
}

TEST_F(AgentReporterTest, advancedAttrTest)
{
    // No EXPECT_CALL since attr list should be empty
    periodic_report();

    EXPECT_TRUE(report->addAttr({{"c", "d"}, {"1", "2"}, {"send", "me"}}));
    EXPECT_TRUE(report->addAttr("a", "b"));

    EXPECT_CALL(
        mock_messaging,
        mockSendPersistentMessage(
            _,
            "{\n"
            "    \"attributes\": {\n"
            "        \"1\": \"2\",\n"
            "        \"a\": \"b\",\n"
            "        \"c\": \"d\",\n"
            "        \"send\": \"me\"\n"
            "    }\n"
            "}",
            I_Messaging::Method::PATCH,
            "/agents",
            _,
            _,
            MessageTypeTag::GENERIC
        )
    ).WillOnce(Return(string()));

    periodic_report();

    EXPECT_FALSE(report->addAttr("a", "key exist so value not added"));
    // No second EXPECT_CALL since attr list was not updated after previous send
    periodic_report();

    EXPECT_TRUE(report->addAttr("new", "key val"));
    EXPECT_TRUE(report->addAttr("a", "key val override", true));

    EXPECT_CALL(
        mock_messaging,
        mockSendPersistentMessage(
            _,
            "{\n"
            "    \"attributes\": {\n"
            "        \"1\": \"2\",\n"
            "        \"a\": \"key val override\",\n"
            "        \"c\": \"d\",\n"
            "        \"new\": \"key val\",\n"
            "        \"send\": \"me\"\n"
            "    }\n"
            "}",
            I_Messaging::Method::PATCH,
            "/agents",
            _,
            _,
            MessageTypeTag::GENERIC
        )
    ).WillOnce(Return(string()));

    periodic_report();
}

TEST_F(AgentReporterTest, RestDetailsTest)
{
    stringstream rest_call_parameters;
    rest_call_parameters
        << "{\n"
        << "    \"attributes\": {\n"
        << "        \"1\": \"2\",\n"
        << "        \"a\": \"key val override\",\n"
        << "        \"c\": \"d\",\n"
        << "        \"send\": \"me\"\n"
        << "    }\n"
        << "}";
    add_details_rest_cb->performRestCall(rest_call_parameters);

    EXPECT_CALL(
        mock_messaging,
        mockSendPersistentMessage(
            _,
            rest_call_parameters.str(),
            I_Messaging::Method::PATCH,
            "/agents",
            _,
            _,
            MessageTypeTag::GENERIC
        )
    ).WillOnce(Return(string()));

    EXPECT_TRUE(report->sendAttributes());

    is_server_mode = false;

    EXPECT_CALL(mock_mainloop, addRecurringRoutine(_, _, _, "Report agent details attributes", _)).WillOnce(Return(2));

    EXPECT_CALL(mock_rest, mockRestCall(RestAction::ADD, "agent-details-attr", _)).Times(0);
    agent_details_reporter_comp.init();

    EXPECT_TRUE(report->addAttr("new", "key val"));
    ::Flags<MessageConnConfig> conn_flags;
    conn_flags.setFlag(MessageConnConfig::ONE_TIME_CONN);
    EXPECT_CALL(
        mock_messaging,
        sendMessage(
            true,
            "{\n"
            "    \"attributes\": {\n"
            "        \"1\": \"2\",\n"
            "        \"a\": \"key val override\",\n"
            "        \"c\": \"d\",\n"
            "        \"new\": \"key val\",\n"
            "        \"send\": \"me\"\n"
            "    }\n"
            "}",
            I_Messaging::Method::POST,
            string("127.0.0.1"),
            7777,
            conn_flags,
            string("add-agent-details-attr"),
            string(),
            _,
            MessageTypeTag::GENERIC
        )
    ).WillOnce(Return(Maybe<string>(string("{\"status\":true}"))));

    periodic_report();
}

TEST_F(AgentReporterTest, PersistenceAttrTest)
{
    // no expect call for send message since the attr were not added yet
    EXPECT_TRUE(report->sendAttributes());

    ofstream write_attributes(persistence_attr_file.fname);
    ASSERT_TRUE(write_attributes.is_open());

    string expected_attributes(
        "{\n"
        "    \"attributes\": {\n"
        "        \"1\": \"2\",\n"
        "        \"a\": \"key val override\",\n"
        "        \"c\": \"d\",\n"
        "        \"send\": \"me\"\n"
        "    }\n"
        "}"
    );

    write_attributes << expected_attributes;
    write_attributes.close();

    EXPECT_CALL(mock_mainloop, addRecurringRoutine(_, _, _, "Report agent details attributes", _)).WillOnce(Return(2));
    EXPECT_CALL(mock_rest, mockRestCall(RestAction::ADD, "agent-details-attr", _)).WillOnce(Return(true));
    agent_details_reporter_comp.init();


    EXPECT_CALL(
        mock_messaging,
        mockSendPersistentMessage(
            _,
            expected_attributes,
            I_Messaging::Method::PATCH,
            "/agents",
            _,
            _,
            MessageTypeTag::GENERIC
        )
    ).WillOnce(Return(string()));
    EXPECT_TRUE(report->sendAttributes());

    EXPECT_TRUE(report->addAttr("new attr", "to add before fini"));
    agent_details_reporter_comp.fini();

    ifstream read_attributes(persistence_attr_file.fname);
    ASSERT_TRUE(read_attributes.is_open());

    expected_attributes =
        "{\n"
        "    \"attributes\": {\n"
        "        \"1\": \"2\",\n"
        "        \"a\": \"key val override\",\n"
        "        \"c\": \"d\",\n"
        "        \"new attr\": \"to add before fini\",\n"
        "        \"send\": \"me\"\n"
        "    }\n"
        "}";

    stringstream actual_attributes;
    actual_attributes << read_attributes.rdbuf();
    read_attributes.close();

    EXPECT_EQ(actual_attributes.str(), expected_attributes);
}
