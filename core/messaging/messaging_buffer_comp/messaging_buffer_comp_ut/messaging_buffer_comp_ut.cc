#include "messaging_buffer.h"

#include "agent_core_utilities.h"
#include "agent_details.h"
#include "config.h"
#include "config_component.h"
#include "cptest.h"
#include "environment.h"
#include "agent_details.h"
#include "instance_awareness.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_messaging.h"
#include "mock/mock_tenant_manager.h"
#include "mock/mock_encryptor.h"
#include "shell_cmd.h"
#include "time_proxy.h"

using namespace std;
using namespace testing;

string removeWhitespaces(const std::string &str);

class TestMessagingBuffer : public Test
{
public:
    TestMessagingBuffer()
    {
        env.preload();
        Singleton::Consume<I_Environment>::from(env)->registerValue<string>("Base Executable Name", "tmp_test_file");

        config.preload();
        config.init();

        string config_json =
            "{"
            "   \"agentSettings\": [\n"
            "   {\n"
            "       \"id\": \"123\",\n"
            "       \"key\": \"eventBuffer.maxSizeOnDiskInMB\",\n"
            "       \"value\": \"1\"\n"
            "   },\n"
            "   {\n"
            "       \"id\": \"123\",\n"
            "       \"key\": \"eventBuffer.baseFolder\",\n"
            "       \"value\": \"../.." + cptestFnameInExeDir("test_data") + "\"\n"
            "   }]\n"
            "}";

        istringstream ss(config_json);
        Singleton::Consume<Config::I_Config>::from(config)->loadConfiguration({"--id=8"});
        Singleton::Consume<Config::I_Config>::from(config)->loadConfiguration(ss);

        EXPECT_CALL(mock_mainloop, addRecurringRoutine(_, _, _, "A-sync messaging routine", _))
            .WillOnce(DoAll(SaveArg<2>(&async_routine), Return(0)));

        EXPECT_CALL(mock_mainloop, addRecurringRoutine(_, _, _, "Handling in-memory messages", _))
            .WillOnce(DoAll(SaveArg<2>(&memory_routine), Return(0)));

        buffer_comp.init();
        buffer_provider = Singleton::Consume<I_MessageBuffer>::from(buffer_comp);

        agent_details.setFogDomain("fog_domain");
        agent_details.setFogPort(443);
    }

    ~TestMessagingBuffer() { buffer_provider->cleanBuffer(); }

    NiceMock<MockTenantManager> tenant_manager;
    NiceMock<MockMainLoop> mock_mainloop;
    NiceMock<MockMessaging> mock_messaging;
    ConfigComponent config;
    MessagingBufferComponent buffer_comp;
    ::Environment env;
    ShellCmd shell_cmd;
    StrictMock<MockEncryptor> m_encryptor;
    TimeProxyComponent time_proxy;
    AgentDetails agent_details;
    InstanceAwareness instance_awareness;
    I_MessageBuffer *buffer_provider;
    I_MainLoop::Routine async_routine;
    I_MainLoop::Routine memory_routine;
};

TEST_F(TestMessagingBuffer, testPeekingEmptyBuffer)
{
    auto msg = buffer_provider->peekMessage();
    ASSERT_FALSE(msg.ok());
}

static bool
checkExistence(const string &path)
{
    try {
        struct stat info;
        if (stat(path.c_str(), &info) != 0) return false;
        return info.st_mode & S_IFREG;
    } catch (exception &e) {
        return false;
    }
}

TEST_F(TestMessagingBuffer, testPushOneBuffer)
{
    string body = "body";
    string uri = "uri";
    MessageCategory category = MessageCategory::GENERIC;
    MessageMetadata message_metadata = MessageMetadata();
    HTTPMethod method = HTTPMethod::POST;

    buffer_provider->pushNewBufferedMessage(body, method, uri, category, message_metadata, true);

    auto msg = buffer_provider->peekMessage();
    ASSERT_TRUE(msg.ok());

    BufferedMessage expected(body, method, uri, category, message_metadata);
    EXPECT_EQ(*msg, expected);
    EXPECT_TRUE(checkExistence(cptestFnameInExeDir("test_data") + "/tmp_test_file8.output"));
}

TEST_F(TestMessagingBuffer, testMultiplePushesAndPulls)
{
    string uri = "uri";
    MessageCategory category = MessageCategory::GENERIC;
    MessageMetadata message_metadata = MessageMetadata();
    HTTPMethod method = HTTPMethod::POST;

    string body1 = "body1";
    string body2 = "body2";
    string body3 = "body3";
    string body4 = "body4";
    string body5 = "body5";

    BufferedMessage expected1(body1, method, uri, category, message_metadata);
    BufferedMessage expected2(body2, method, uri, category, message_metadata);
    BufferedMessage expected3(body3, method, uri, category, message_metadata);
    BufferedMessage expected4(body4, method, uri, category, message_metadata);
    BufferedMessage expected5(body5, method, uri, category, message_metadata);

    buffer_provider->pushNewBufferedMessage(body1, method, uri, category, message_metadata, true);
    buffer_provider->pushNewBufferedMessage(body2, method, uri, category, message_metadata, true);

    auto msg = buffer_provider->peekMessage();
    ASSERT_TRUE(msg.ok());
    EXPECT_EQ(*msg, expected2);
    buffer_provider->popMessage();

    buffer_provider->pushNewBufferedMessage(body3, method, uri, category, message_metadata, true);
    buffer_provider->pushNewBufferedMessage(body4, method, uri, category, message_metadata, true);

    msg = buffer_provider->peekMessage();
    ASSERT_TRUE(msg.ok());
    EXPECT_EQ(*msg, expected1);
    buffer_provider->popMessage();

    msg = buffer_provider->peekMessage();
    ASSERT_TRUE(msg.ok());
    EXPECT_EQ(*msg, expected4);
    buffer_provider->popMessage();


    msg = buffer_provider->peekMessage();
    ASSERT_TRUE(msg.ok());
    EXPECT_EQ(*msg, expected3);
    buffer_provider->popMessage();

    buffer_provider->pushNewBufferedMessage(body5, method, uri, category, message_metadata, true);

    msg = buffer_provider->peekMessage();
    ASSERT_TRUE(msg.ok());
    EXPECT_EQ(*msg, expected5);
    buffer_provider->popMessage();

    msg = buffer_provider->peekMessage();
    ASSERT_FALSE(msg.ok());
}

TEST_F(TestMessagingBuffer, testPushMoreThanAllowed)
{
    string body_1 = "body";
    string body_2 = string(1024 * 1024 * 1, 'a'); // 1MB
    string body_3 = "body";
    string uri_1 = "uri_1";
    string uri_2 = "uri_2";
    string uri_3 = "uri_3";
    MessageCategory category = MessageCategory::GENERIC;
    MessageMetadata message_metadata = MessageMetadata();
    HTTPMethod method = HTTPMethod::POST;

    BufferedMessage expected1(body_1, method, uri_1, category, message_metadata);
    BufferedMessage expected3(body_3, method, uri_3, category, message_metadata);

    buffer_provider->pushNewBufferedMessage(body_1, method, uri_1, category, message_metadata, true);
    buffer_provider->pushNewBufferedMessage(body_2, method, uri_2, category, message_metadata, true);
    buffer_provider->pushNewBufferedMessage(body_3, method, uri_3, category, message_metadata, true);

    auto msg = buffer_provider->peekMessage();
    ASSERT_TRUE(msg.ok());
    EXPECT_EQ(*msg, expected3);
    buffer_provider->popMessage();

    msg = buffer_provider->peekMessage();
    ASSERT_TRUE(msg.ok());
    EXPECT_EQ(*msg, expected1);
    buffer_provider->popMessage();

    msg = buffer_provider->peekMessage();
    ASSERT_FALSE(msg.ok());
}

TEST_F(TestMessagingBuffer, testRoutinePulling)
{
    string body_1 = "body1";
    string body_2 = "body2";
    string uri_1 = "uri_1";
    string uri_2 = "uri_2";
    MessageCategory category = MessageCategory::GENERIC;
    MessageMetadata message_metadata = MessageMetadata();
    HTTPMethod method = HTTPMethod::POST;

    buffer_provider->pushNewBufferedMessage(body_1, method, uri_1, category, message_metadata, true);
    buffer_provider->pushNewBufferedMessage(body_2, method, uri_2, category, message_metadata, true);

    HTTPResponse res(HTTPStatusCode::HTTP_OK, "");

    EXPECT_CALL(mock_messaging, sendSyncMessage(method, uri_1, body_1, _, _)).WillOnce(Return(res));
    EXPECT_CALL(mock_messaging, sendSyncMessage(method, uri_2, body_2, _, _)).WillOnce(Return(res));

    async_routine();
}

TEST_F(TestMessagingBuffer, testRoutinInMemory)
{
    string body_1 = "body1";
    string body_2 = "body2";
    string body_3 = "body3";
    string body_4 = "body4";
    string uri_1 = "uri_1";
    string uri_2 = "uri_2";
    string uri_3 = "uri_3";
    string uri_4 = "uri_4";

    MessageCategory category = MessageCategory::GENERIC;
    MessageMetadata message_metadata = MessageMetadata();
    MessageMetadata msg_2_message_metadata = MessageMetadata();
    msg_2_message_metadata.setShouldBufferMessage(true);
    HTTPMethod method = HTTPMethod::POST;

    buffer_provider->pushNewBufferedMessage(body_1, method, uri_1, category, message_metadata, false);
    buffer_provider->pushNewBufferedMessage(
        body_2,
        method,
        uri_2,
        category,
        msg_2_message_metadata,
        false
    ); // should be buffered
    buffer_provider->pushNewBufferedMessage(body_3, method, uri_3, category, message_metadata, false);
    buffer_provider->pushNewBufferedMessage(
        body_4,
        method,
        uri_4,
        category,
        message_metadata,
        false
    ); // shouldn't be buffered

    HTTPResponse res(HTTPStatusCode::HTTP_OK, "");
    Maybe<HTTPResponse, HTTPResponse> err = genError(res);

    EXPECT_CALL(mock_messaging, sendSyncMessage(method, uri_1, body_1, _, _)).WillOnce(Return(res));
    EXPECT_CALL(mock_messaging, sendSyncMessage(method, uri_2, body_2, _, _)).WillOnce(Return(err));
    EXPECT_CALL(mock_messaging, sendSyncMessage(method, uri_3, body_3, _, _)).WillOnce(Return(res));
    EXPECT_CALL(mock_messaging, sendSyncMessage(method, uri_4, body_4, _, _)).WillOnce(Return(err));

    memory_routine();

    auto msg = buffer_provider->peekMessage();
    ASSERT_TRUE(msg.ok());
    EXPECT_EQ(*msg, BufferedMessage(body_2, method, uri_2, category, message_metadata));
    buffer_provider->popMessage();

    msg = buffer_provider->peekMessage();
    ASSERT_FALSE(msg.ok());
}

TEST_F(TestMessagingBuffer, testRoutinInMemoryOverflow)
{
    string config_json =
        "{"
        "   \"agentSettings\": [\n"
        "   {\n"
        "       \"id\": \"123\",\n"
        "       \"key\": \"eventBuffer.maxMemoryMessagesToStore\",\n"
        "       \"value\": \"5\"\n"
        "   },\n"
        "   {\n"
        "       \"id\": \"123\",\n"
        "       \"key\": \"eventBuffer.additionalBufferSize\",\n"
        "       \"value\": \"1\"\n"
        "   }]\n"
        "}";

    istringstream ss(config_json);
    Singleton::Consume<Config::I_Config>::from(config)->loadConfiguration(ss);

    MessageCategory category = MessageCategory::GENERIC;
    MessageMetadata message_metadata = MessageMetadata();
    message_metadata.setShouldBufferMessage(true);
    HTTPMethod method = HTTPMethod::POST;
    HTTPResponse res(HTTPStatusCode::HTTP_OK, "");

    for (int i = 0; i < 6; i++) {
        string body = "body" + to_string(i);
        buffer_provider->pushNewBufferedMessage(body, method,  "/" + to_string(i), category, message_metadata, false);
        EXPECT_CALL(mock_messaging, sendSyncMessage(method,  "/" + to_string(i), body, _, _)).WillOnce(Return(res));
    }

    for (int i = 0; i < 2; i++) {
        string body = "body" + to_string(i);
        buffer_provider->pushNewBufferedMessage(body, method,  "/" + to_string(i), category, message_metadata, false);
    }

    memory_routine();

    for (int i = 0; i < 2; i++) {
        auto msg = buffer_provider->peekMessage();
        ASSERT_TRUE(msg.ok());
        buffer_provider->popMessage();
    }
    auto msg = buffer_provider->peekMessage();
    ASSERT_FALSE(msg.ok());
}
