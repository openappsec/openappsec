#include "messaging_comp.h"

#include "agent_core_utilities.h"
#include "config.h"
#include "config_component.h"
#include "connection.h"
#include "cptest.h"
#include "environment.h"
#include "mainloop.h"
#include "mock/mock_agent_details.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_time_get.h"
#include "mock/mock_proxy_configuration.h"
#include "mocks/mock_messaging_buffer.h"
#include "mocks/mock_messaging_connection.h"
#include "rest.h"
#include "rest_server.h"
#include "dummy_socket.h"

using namespace std;
using namespace testing;

static ostream &
operator<<(ostream &os, const Maybe<BufferedMessage> &)
{
    return os;
}

static std::ostream &
operator<<(std::ostream &os, const HTTPResponse &)
{
    return os;
}

static std::ostream &
operator<<(std::ostream &os, const HTTPStatusCode &)
{
    return os;
}

static std::ostream &
operator<<(std::ostream &os, const Connection &)
{
    return os;
}

class TestMessagingComp : public testing::Test
{
public:
    TestMessagingComp()
    {
        Debug::setUnitTestFlag(D_MESSAGING, Debug::DebugLevel::TRACE);
        EXPECT_CALL(mock_time_get, getMonotonicTime()).WillRepeatedly(Return(chrono::microseconds(0)));

        ON_CALL(mock_agent_details, getFogDomain()).WillByDefault(Return(Maybe<string>(fog_addr)));
        ON_CALL(mock_agent_details, getFogPort()).WillByDefault(Return(Maybe<uint16_t>(fog_port)));
        messaging_comp.init();
        dummy_socket.init();
    }

    void
    setAgentDetails()
    {
        EXPECT_CALL(mock_agent_details, getFogDomain()).WillRepeatedly(Return(string(fog_addr)));
        EXPECT_CALL(mock_agent_details, getFogPort()).WillRepeatedly(Return(fog_port));
        EXPECT_CALL(mock_agent_details, getOpenSSLDir()).WillRepeatedly(Return(string("/usr/lib/ssl/certs/")));
        EXPECT_CALL(mock_agent_details, getAccessToken()).WillRepeatedly(Return(string("accesstoken")));
        EXPECT_CALL(mock_agent_details, readAgentDetails()).WillRepeatedly(Return(true));
        EXPECT_CALL(mock_proxy_conf, loadProxy()).WillRepeatedly(Return(Maybe<void>()));
        EXPECT_CALL(mock_proxy_conf, getProxyExists(_)).WillRepeatedly(Return(true));
        EXPECT_CALL(mock_proxy_conf, getProxyDomain(_)).WillRepeatedly(Return(string("7.7.7.7")));
        EXPECT_CALL(mock_proxy_conf, getProxyPort(_)).WillRepeatedly(Return(8080));
        EXPECT_CALL(mock_proxy_conf, getProxyAuthentication(_)).WillRepeatedly(Return(string("cred")));
    }

    const string fog_addr = "127.0.0.1";
    int fog_port = 8080;
    CPTestTempfile agent_details_file;
    MessagingComp messaging_comp;
    ::Environment env;
    ConfigComponent config;
    NiceMock<MockMessagingConnection> mock_messaging_connection;
    NiceMock<MockMessagingBuffer> mock_messaging_buffer;
    NiceMock<MockMainLoop> mock_mainloop;
    NiceMock<MockTimeGet> mock_time_get;
    NiceMock<MockAgentDetails> mock_agent_details;
    NiceMock<MockProxyConfiguration> mock_proxy_conf;
    DummySocket dummy_socket;
};

TEST_F(TestMessagingComp, testInitComp)
{
    EXPECT_CALL(
        mock_mainloop, addRecurringRoutine(I_MainLoop::RoutineType::Timer, _, _, "Delete expired cache entries", _)
    )
        .WillOnce(Return(0));
    messaging_comp.init();
}

TEST_F(TestMessagingComp, testSendSyncMessage)
{
    setAgentDetails();
    string body = "test body";
    HTTPMethod method = HTTPMethod::POST;
    string uri = "/test-uri";
    MessageCategory category = MessageCategory::GENERIC;

    MessageConnectionKey conn_key(fog_addr, fog_port, MessageCategory::GENERIC);
    Flags<MessageConnectionConfig> conn_flags;
    conn_flags.setFlag(MessageConnectionConfig::UNSECURE_CONN);
    MessageMetadata conn_metadata(fog_addr, fog_port, conn_flags, false, true);
    Connection conn(conn_key, conn_metadata);

    EXPECT_CALL(mock_messaging_connection, getFogConnectionByCategory(MessageCategory::GENERIC))
        .WillOnce(Return(conn));

    HTTPResponse res(HTTPStatusCode::HTTP_OK, "response!!");
    EXPECT_CALL(mock_messaging_connection, mockSendRequest(_, _, _)).WillOnce(Return(res));
    auto sending_res = messaging_comp.sendSyncMessage(method, uri, body, category, conn_metadata);
    ASSERT_TRUE(sending_res.ok());
    HTTPResponse http_res = sending_res.unpack();
    EXPECT_EQ(http_res.getBody(), "response!!");
    EXPECT_EQ(http_res.getHTTPStatusCode(), HTTPStatusCode::HTTP_OK);
}

TEST_F(TestMessagingComp, testSendAsyncMessage)
{
    setAgentDetails();
    string body = "test body";
    HTTPMethod method = HTTPMethod::POST;
    string uri = "/test-uri";
    MessageCategory category = MessageCategory::GENERIC;
    MessageMetadata message_metadata;

    EXPECT_CALL(mock_messaging_buffer, pushNewBufferedMessage(body, method, uri, category, _, _)).Times(1);
    messaging_comp.sendAsyncMessage(method, uri, body, category, message_metadata, true);
}

TEST_F(TestMessagingComp, testSendSyncMessageOnSuspendedConn)
{
    setAgentDetails();
    string body = "test body";
    HTTPMethod method = HTTPMethod::POST;
    string uri = "/test-uri";
    MessageCategory category = MessageCategory::GENERIC;
    MessageMetadata message_metadata;

    MessageConnectionKey conn_key(fog_addr, fog_port, MessageCategory::GENERIC);
    Connection conn(conn_key, message_metadata);

    EXPECT_CALL(mock_time_get, getMonotonicTime())
        .WillRepeatedly(Invoke([] () { static int j = 0; return chrono::microseconds(++j * 1000 * 1000); }));
    for (int i = 0; i < 20; i++) {
        conn.sendRequest(".");
    }
    EXPECT_CALL(mock_messaging_connection, getFogConnectionByCategory(MessageCategory::GENERIC))
        .WillOnce(Return(conn));

    auto sending_res = messaging_comp.sendSyncMessage(method, uri, body, category, message_metadata);
    ASSERT_FALSE(sending_res.ok());
    HTTPResponse http_res = sending_res.getErr();
    EXPECT_EQ(http_res.getBody(), "The connection is suspended due to consecutive message sending errors.");
    EXPECT_EQ(http_res.getHTTPStatusCode(), HTTPStatusCode::HTTP_SUSPEND);
}

TEST_F(TestMessagingComp, testUploadFile)
{
    string path = cptestFnameInSrcDir("tests_files/file_to_send.txt");

    setAgentDetails();
    string uri = "/test-uri";
    MessageCategory category = MessageCategory::GENERIC;

    MessageConnectionKey conn_key(fog_addr, fog_port, MessageCategory::GENERIC);
    Flags<MessageConnectionConfig> conn_flags;
    conn_flags.setFlag(MessageConnectionConfig::UNSECURE_CONN);
    MessageMetadata conn_metadata(fog_addr, fog_port, conn_flags, false, true);
    Connection conn(conn_key, conn_metadata);
    EXPECT_CALL(mock_messaging_connection, getFogConnectionByCategory(MessageCategory::GENERIC))
        .WillOnce(Return(conn));

    HTTPResponse res(HTTPStatusCode::HTTP_OK, "");
    EXPECT_CALL(mock_messaging_connection, mockSendRequest(_, _, _)).WillOnce(Return(res));
    auto upload_res = messaging_comp.uploadFile(uri, path, category, conn_metadata);
    ASSERT_TRUE(upload_res.ok());
}

TEST_F(TestMessagingComp, testDownloadFile)
{
    string path = cptestFnameInSrcDir("tests_files/file_to_send.txt");

    setAgentDetails();
    string uri = "/test-uri";
    HTTPMethod method = HTTPMethod::GET;
    MessageCategory category = MessageCategory::GENERIC;

    MessageConnectionKey conn_key(fog_addr, fog_port, MessageCategory::GENERIC);
    Flags<MessageConnectionConfig> conn_flags;
    conn_flags.setFlag(MessageConnectionConfig::UNSECURE_CONN);
    MessageMetadata conn_metadata(fog_addr, fog_port, conn_flags, false, true);
    Connection conn(conn_key, conn_metadata);
    EXPECT_CALL(mock_messaging_connection, getFogConnectionByCategory(MessageCategory::GENERIC))
        .WillOnce(Return(conn));

    HTTPResponse res(HTTPStatusCode::HTTP_OK, "");
    EXPECT_CALL(mock_messaging_connection, mockSendRequest(_, _, _)).WillOnce(Return(res));
    auto upload_res = messaging_comp.downloadFile(method, uri, "/tmp/test.txt", category, conn_metadata);
    ASSERT_TRUE(upload_res.ok());
}

bool
operator==(const MessageProxySettings &one, const MessageProxySettings &two)
{
    return
        one.getProxyHost() == two.getProxyHost() &&
        one.getProxyAuth() == two.getProxyAuth() &&
        one.getProxyPort() == two.getProxyPort();
}

bool
operator==(const MessageMetadata &one, const MessageMetadata &two)
{
    return
        one.getHostName() == two.getHostName() &&
        one.getPort() == two.getPort() &&
        one.getConnectionFlags() == two.getConnectionFlags() &&
        one.getProxySettings() == two.getProxySettings() &&
        one.getExternalCertificate() == two.getExternalCertificate() &&
        one.getHeaders() == two.getHeaders() &&
        one.shouldBufferMessage() == two.shouldBufferMessage() &&
        one.isProxySet() == two.isProxySet();
}

TEST_F(TestMessagingComp, testSetFogConnection)
{
    setAgentDetails();

    MessageCategory category = MessageCategory::GENERIC;
    MessageConnectionKey conn_key(fog_addr, fog_port, category);
    MessageMetadata metadata(fog_addr, fog_port, true);
    MessageProxySettings proxy_settings("7.7.7.7", "cred", 8080);
    metadata.setProxySettings(proxy_settings);
    Connection conn(conn_key, metadata);

    EXPECT_CALL(mock_messaging_connection, establishConnection(metadata, category)).WillOnce(Return(conn));
    EXPECT_TRUE(messaging_comp.setFogConnection(category));
}
