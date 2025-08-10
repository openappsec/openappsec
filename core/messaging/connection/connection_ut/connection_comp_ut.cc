#include "connection_comp.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <thread>
#include <fcntl.h>
#include <poll.h>

#include "agent_core_utilities.h"
#include "agent_details.h"
#include "config.h"
#include "config_component.h"
#include "cptest.h"
#include "environment.h"
#include "mainloop.h"
#include "connection.h"
#include "mocks/mock_messaging_buffer.h"
#include "mock/mock_agent_details.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_time_get.h"
#include "mock/mock_encryptor.h"
#include "rest.h"
#include "rest_server.h"
#include "dummy_socket.h"

using namespace std;
using namespace testing;

USE_DEBUG_FLAG(D_CONNECTION);

static ostream &
operator<<(ostream &os, const BufferedMessage &)
{
    return os;
}

class TestConnectionComp : public testing::Test
{
public:
    TestConnectionComp()
    {
        Debug::setUnitTestFlag(D_CONNECTION, Debug::DebugLevel::TRACE);
        connection_comp.init();
        i_conn = Singleton::Consume<I_MessagingConnection>::from(connection_comp);
        setAgentDetails();
        dummy_socket.init();
    }

    void
    setAgentDetails()
    {
        EXPECT_CALL(mock_agent_details, getFogDomain()).WillRepeatedly(Return(string(fog_addr)));
        EXPECT_CALL(mock_agent_details, getFogPort()).WillRepeatedly(Return(fog_port));
        EXPECT_CALL(mock_agent_details, getOpenSSLDir()).WillRepeatedly(Return(string("/usr/lib/ssl/certs/")));
        EXPECT_CALL(mock_agent_details, getAccessToken()).WillRepeatedly(Return(string("accesstoken")));
    }

    const string fog_addr = "127.0.0.1";
    int fog_port = 8080;
    CPTestTempfile agent_details_file;
    ConnectionComponent connection_comp;
    I_MessagingConnection *i_conn;
    ::Environment env;
    ConfigComponent config;
    NiceMock<MockMessagingBuffer> mock_messaging_buffer;
    NiceMock<MockAgentDetails> mock_agent_details;
    NiceMock<MockTimeGet> mock_timer;
    NiceMock<MockMainLoop> mock_mainloop;
    StrictMock<MockEncryptor> mock_encryptor;
    DummySocket dummy_socket;
};

TEST_F(TestConnectionComp, testSetAndGetFogConnection)
{
    Flags<MessageConnectionConfig> conn_flags;
    conn_flags.setFlag(MessageConnectionConfig::UNSECURE_CONN);
    MessageMetadata conn_metadata(fog_addr, fog_port, conn_flags);
    auto maybe_connection = i_conn->establishConnection(conn_metadata, MessageCategory::GENERIC);
    ASSERT_TRUE(maybe_connection.ok());

    auto maybe_get_connection = i_conn->getFogConnectionByCategory(MessageCategory::GENERIC);
    ASSERT_TRUE(maybe_get_connection.ok());
}

TEST_F(TestConnectionComp, testSetAndGetConnection)
{
    Flags<MessageConnectionConfig> conn_flags;
    conn_flags.setFlag(MessageConnectionConfig::UNSECURE_CONN);
    MessageMetadata conn_metadata("127.0.0.1", 8080, conn_flags);
    conn_metadata.setCAPath("ca.pem");
    conn_metadata.setDualAuthenticationSettings("ca_client.pem", "private_client.key");
    auto maybe_connection = i_conn->establishConnection(conn_metadata, MessageCategory::LOG);
    ASSERT_TRUE(maybe_connection.ok());

    auto maybe_get_connection = i_conn->getPersistentConnection("127.0.0.1", 8080, MessageCategory::LOG);
    ASSERT_TRUE(maybe_get_connection.ok());
    auto get_conn = maybe_get_connection.unpack();
    EXPECT_EQ(get_conn.getConnKey().getHostName(), "127.0.0.1");
    EXPECT_EQ(get_conn.getConnKey().getPort(), 8080);
    EXPECT_EQ(get_conn.getConnKey().getCategory(), MessageCategory::LOG);
}

TEST_F(TestConnectionComp, testEstablishNewConnection)
{
    Flags<MessageConnectionConfig> conn_flags;
    conn_flags.setFlag(MessageConnectionConfig::UNSECURE_CONN);
    conn_flags.setFlag(MessageConnectionConfig::ONE_TIME_CONN);
    MessageMetadata conn_metadata("127.0.0.1", 8080, conn_flags);
    conn_metadata.setExternalCertificate("external cert");

    auto maybe_connection = i_conn->establishConnection(conn_metadata, MessageCategory::LOG);
    ASSERT_TRUE(maybe_connection.ok());
    auto get_conn = maybe_connection.unpack();
    EXPECT_EQ(get_conn.getConnKey().getHostName(), "127.0.0.1");
}

TEST_F(TestConnectionComp, testSendRequest)
{
    Flags<MessageConnectionConfig> conn_flags;
    conn_flags.setFlag(MessageConnectionConfig::UNSECURE_CONN);
    MessageMetadata conn_metadata("127.0.0.1", 8080, conn_flags);

    auto maybe_connection = i_conn->establishConnection(conn_metadata, MessageCategory::LOG);
    ASSERT_TRUE(maybe_connection.ok());
    auto conn = maybe_connection.unpack();

    auto req = HTTPRequest::prepareRequest(conn, HTTPMethod::POST, "/test", conn_metadata.getHeaders(), "test-body");
    ASSERT_TRUE(req.ok());

    ON_CALL(mock_mainloop, yield(false))
        .WillByDefault(
            InvokeWithoutArgs(
                [&] ()
                {
                    dummy_socket.acceptSocket();
                    dummy_socket.writeToSocket("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nmy-test");
                }
            )
        );

    EXPECT_CALL(mock_timer, getMonotonicTime())
        .WillRepeatedly(Invoke([] () {static int j = 0; return chrono::microseconds(++j * 1000 * 1000);}));
    auto maybe_response = i_conn->sendRequest(conn, *req);
    ASSERT_TRUE(maybe_response.ok());
    EXPECT_EQ((*maybe_response).getBody(), "my-test");

    string expected_msg =
        "POST /test HTTP/1.1\r\n"
        "Accept-Encoding: identity\r\n"
        "Authorization: Bearer accesstoken\r\n"
        "Connection: keep-alive\r\n"
        "Content-Length: 9\r\n"
        "Content-type: application/json\r\n"
        "Host: 127.0.0.1\r\n"
        "\r\n"
        "test-body";
    EXPECT_EQ(dummy_socket.readFromSocket(), expected_msg);
}

TEST_F(TestConnectionComp, testCloseConnectionBeforeResponse)
{
    // Create a connection
    Flags<MessageConnectionConfig> conn_flags;
    conn_flags.setFlag(MessageConnectionConfig::UNSECURE_CONN);
    MessageMetadata conn_metadata("127.0.0.1", 8080, conn_flags);

    // Insert the connection to the map
    auto maybe_connection = i_conn->establishConnection(conn_metadata, MessageCategory::LOG);
    ASSERT_TRUE(maybe_connection.ok());

    // Get the connection from the map - Should be successful
    auto maybe_get_connection = i_conn->getPersistentConnection("127.0.0.1", 8080, MessageCategory::LOG);
    ASSERT_TRUE(maybe_get_connection.ok());
    auto conn = maybe_get_connection.unpack();

    auto req = HTTPRequest::prepareRequest(conn, HTTPMethod::POST, "/test", conn_metadata.getHeaders(), "test-body");
    ASSERT_TRUE(req.ok());

    // force the connection to be closed
    ON_CALL(mock_mainloop, yield(false)).WillByDefault(InvokeWithoutArgs([&] () { return; }));

    EXPECT_CALL(mock_timer, getMonotonicTime())
        .WillRepeatedly(Invoke([] () {static int j = 0; return chrono::microseconds(++j * 1000 * 1000);}));

    auto maybe_response = i_conn->sendRequest(conn, *req);
    ASSERT_TRUE(!maybe_response.ok());
    ASSERT_EQ(
        maybe_response.getErr().toString(),
        "[Status-code]: -1 - HTTP_UNKNOWN, [Body]: Failed to receive all data in time"
    );

    auto maybe_get_closed_connection = i_conn->getPersistentConnection("127.0.0.1", 8080, MessageCategory::LOG);
    ASSERT_TRUE(!maybe_get_closed_connection.ok());
    ASSERT_EQ(maybe_get_closed_connection.getErr(), "The connection needs to reestablish");
}

TEST_F(TestConnectionComp, testSendRequestReplyChunked)
{
    Flags<MessageConnectionConfig> conn_flags;
    conn_flags.setFlag(MessageConnectionConfig::UNSECURE_CONN);
    MessageMetadata conn_metadata("127.0.0.1", 8080, conn_flags);

    auto maybe_connection = i_conn->establishConnection(conn_metadata, MessageCategory::LOG);
    ASSERT_TRUE(maybe_connection.ok());
    auto conn = maybe_connection.unpack();

    auto req = HTTPRequest::prepareRequest(conn, HTTPMethod::POST, "/test", conn_metadata.getHeaders(), "test-body");
    ASSERT_TRUE(req.ok());

    ON_CALL(mock_mainloop, yield(false))
        .WillByDefault(
            InvokeWithoutArgs(
                [&] ()
                {
                    dummy_socket.acceptSocket();
                    string msg =
                        "HTTP/1.1 200 OK\r\n"
                        "Transfer-Encoding: chunked\r\n"
                        "\r\n"
                        "3\r\n"
                        "my-\r\n"
                        "4\r\n"
                        "test\r\n"
                        "0\r\n"
                        "\r\n";
                    dummy_socket.writeToSocket(msg);
                }
            )
        );

    EXPECT_CALL(mock_timer, getMonotonicTime())
        .WillRepeatedly(Invoke([] () {static int j = 0; return chrono::microseconds(++j * 1000 * 1000);}));
    auto maybe_response = i_conn->sendRequest(conn, *req);
    ASSERT_TRUE(maybe_response.ok());
    EXPECT_EQ((*maybe_response).getHTTPStatusCode(), HTTPStatusCode::HTTP_OK);
    EXPECT_EQ((*maybe_response).getBody(), "my-test");
    EXPECT_EQ((*maybe_response).toString(), "[Status-code]: 200 - HTTP_OK, [Body]: my-test");
}

TEST_F(TestConnectionComp, testEstablishNewProxyConnection)
{
    Flags<MessageConnectionConfig> conn_flags;
    conn_flags.setFlag(MessageConnectionConfig::UNSECURE_CONN);
    MessageMetadata conn_metadata("1.1.1.1", 9000, conn_flags);

    MessageProxySettings proxy_settings("127.0.0.1", "oren", 8080);
    conn_metadata.setProxySettings(proxy_settings);

    //ON_CALL(mock_encryptor, base64Encode("oren")).WillByDefault(Return("encoded_oren"));
    EXPECT_CALL(mock_encryptor, base64Encode("oren")).WillRepeatedly(Return("encoded_oren"));

    ON_CALL(mock_mainloop, yield(false))
        .WillByDefault(
            InvokeWithoutArgs(
                [&] ()
                {
                    dummy_socket.acceptSocket();
                    dummy_socket.writeToSocket("HTTP/1.1 200 OK\r\n\r\n");
                }
            )
        );

    auto maybe_connection = i_conn->establishConnection(conn_metadata, MessageCategory::LOG);
}

TEST_F(TestConnectionComp, testSendRequestWithOneTimeFogConnection)
{
    Flags<MessageConnectionConfig> conn_flags;
    conn_flags.setFlag(MessageConnectionConfig::UNSECURE_CONN);
    conn_flags.setFlag(MessageConnectionConfig::ONE_TIME_FOG_CONN);
    MessageMetadata conn_metadata(fog_addr, fog_port, conn_flags);

    auto maybe_connection = i_conn->establishConnection(conn_metadata, MessageCategory::LOG);
    ASSERT_TRUE(maybe_connection.ok());
    auto conn = maybe_connection.unpack();

    auto req = HTTPRequest::prepareRequest(conn, HTTPMethod::POST, "/test", conn_metadata.getHeaders(), "test-body");
    ASSERT_TRUE(req.ok());

    EXPECT_CALL(mock_mainloop, yield(A<std::chrono::microseconds>()))
        .WillOnce(
            InvokeWithoutArgs(
                [&]() {
                    cerr << "accepting socket" << endl;
                    dummy_socket.acceptSocket();
                    dummy_socket.writeToSocket("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nmy-test");
                }
            )
        ).WillRepeatedly(Return());

    EXPECT_CALL(mock_timer, getMonotonicTime())
        .WillRepeatedly(Invoke([]() { static int j = 0; return chrono::microseconds(++j * 10); }));

    auto maybe_response = i_conn->sendRequest(conn, *req);
    if (!maybe_response.ok()) {
        cout << "Error: " << maybe_response.getErr().toString() << endl;
    }
    ASSERT_TRUE(maybe_response.ok());
    EXPECT_EQ((*maybe_response).getBody(), "my-test");

    string expected_msg =
        "POST /test HTTP/1.1\r\n"
        "Accept-Encoding: identity\r\n"
        "Authorization: Bearer accesstoken\r\n"
        "Connection: keep-alive\r\n"
        "Content-Length: 9\r\n"
        "Content-type: application/json\r\n"
        "Host: 127.0.0.1\r\n"
        "\r\n"
        "test-body";
    EXPECT_EQ(dummy_socket.readFromSocket(), expected_msg);
}
