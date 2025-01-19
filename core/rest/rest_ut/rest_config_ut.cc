#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

#include "cptest.h"
#include "environment.h"
#include "config.h"
#include "config_component.h"
#include "singleton.h"
#include "time_proxy.h"
#include "mainloop.h"
#include "rest_server.h"
#include "agent_details.h"
#include "mock/mock_messaging.h"
#include "tenant_manager.h"
#include <netdb.h>
#include <arpa/inet.h>

using namespace std;
using namespace testing;

static const string config_json_allow_external =
        "{\n"
        "    \"connection\": {\n"
        "        \"Nano service API Port Primary\": [\n"
        "            {\n"
        "                \"value\": 9777\n"
        "            }\n"
        "        ],\n"
        "        \"Nano service API Port Alternative\": [\n"
        "            {\n"
        "                \"value\": 9778\n"
        "            }\n"
        "        ],\n"
        "        \"Nano service API Allow Get From External IP\": [\n"
        "            {\n"
        "                \"value\": true\n"
        "            }\n"
        "        ]\n"
        "    }\n"
        "}\n";

static const string config_json =
        "{\n"
        "    \"connection\": {\n"
        "        \"Nano service API Port Primary\": [\n"
        "            {\n"
        "                \"value\": 9777\n"
        "            }\n"
        "        ],\n"
        "        \"Nano service API Port Alternative\": [\n"
        "            {\n"
        "                \"value\": 9778\n"
        "            }\n"
        "        ]\n"
        "    }\n"
        "}\n";

USE_DEBUG_FLAG(D_API);
USE_DEBUG_FLAG(D_MAINLOOP);

class RestConfigTest : public Test
{
public:
    RestConfigTest()
    {
        rest_server.preload();

        time_proxy.init();
        mainloop_comp.init();

        istringstream ss(config_json);
        Singleton::Consume<Config::I_Config>::from(config)->loadConfiguration(ss);

        Debug::setUnitTestFlag(D_API, Debug::DebugLevel::NOISE);
        Debug::setUnitTestFlag(D_MAINLOOP, Debug::DebugLevel::NOISE);
        Debug::setNewDefaultStdout(&capture_debug);
    }

    ~RestConfigTest()
    {
        Debug::setNewDefaultStdout(&cout);
        auto mainloop = Singleton::Consume<I_MainLoop>::from(mainloop_comp);
        mainloop->stopAll();
        rest_server.fini();
        time_proxy.fini();
        mainloop_comp.fini();
    }

    ostringstream capture_debug;
    TimeProxyComponent time_proxy;
    MainloopComponent mainloop_comp;
    ::Environment env;
    ConfigComponent config;
    RestServer rest_server;
    TenantManager tenant_manager;
    AgentDetails agent_details;
    NiceMock<MockMessaging> messaging;
};

TEST_F(RestConfigTest, alternative_port_used)
{
    int file_descriptor =  socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_NE(file_descriptor, -1);

    auto primary_port = getConfiguration<uint>("connection", "Nano service API Port Primary");
    EXPECT_TRUE(primary_port.ok());

    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(primary_port.unpack());
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");
    int socket_enable = 1;
    EXPECT_EQ(setsockopt(file_descriptor, SOL_SOCKET, SO_REUSEADDR, &socket_enable, sizeof(int)), 0);
    EXPECT_EQ(bind(file_descriptor, reinterpret_cast<struct sockaddr *>(&sa), sizeof(struct sockaddr_in)), 0);
    EXPECT_EQ(listen(file_descriptor, 1), 0);

    auto alternative_port = getConfiguration<uint>("connection", "Nano service API Port Alternative");
    EXPECT_TRUE(alternative_port.ok());

    rest_server.init();

    file_descriptor =  socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_NE(file_descriptor, -1);

    auto mainloop = Singleton::Consume<I_MainLoop>::from(mainloop_comp);
    I_MainLoop::Routine stop_routine = [mainloop] () { mainloop->stopAll(); };
    mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::RealTime,
        stop_routine,
        "RestConfigTest-alternative_port_used stop routine",
        false
    );
    mainloop->run();

    EXPECT_EQ(Singleton::Consume<I_RestApi>::from(rest_server)->getListeningPort(), *alternative_port);

    sa.sin_port = htons(alternative_port.unpack());
    EXPECT_EQ(bind(file_descriptor, reinterpret_cast<struct sockaddr *>(&sa), sizeof(struct sockaddr_in)), -1);

    EXPECT_THAT(capture_debug.str(), HasSubstr("REST server started: " + to_string(alternative_port.unpack())));

    rest_server.fini();
    close(file_descriptor);
}

class TestServer : public ServerRest
{
    void doCall() override { g_num = num; }

    C2S_PARAM(int, num);
public:
    static int g_num;
};

int TestServer::g_num = 0;

TEST_F(RestConfigTest, basic_flow)
{
    env.preload();
    Singleton::Consume<I_Environment>::from(env)->registerValue<string>("Base Executable Name", "tmp_test_file");

    config.preload();
    config.init();

    rest_server.init();
    time_proxy.init();
    mainloop_comp.init();

    auto i_rest = Singleton::Consume<I_RestApi>::from(rest_server);
    ASSERT_TRUE(i_rest->addRestCall<TestServer>(RestAction::ADD, "test"));
    ASSERT_TRUE(i_rest->addGetCall("stuff", [] () { return string("blabla"); }));
    ASSERT_TRUE(
        i_rest->addWildcardGetCall("api/", [] (const string &uri) { return uri.substr(uri.find_last_of('/') + 1); })
    );

    int file_descriptor1 = socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_NE(file_descriptor1, -1);
    int file_descriptor2 = socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_NE(file_descriptor2, -1);
    int file_descriptor3 = socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_NE(file_descriptor3, -1);

    auto primary_port = getConfiguration<uint>("connection", "Nano service API Port Alternative");
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(primary_port.unpack());
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");
    int socket_enable = 1;
    EXPECT_EQ(setsockopt(file_descriptor1, SOL_SOCKET, SO_REUSEADDR, &socket_enable, sizeof(int)), 0);
    EXPECT_EQ(setsockopt(file_descriptor2, SOL_SOCKET, SO_REUSEADDR, &socket_enable, sizeof(int)), 0);
    EXPECT_EQ(setsockopt(file_descriptor3, SOL_SOCKET, SO_REUSEADDR, &socket_enable, sizeof(int)), 0);

    EXPECT_CALL(messaging, sendSyncMessage(_, _, _, _, _))
        .WillRepeatedly(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, "")));

    auto mainloop = Singleton::Consume<I_MainLoop>::from(mainloop_comp);
    I_MainLoop::Routine stop_routine = [&] () {
        EXPECT_EQ(connect(file_descriptor1, (struct sockaddr*)&sa, sizeof(struct sockaddr)), 0)
            << "file_descriptor1 Error: "
            << strerror(errno);
        string msg1 = "GET /stuff HTTP/1.1\r\n\r\n";
        EXPECT_EQ(write(file_descriptor1, msg1.data(), msg1.size()), static_cast<int>(msg1.size()));

        EXPECT_EQ(connect(file_descriptor2, (struct sockaddr*)&sa, sizeof(struct sockaddr)), 0)
            << "file_descriptor2 Error: "
            << strerror(errno);
        string msg2 = "POST /add-test HTTP/1.1\r\nContent-Length: 10\r\n\r\n{\"num\": 5}";
        EXPECT_EQ(write(file_descriptor2, msg2.data(), msg2.size()), static_cast<int>(msg2.size()));

        EXPECT_EQ(connect(file_descriptor3, (struct sockaddr*)&sa, sizeof(struct sockaddr)), 0)
            << "file_descriptor3 Error: "
            << strerror(errno);
        string msg3 = "GET /api/123 HTTP/1.1\r\n\r\n";
        EXPECT_EQ(write(file_descriptor3, msg3.data(), msg3.size()), static_cast<int>(msg3.size()));
        while(!TestServer::g_num) {
            mainloop->yield(true);
        }

        struct pollfd s_poll;
        s_poll.fd = file_descriptor1;
        s_poll.events = POLLIN;
        s_poll.revents = 0;
        while(poll(&s_poll, 1, 0) <= 0) {
            mainloop->yield(true);
        }

        struct pollfd s_poll3;
        s_poll3.fd = file_descriptor3;
        s_poll3.events = POLLIN;
        s_poll3.revents = 0;
        while(poll(&s_poll3, 1, 0) <= 0) {
            mainloop->yield(true);
        }

        mainloop->stopAll();
    };
    mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::RealTime,
        stop_routine,
        "RestConfigTest-alternative_port_used stop routine",
        true
    );
    mainloop->run();

    EXPECT_EQ(TestServer::g_num, 5);

    char respose[1000];
    EXPECT_EQ(read(file_descriptor1, respose, 1000), 76);
    EXPECT_EQ(
        string(respose, 76),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 6\r\n\r\nblabla"
    );
    EXPECT_EQ(read(file_descriptor3, respose, 1000), 73);
    EXPECT_EQ(
        string(respose, 73),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 3\r\n\r\n123"
    );
}

string
getLocalIPAddress() {
    char hostname[1024];
    hostname[1024 - 1] = '\0';

    // Get the hostname
    if (gethostname(hostname, sizeof(hostname)) == -1) {
        return "";
    }

    struct addrinfo hints, *info, *p;
    int gai_result;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // Use AF_INET for IPv4
    hints.ai_socktype = SOCK_STREAM;

    // Get the address info
    if ((gai_result = getaddrinfo(hostname, nullptr, &hints, &info)) != 0) {
        return "";
    }

    std::string ip_address;
    for (p = info; p != nullptr; p = p->ai_next) {
        void *addr;
        char ipstr[INET_ADDRSTRLEN];

        struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
        addr = &(ipv4->sin_addr);

        // Convert the IP to a string and print it
        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
        if (std::string(ipstr) != "127.0.0.1") {
            ip_address = ipstr;
            break;
        }
    }

    freeaddrinfo(info); // Free the linked list

    return ip_address;
}


TEST_F(RestConfigTest, not_loopback_flow)
{
    env.preload();
    Singleton::Consume<I_Environment>::from(env)->registerValue<string>("Executable Name", "tmp_test_file");


    istringstream ss(config_json_allow_external);
    Singleton::Consume<Config::I_Config>::from(config)->loadConfiguration(ss);

    config.preload();
    config.init();

    rest_server.init();
    time_proxy.init();
    mainloop_comp.init();

    auto i_rest = Singleton::Consume<I_RestApi>::from(rest_server);
    ASSERT_TRUE(i_rest->addRestCall<TestServer>(RestAction::ADD, "test"));
    ASSERT_TRUE(i_rest->addGetCall("stuff", [] () { return string("blabla"); }));

    int file_descriptor1 = socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_NE(file_descriptor1, -1);
    int file_descriptor2 = socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_NE(file_descriptor2, -1);

    auto primary_port = getConfiguration<uint>("connection", "Nano service API Port Primary");
    auto second_port = getConfiguration<uint>("connection", "Nano service API Port Alternative");
    auto local_ip = getLocalIPAddress();
    struct sockaddr_in sa_primary;
    sa_primary.sin_family = AF_INET;
    sa_primary.sin_port = htons(primary_port.unpack());
    sa_primary.sin_addr.s_addr = inet_addr(local_ip.c_str());
    struct sockaddr_in sa_second;
    sa_second.sin_family = AF_INET;
    sa_second.sin_port = htons(second_port.unpack());
    sa_second.sin_addr.s_addr = inet_addr(local_ip.c_str());

    int socket_enable = 1;
    EXPECT_EQ(setsockopt(file_descriptor1, SOL_SOCKET, SO_REUSEADDR, &socket_enable, sizeof(int)), 0);
    EXPECT_EQ(setsockopt(file_descriptor2, SOL_SOCKET, SO_REUSEADDR, &socket_enable, sizeof(int)), 0);

    EXPECT_CALL(messaging, sendSyncMessage(_, _, _, _, _))
            .WillRepeatedly(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, "")));
    Debug::setNewDefaultStdout(&cout);
    auto mainloop = Singleton::Consume<I_MainLoop>::from(mainloop_comp);
    Debug::setNewDefaultStdout(&cout);
    I_MainLoop::Routine stop_routine = [&] () {
        int socket_client_2 = -1;
        auto socket_client_1 = connect(file_descriptor1, (struct sockaddr*)&sa_primary, sizeof(struct sockaddr));
        dbgDebug(D_API) <<  "socket_client_1: " << socket_client_1;
        if (socket_client_1 == -1) {
            dbgDebug(D_API) << "Error: " << strerror(errno);
            socket_client_2 = connect(file_descriptor1, (struct sockaddr*)&sa_second, sizeof(struct sockaddr));
            dbgDebug(D_API) << "socket_client_2: " << socket_client_2;
            if (socket_client_2 == -1) {
                dbgDebug(D_API) << "Error: " << strerror(errno) << endl;
            } else {
                EXPECT_EQ(connect(file_descriptor2, (struct sockaddr*)&sa_second, sizeof(struct sockaddr)), 0);
                string msg2 = "POST /add-test HTTP/1.1\r\nContent-Length: 10\r\n\r\n{\"num\": 5}";
                EXPECT_EQ(write(file_descriptor2, msg2.data(), msg2.size()), static_cast<int>(msg2.size()));
            }
        } else {
            EXPECT_EQ(connect(file_descriptor2, (struct sockaddr*)&sa_primary, sizeof(struct sockaddr)), 0);
            string msg2 = "POST /add-test HTTP/1.1\r\nContent-Length: 10\r\n\r\n{\"num\": 5}";
            EXPECT_EQ(write(file_descriptor2, msg2.data(), msg2.size()), static_cast<int>(msg2.size()));
        }
        EXPECT_TRUE(socket_client_1 != -1 || socket_client_2 != -1);
        string msg1 = "GET /stuff HTTP/1.1\r\n\r\n";
        EXPECT_EQ(write(file_descriptor1, msg1.data(), msg1.size()), static_cast<int>(msg1.size()));

        mainloop->yield(true);

        struct pollfd s_poll;
        s_poll.fd = file_descriptor1;
        s_poll.events = POLLIN;
        s_poll.revents = 0;
        while(poll(&s_poll, 1, 0) <= 0) {
            mainloop->yield(true);
        }

        struct pollfd s_poll2;
        s_poll2.fd = file_descriptor2;
        s_poll2.events = POLLIN;
        s_poll2.revents = 0;
        while(poll(&s_poll2, 1, 0) <= 0) {
            mainloop->yield(true);
        }

        mainloop->stopAll();
    };
    mainloop->addOneTimeRoutine(
            I_MainLoop::RoutineType::RealTime,
            stop_routine,
            "RestConfigTest-alternative_port_used stop routine",
            true
    );
    mainloop->run();

    char respose[1000];
    EXPECT_EQ(read(file_descriptor1, respose, 1000), 76);
    EXPECT_EQ(
            string(respose, 76),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 6\r\n\r\nblabla"
    );

    EXPECT_EQ(read(file_descriptor2, respose, 1000), 89);
    EXPECT_EQ(
            string(respose, 89),
            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n"
    );
}
