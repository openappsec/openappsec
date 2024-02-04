#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

using namespace std;
using namespace testing;

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

        string config_json =
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

        istringstream ss(config_json);
        Singleton::Consume<Config::I_Config>::from(config)->loadConfiguration(ss);

        Debug::setUnitTestFlag(D_API, Debug::DebugLevel::NOISE);
        Debug::setUnitTestFlag(D_MAINLOOP, Debug::DebugLevel::NOISE);
        Debug::setNewDefaultStdout(&capture_debug);
    }

    ~RestConfigTest()
    {
        Debug::setNewDefaultStdout(&cout);
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
    Singleton::Consume<I_Environment>::from(env)->registerValue<string>("Executable Name", "tmp_test_file");

    config.preload();
    config.init();

    rest_server.init();
    time_proxy.init();
    mainloop_comp.init();

    auto i_rest = Singleton::Consume<I_RestApi>::from(rest_server);
    ASSERT_TRUE(i_rest->addRestCall<TestServer>(RestAction::ADD, "test"));

    int file_descriptor =  socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_NE(file_descriptor, -1);

    auto primary_port = getConfiguration<uint>("connection", "Nano service API Port Alternative");
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(primary_port.unpack());
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");
    int socket_enable = 1;
    EXPECT_EQ(setsockopt(file_descriptor, SOL_SOCKET, SO_REUSEADDR, &socket_enable, sizeof(int)), 0);

    EXPECT_CALL(messaging, sendSyncMessage(_, _, _, _, _))
        .WillRepeatedly(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, "")));

    auto mainloop = Singleton::Consume<I_MainLoop>::from(mainloop_comp);
    I_MainLoop::Routine stop_routine = [&] () {
        EXPECT_EQ(connect(file_descriptor, (struct sockaddr*)&sa, sizeof(struct sockaddr)), 0);
        string msg = "POST /add-test HTTP/1.1\r\nContent-Length: 10\r\n\r\n{\"num\": 5}";
        EXPECT_EQ(write(file_descriptor, msg.data(), msg.size()), msg.size());

        while(!TestServer::g_num) {
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
}
