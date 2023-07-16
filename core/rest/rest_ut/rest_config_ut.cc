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

using namespace std;
using namespace testing;

USE_DEBUG_FLAG(D_API);

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
}
