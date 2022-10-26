#include "health_checker.h"

#include "cptest.h"
#include "agent_details.h"
#include "mock/mock_logging.h"
#include "mock/mock_time_get.h"
#include "mock/mock_socket_is.h"
#include "mock/mock_mainloop.h"
#include "health_check_manager.h"

#include "config.h"
#include "config_component.h"
#include "singleton.h"
#include "environment.h"

using namespace std;
using namespace testing;

USE_DEBUG_FLAG(D_HEALTH_CHECK);

class HealthCheckerTest : public testing::Test
{
public:
    HealthCheckerTest()
    {
        setConfiguration(true, "Health Check", "Probe enabled");
        i_health_check_manager = Singleton::Consume<I_Health_Check_Manager>::from(health_check_manager);
        Debug::setUnitTestFlag(D_HEALTH_CHECK, Debug::DebugLevel::TRACE);
        Debug::setNewDefaultStdout(&capture_debug);
    }

    ~HealthCheckerTest()
    {
        Debug::setNewDefaultStdout(&cout);

        if (server_socket > 0) {
            EXPECT_THAT(capture_debug.str(), HasSubstr("Server socket closed"));
            EXPECT_CALL(mock_socket, closeSocket(server_socket));
        }
        health_checker.fini();
    }

    ostringstream                       capture_debug;
    StrictMock<MockMainLoop>            mock_mainloop;
    NiceMock<MockTimeGet>               mock_time_get;
    ::Environment                       env;
    NiceMock<MockLogging>               mock_log;
    AgentDetails                        agent_details;
    StrictMock<MockSocketIS>            mock_socket;
    I_Socket::socketFd                  server_socket = -1;
    Context                             ctx;
    ConfigComponent                     config;
    HealthChecker                       health_checker;
    I_MainLoop::Routine                 connection_handler_routine;
    I_MainLoop::Routine                 client_connection_handler_routine;
    I_MainLoop::Routine                 handle_probe_routine;
    //StrictMock<MockHealthCheckManager>  mock_health_check_manager;
    HealthCheckManager                  health_check_manager;
    I_Health_Check_Manager              *i_health_check_manager;
};

TEST_F(HealthCheckerTest, empty)
{
}

TEST_F(HealthCheckerTest, load_policy)
{
    health_checker.preload();
    health_checker.init();

    stringstream config;
    config << "{}";
    EXPECT_TRUE(Singleton::Consume<Config::I_Config>::from<ConfigComponent>()->loadConfiguration(config));
}

TEST_F(HealthCheckerTest, clientConnection)
{
    string ip = "1.2.3.4";
    setConfiguration(ip, "Health Check", "Probe IP");
    uint port = 11600;
    setConfiguration(port, "Health Check", "Probe port");

    EXPECT_CALL(
        mock_mainloop,
        addOneTimeRoutine(I_MainLoop::RoutineType::System, _, _, false)
    ).WillOnce(DoAll(SaveArg<1>(&handle_probe_routine), Return(0)));

    EXPECT_CALL(
        mock_socket,
        genSocket(I_Socket::SocketType::TCP, false, true, _)
    ).WillRepeatedly(Return(1));

    EXPECT_CALL(
        mock_mainloop,
        addFileRoutine(I_MainLoop::RoutineType::RealTime, _, _, _, true)
    ).WillRepeatedly(DoAll(SaveArg<2>(&connection_handler_routine), Return(0)));

    int socket = 1;
    EXPECT_CALL(mock_socket, acceptSocket(1, false, ip)).WillOnce(Return(socket));
    EXPECT_CALL(mock_mainloop, getCurrentRoutineId()).WillRepeatedly(Return(0));
    EXPECT_CALL(mock_socket, receiveData(_, 1, false)).WillOnce(Return(vector<char>()));
    EXPECT_CALL(mock_socket, closeSocket(socket)).Times(2);
    health_checker.init();
    handle_probe_routine();
    connection_handler_routine();
    connection_handler_routine();
    health_checker.fini();
}

TEST_F(HealthCheckerTest, loadFromDynamicConfiguration)
{
    uint port = 11600;

    EXPECT_CALL(
        mock_socket,
        genSocket(I_Socket::SocketType::TCP, false, true, _)
    ).WillRepeatedly(Return(1));

    EXPECT_CALL(
        mock_mainloop,
        addFileRoutine(I_MainLoop::RoutineType::RealTime, _, _, _, true)
    ).WillRepeatedly(DoAll(SaveArg<2>(&connection_handler_routine), Return(0)));

    health_checker.init();
    health_checker.preload();
    EXPECT_THAT(
        capture_debug.str(),
        HasSubstr(
            "Cannot initialize health check component, "
            "listening port was not provided. Please provide valid port (>0)."
        )
    );

    setConfiguration(string("1.2.3.4"), "Health Check", "Probe IP");
    setConfiguration(port, "Health Check", "Probe port");
}

TEST_F(HealthCheckerTest, connectionsLimit)
{
    string ip = "1.2.3.4";
    setConfiguration(ip, "Health Check", "Probe IP");
    uint port = 11600;
    setConfiguration(port, "Health Check", "Probe port");
    uint a = 0;
    setConfiguration(a, "Health Check", "Probe maximun open connections");

    EXPECT_CALL(
        mock_mainloop,
        addOneTimeRoutine(I_MainLoop::RoutineType::System, _, _, false)
    ).WillOnce(DoAll(SaveArg<1>(&handle_probe_routine), Return(0)));

    EXPECT_CALL(
        mock_socket,
        genSocket(I_Socket::SocketType::TCP, false, true, _)
    ).WillRepeatedly(Return(1));

    EXPECT_CALL(
        mock_mainloop,
        addFileRoutine(I_MainLoop::RoutineType::RealTime, _, _, _, true)
    ).WillRepeatedly(DoAll(SaveArg<2>(&connection_handler_routine), Return(0)));

    EXPECT_CALL(mock_mainloop, doesRoutineExist(_)).WillRepeatedly(Return(false));
    EXPECT_CALL(mock_socket, acceptSocket(1, false, ip)).WillRepeatedly(Return(1));
    EXPECT_CALL(mock_socket, receiveData(_, 1, false)).WillRepeatedly(Return(vector<char>()));
    EXPECT_CALL(mock_socket, closeSocket(_)).WillRepeatedly(Return());
    health_checker.init();
    handle_probe_routine();
    connection_handler_routine();

    EXPECT_THAT(
        capture_debug.str(), HasSubstr("Cannot serve new client, reached maximun open connections")
    );
}

TEST_F(HealthCheckerTest, disablingAfterEnabled)
{
    string ip = "1.2.3.4";
    setConfiguration(ip, "Health Check", "Probe IP");
    uint port = 11600;
    setConfiguration(port, "Health Check", "Probe port");

    EXPECT_CALL(
        mock_mainloop,
        addOneTimeRoutine(I_MainLoop::RoutineType::System, _, _, false)
    ).WillOnce(DoAll(SaveArg<1>(&handle_probe_routine), Return(0)));

    EXPECT_CALL(
        mock_socket,
        genSocket(I_Socket::SocketType::TCP, false, true, _)
    ).WillRepeatedly(Return(1));

    EXPECT_CALL(
        mock_mainloop,
        addFileRoutine(I_MainLoop::RoutineType::RealTime, _, _, _, true)
    ).WillRepeatedly(DoAll(SaveArg<2>(&connection_handler_routine), Return(0)));

    int socket = 1;
    EXPECT_CALL(mock_socket, acceptSocket(1, false, ip)).WillOnce(Return(socket));
    EXPECT_CALL(mock_mainloop, getCurrentRoutineId()).WillRepeatedly(Return(0));
    EXPECT_CALL(mock_socket, receiveData(_, 1, false)).WillOnce(Return(vector<char>()));
    EXPECT_CALL(mock_socket, closeSocket(socket)).Times(2);
    health_checker.init();
    handle_probe_routine();
    connection_handler_routine();
    connection_handler_routine();
    setConfiguration(false, "Health Check", "Probe enabled");
}

TEST_F(HealthCheckerTest, noPort)
{
    health_checker.init();
    health_checker.preload();

    EXPECT_THAT(
        capture_debug.str(),
        HasSubstr(
            "Cannot initialize health check component, "
            "listening port was not provided. Please provide valid port (>0)."
        )
    );
}

TEST_F(HealthCheckerTest, changePortIpConfig)
{
    string ip = "1.2.3.4";
    setConfiguration(ip, "Health Check", "Probe IP");
    uint port = 11600;
    setConfiguration(port, "Health Check", "Probe port");

    EXPECT_CALL(
        mock_mainloop,
        addOneTimeRoutine(I_MainLoop::RoutineType::System, _, _, false)
    ).WillOnce(DoAll(SaveArg<1>(&handle_probe_routine), Return(0)));

    EXPECT_CALL(
        mock_socket,
        genSocket(I_Socket::SocketType::TCP, false, true, _)
    ).WillRepeatedly(Return(1));

    EXPECT_CALL(
        mock_mainloop,
        addFileRoutine(I_MainLoop::RoutineType::RealTime, _, _, _, true)
    ).WillRepeatedly(DoAll(SaveArg<2>(&connection_handler_routine), Return(0)));

    int socket = 1;
    EXPECT_CALL(mock_socket, acceptSocket(1, false, ip)).WillOnce(Return(socket));
    EXPECT_CALL(mock_mainloop, getCurrentRoutineId()).WillRepeatedly(Return(0));
    EXPECT_CALL(mock_socket, receiveData(_, 1, false)).Times(2).WillRepeatedly(Return(vector<char>()));
    EXPECT_CALL(mock_socket, closeSocket(socket)).Times(2);
    health_checker.init();
    handle_probe_routine();
    connection_handler_routine();
    connection_handler_routine();
    setConfiguration(false, "Health Check", "Probe enabled");
    string new_ip = "1.1.1.1";
    setConfiguration(new_ip, "Health Check", "Probe IP");
    uint new_port = 11111;
    setConfiguration(new_port, "Health Check", "Probe port");
    connection_handler_routine();
}
