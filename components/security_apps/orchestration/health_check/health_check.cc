// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "health_checker.h"

#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <unordered_map>

#include "config.h"
#include "log_generator.h"
#include "health_check_manager.h"
#include "agent_core_utilities.h"

using namespace std;
using namespace ReportIS;

USE_DEBUG_FLAG(D_HEALTH_CHECK);

class HealthChecker::Impl
{
public:
    void
    init()
    {
        i_mainloop = Singleton::Consume<I_MainLoop>::by<HealthChecker>();
        i_socket = Singleton::Consume<I_Socket>::by<HealthChecker>();
        initConfig();
        initServerSocket();

        registerConfigLoadCb(
            [&]()
            {
                initConfig();
                initServerSocket();
            }
        );
    }

    void
    initServerSocket()
    {
        if (!enable) {
            return;
        }

        if (!checkInternalHealthCheckStatus()) {
            reportError("Internal health check failed. Wait for restart.");
            return;
        }

        if (port == 0) {
            string error_msg =
                "Cannot initialize health check component, listening port was not provided. "
                "Please provide valid port (>0).";
            reportError(error_msg);
            return;
        }

        if (server_sock == -1) {
            i_mainloop->addOneTimeRoutine(
                I_MainLoop::RoutineType::System,
                [this] () { HandleProbeStartup(); },
                "Health check probe listener startup",
                false
            );
        }
    }

    void
    fini()
    {
        closeConnection();
    }

private:
    bool
    checkInternalHealthCheckStatus()
    {
        dbgTrace(D_HEALTH_CHECK) << "Start agent general health check.";

        HealthCheckStatus status =
            Singleton::Consume<I_Health_Check_Manager>::by<HealthChecker>()->getAggregatedStatus();

        dbgTrace(D_HEALTH_CHECK)
            << "Finished agent general health check. Received aggregated status: "
            << HealthCheckStatusReply::convertHealthCheckStatusToStr(status);

        return status != HealthCheckStatus::UNHEALTHY;
    }

    void
    reportError(const string &error_msg)
    {
        dbgWarning(D_HEALTH_CHECK) << error_msg;
        LogGen(
            error_msg,
            Audience::SECURITY,
            Severity::CRITICAL,
            Priority::URGENT,
            Tags::ORCHESTRATOR
        );
    }

    void
    closeConnection()
    {
        dbgDebug(D_HEALTH_CHECK) << "Closing connection";
        if (server_sock > 0) {
            i_socket->closeSocket(server_sock);
            server_sock = -1;
            dbgDebug(D_HEALTH_CHECK) << "Server socket closed";
        }

        if (routine_id > 0 && i_mainloop->doesRoutineExist(routine_id)) {
            i_mainloop->stop(routine_id);
            routine_id = 0;
        }

        for (auto socket_routine : client_sockets_routines) {
            auto routine = socket_routine.first;
            if (routine > 0 && i_mainloop->doesRoutineExist(routine)) {
                i_mainloop->stop(routine);
            }
            auto socket = socket_routine.second;

            if (socket > 0) {
                i_socket->closeSocket(socket);
            }
        }
        client_sockets_routines.clear();
    }

    void
    initCloudVendorConfig()
    {
        static const map<string, pair<string, int>> ip_port_defaults_map = {
            {"Azure", make_pair(getenv("DOCKER_RPM_ENABLED") ? "" : "168.63.129.16", 8117)},
            {"Aws", make_pair("", 8117)},
            {"Local", make_pair("", 8117)}
        };

        auto cloud_vendor_maybe = getSetting<string>("reverseProxy", "cloudVendorName");
        if (cloud_vendor_maybe.ok()) {
            const string cloud_vendor = cloud_vendor_maybe.unpack();
            auto value = ip_port_defaults_map.find(cloud_vendor);
            if (value != ip_port_defaults_map.end()) {
                const pair<string, uint> &ip_port_pair = value->second;
                ip_address = ip_port_pair.first;
                port = ip_port_pair.second;
                enable = true;
            }
        }

        ip_address = getProfileAgentSettingWithDefault<string>(
            ip_address,
            "agent.config.orchestration.healthCheckProbe.IP"
        );
        port = getProfileAgentSettingWithDefault<uint>(port, "agent.config.orchestration.healthCheckProbe.port");
        enable = getProfileAgentSettingWithDefault<bool>(enable, "agent.config.orchestration.healthCheckProbe.enable");

        ip_address = getConfigurationWithDefault<string>(ip_address, "Health Check", "Probe IP");
        port = getConfigurationWithDefault<uint>(port, "Health Check", "Probe port");
        enable = getConfigurationWithDefault<bool>(enable, "Health Check", "Probe enabled");
    }

    void
    initConfig()
    {
        auto prev_ip_address = ip_address;
        auto prev_port = port;

        initCloudVendorConfig();

        max_connections = getProfileAgentSettingWithDefault<uint>(
            10,
            "agent.config.orchestration.healthCheckProbe.maximunConnections"
        );
        max_connections = getConfigurationWithDefault<uint>(
            max_connections,
            "Health Check",
            "Probe maximun open connections"
        );

        max_retry_interval = getProfileAgentSettingWithDefault<uint>(
            600,
            "agent.config.orchestration.healthCheckProbe.socketReopenPeriod"
        );
        max_retry_interval = getConfigurationWithDefault<uint>(
            max_retry_interval,
            "Health Check",
            "Probe socket reopen period"
        );
        if (!enable) {
            if (server_sock != -1) closeConnection();
            return;
        }

        if (prev_ip_address != ip_address || prev_port != port) {
            if (server_sock != -1) closeConnection();
        }
    }

    void
    HandleProbeStartup()
    {
        size_t next_retry_interval = 1;
        while (server_sock == -1) {
            next_retry_interval =
                next_retry_interval < max_retry_interval ? next_retry_interval*2 : max_retry_interval;
            auto socket = i_socket->genSocket(
                I_Socket::SocketType::TCP,
                false,
                true,
                "0.0.0.0:" + to_string(port)
            );
            if (socket.ok()) {
                dbgInfo(D_HEALTH_CHECK) << "Successfully created probe listener."
                << " port: "
                << port;
                server_sock = socket.unpack();
            } else {
                dbgWarning(D_HEALTH_CHECK)
                    << "Failed to set up socket:"
                    << ", Error: "
                    << socket.getErr()
                    << ", trying again to set up socket in "
                    << next_retry_interval
                    << " seconds";
                i_mainloop->yield(chrono::seconds(next_retry_interval));
            }
        }
        routine_id = i_mainloop->addFileRoutine(
            I_MainLoop::RoutineType::RealTime,
            server_sock,
            [this] () { handleConnection(); },
            "Health check probe server",
            true
        );
    }

    HealthCheckStatus
    getStandaloneHealthStatus()
    {
        if (!getenv("DOCKER_RPM_ENABLED")) return HealthCheckStatus::IGNORED;

        static const string standalone_cmd = "/usr/sbin/cpnano -s --docker-rpm; echo $?";
        static int timeout_tolerance = 1;
        static HealthCheckStatus health_status = HealthCheckStatus::HEALTHY;

        dbgTrace(D_HEALTH_CHECK) << "Checking the standalone docker health status with command: " << standalone_cmd;

        auto maybe_result = Singleton::Consume<I_ShellCmd>::by<HealthChecker>()->getExecOutput(standalone_cmd, 5000);
        if (!maybe_result.ok()) {
            if (maybe_result.getErr().find("Reached timeout") != string::npos) {
                dbgWarning(D_HEALTH_CHECK)
                    << "Reached timeout while querying standalone health status, attempt number: "
                    << timeout_tolerance;

                return health_status == HealthCheckStatus::UNHEALTHY || timeout_tolerance++ > 3 ?
                    HealthCheckStatus::UNHEALTHY :
                    health_status;
            }

            dbgWarning(D_HEALTH_CHECK) << "Unable to get the standalone docker status. Returning unhealthy status.";
            return HealthCheckStatus::UNHEALTHY;
        }
        dbgTrace(D_HEALTH_CHECK) << "Got response: " << maybe_result.unpack();

        auto response = NGEN::Strings::removeTrailingWhitespaces(maybe_result.unpack());

        if (response.back() == '1') return health_status = HealthCheckStatus::UNHEALTHY;

        timeout_tolerance = 1;
        return health_status = (response.back() == '0') ? HealthCheckStatus::HEALTHY : HealthCheckStatus::DEGRADED;
    }

    bool
    nginxContainerIsRunning()
    {
        static const string nginx_container_name = "cp_nginx_gaia";
        static const string cmd_running =
            "docker ps --filter name=" + nginx_container_name + " --filter status=running";
        dbgTrace(D_HEALTH_CHECK) << "Checking if the container is running with the command: " << cmd_running;

        auto maybe_result = Singleton::Consume<I_ShellCmd>::by<HealthChecker>()->getExecOutput(cmd_running);
        if (!maybe_result.ok()) {
            dbgWarning(D_HEALTH_CHECK)
                << "Unable to get status of nginx container. return false and failing health check.";
            return false;
        }

        return (*maybe_result).find(nginx_container_name) != string::npos;
    }

    void
    closeCurrentSocket(I_Socket::socketFd fd, I_MainLoop::RoutineID curr_routine) {
        dbgDebug(D_HEALTH_CHECK) << "Connection with client closed, client fd: " << fd;
        open_connections_counter--;
        i_socket->closeSocket(fd);
        client_sockets_routines.erase(curr_routine);
    }

    void
    handleConnection()
    {
        if (open_connections_counter >= max_connections) {
            dbgDebug(D_HEALTH_CHECK)
                << "Cannot serve new client, reached maximum open connections bound which is:"
                << open_connections_counter
                << "maximum allowed: "
                << max_connections;
            return;
        }
        Maybe<I_Socket::socketFd> accepted_socket = i_socket->acceptSocket(server_sock, false, ip_address);
        if (!accepted_socket.ok()) {
            dbgWarning(D_HEALTH_CHECK)
                << "Failed to accept a new client socket: "
                << accepted_socket.getErr();
            return;
        }

        auto new_client_socket = accepted_socket.unpack();
        if (new_client_socket <= 0) {
            i_socket->closeSocket(new_client_socket);
            dbgWarning(D_HEALTH_CHECK)
                << "Failed to initialize communication, generated client socket is OK yet negative";
            return;
        }

        dbgDebug(D_HEALTH_CHECK) << "Successfully accepted client, client fd: " << new_client_socket;
        open_connections_counter++;
        auto curr_routine = i_mainloop->addOneTimeRoutine(
            I_MainLoop::RoutineType::RealTime,
            [this] ()
            {
                auto curr_routine_id = i_mainloop->getCurrentRoutineId().unpack();
                auto curr_client_socket = client_sockets_routines[curr_routine_id];
                auto data_recieved = i_socket->receiveData(curr_client_socket, sizeof(uint8_t), false);
                if (!data_recieved.ok()) {
                    closeCurrentSocket(curr_client_socket, curr_routine_id);
                    i_mainloop->stop();
                }

                static const string success_response =
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Length: 25\r\n"
                    "Content-Type: text/plain\r\n"
                    "\r\n"
                    "health check successful\r\n";
                static const vector<char> success_response_buffer(success_response.begin(), success_response.end());

                static const string failure_response =
                    "HTTP/1.1 500 Internal Server Error\r\n"
                    "Content-Length: 21\r\n"
                    "Content-Type: text/plain\r\n"
                    "\r\n"
                    "health check failed\r\n";
                static const vector<char> failure_response_buffer(failure_response.begin(), failure_response.end());

                static const string degraded_response =
                    "HTTP/1.1 202 OK\r\n"
                    "Content-Length: 22\r\n"
                    "Content-Type: text/plain\r\n"
                    "\r\n"
                    "health check partial\r\n";
                static const vector<char> degraded_response_buffer(degraded_response.begin(), degraded_response.end());

                HealthCheckStatus standalone_status = getStandaloneHealthStatus();
                if (standalone_status != HealthCheckStatus::IGNORED) {
                    if (standalone_status == HealthCheckStatus::HEALTHY) {
                        dbgDebug(D_HEALTH_CHECK)
                            << "Standalone status is healthy, returning the following response: "
                            << success_response;
                        i_socket->writeData(curr_client_socket, success_response_buffer);
                        closeCurrentSocket(curr_client_socket, curr_routine_id);
                        return;
                    }

                    if (standalone_status == HealthCheckStatus::UNHEALTHY) {
                        dbgDebug(D_HEALTH_CHECK)
                            << "Standalone status in unhealthy, returning the following response: "
                            << failure_response;
                        i_socket->writeData(curr_client_socket, failure_response_buffer);
                        closeCurrentSocket(curr_client_socket, curr_routine_id);
                        return;
                    }

                    dbgDebug(D_HEALTH_CHECK)
                        << "Standalone status was partially loaded, returning the following response: "
                        << degraded_response;
                    i_socket->writeData(curr_client_socket, degraded_response_buffer);
                    closeCurrentSocket(curr_client_socket, curr_routine_id);
                    return;
                }

                if (nginxContainerIsRunning()) {
                    dbgDebug(D_HEALTH_CHECK)
                    << "nginx conatiner is running, returning the following response: "
                    << success_response;
                    i_socket->writeData(curr_client_socket, success_response_buffer);
                    closeCurrentSocket(curr_client_socket, curr_routine_id);
                    return;
                }

                dbgDebug(D_HEALTH_CHECK)
                    << "nginx conatiner is not running, returning the following response: "
                    << failure_response;
                i_socket->writeData(curr_client_socket, failure_response_buffer);
                closeCurrentSocket(curr_client_socket, curr_routine_id);
            },
            "Health check probe connection handler",
            true
        );
        client_sockets_routines[curr_routine] = new_client_socket;
    }

    bool enable;
    uint max_retry_interval;
    unordered_map<I_MainLoop::RoutineID, I_Socket::socketFd> client_sockets_routines;
    bool is_first_run                               = true;
    uint open_connections_counter                   = 0;
    uint max_connections                            = 0;
    string ip_address                               = "";
    uint port                                       = 0;
    I_Socket::socketFd server_sock                  = -1;
    I_MainLoop::RoutineID routine_id                = 0;
    I_MainLoop *i_mainloop                          = nullptr;
    I_Socket *i_socket                              = nullptr;
    I_Health_Check_Manager *i_health_check_manager  = nullptr;
};

HealthChecker::HealthChecker() : Component("HealthChecker"), pimpl(make_unique<Impl>()) {}
HealthChecker::~HealthChecker() {}

void
HealthChecker::preload()
{
    registerExpectedConfiguration<uint>("Health Check", "Probe maximun open connections");
    registerExpectedConfiguration<bool>("Health Check", "Probe enabled");
    registerExpectedConfiguration<string>("Health Check", "Probe IP");
    registerExpectedConfiguration<uint>("Health Check", "Probe port");
    registerExpectedConfiguration<uint>("Health Check", "Probe socket reopen period");
    registerExpectedSetting<string>("reverseProxy", "cloudVendorName");
}

void
HealthChecker::init()
{
    pimpl->init();
}

void
HealthChecker::fini()
{
    pimpl->fini();
}
