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

#ifndef __LOG_STREAMS_H__
#define __LOG_STREAMS_H__

#include <fstream>
#include <set>

#include "i_mainloop.h"
#include "report/report_bulks.h"
#include "report/log_rest.h"
#include "logging_metric.h"
#include "i_logging.h"
#include "i_socket_is.h"
#include "logging_comp.h"

static const int RETRY_CONNECT_INTERVAL = 120;
static const std::string FIRST_SYSLOG_CONNECT_NAME = "first connecting to Syslog server";
static const std::string SYSLOG_CONNECT_NAME = "connecting to Syslog server";
static const std::string FIRST_CEF_CONNECT_NAME = "first connecting to CEF server";
static const std::string CEF_CONNECT_NAME = "connecting to CEF server";
static const int NUMBER_OF_LOGS_PER_SEND = 15;
static size_t MAX_LOG_QUEUE = 1000;

USE_DEBUG_FLAG(D_REPORT);

class Stream
{
public:
    virtual ~Stream() {}
    virtual void sendLog(const Report &log) = 0;
    virtual void
    sendLog(const LogBulkRest &logs, bool persistance_only)
    {
        if (persistance_only) {
            dbgWarning(D_REPORT) << "Skipping logs due to persistance only setting";
            return;
        }
        for (auto &log : logs) {
            sendLog(log);
        }
    }
};

class DebugStream : public Stream
{
public:
    void sendLog(const Report &log) override;
};

class LogFileStream : public Stream
{
public:
    LogFileStream();
    ~LogFileStream();

    void sendLog(const Report &log) override;

private:
    void openLogFile();
    void closeLogFile();
    bool retryWritingLog(const std::string &log);

    std::string     log_file_name;
    std::ofstream   log_stream;
};

class FogStream : public Stream
{
public:
    FogStream();
    ~FogStream();

    void sendLog(const Report &log) override;
    void sendLog(const LogBulkRest &logs, bool persistance_only) override;

private:
    I_Messaging *i_msg = nullptr;
};

class ContainerSvcStream : public Stream
{
public:
    ContainerSvcStream();
    ~ContainerSvcStream();

    void sendLog(const Report &log) override;
    void sendLog(const LogBulkRest &logs, bool persistance_only) override;

private:
    I_Messaging *i_msg = nullptr;
};

class LogStreamConnector : public Stream
{
public:
    LogStreamConnector(
        const std::string &_address,
        int _port,
        I_Socket::SocketType _protocol,
        const std::string &_log_name) :
        mainloop(Singleton::Consume<I_MainLoop>::by<LoggingComp>()),
        i_socket(Singleton::Consume<I_Socket>::by<LoggingComp>()),
        address(_address),
        port(_port),
        protocol(_protocol),
        logs_in_queue(),
        log_name(_log_name) {}
    virtual ~LogStreamConnector() {}

protected:
    virtual void connect() = 0;
    virtual void updateSettings() = 0;

    void maintainConnection();
    void addLogToQueue(const std::vector<char> &data);
    void writeFail();
    bool basicWriteLog(const std::vector<char> &data);
    void sendLogWithQueue(const std::vector<char> &data);
    void sendAllLogs();

    I_MainLoop *mainloop = nullptr;
    I_Socket *i_socket = nullptr;
    std::string address;
    int port;
    I_Socket::SocketType protocol = I_Socket::SocketType::UDP;
    Maybe<I_Socket::socketFd> socket = genError("Not set yet");
    bool did_write_fail_in_this_window = false;
    std::vector<std::vector<char>> logs_in_queue;
    I_MainLoop::RoutineID connecting_routine = -1;
    int max_logs_per_send = NUMBER_OF_LOGS_PER_SEND;
    std::string log_name;
    uint max_data_in_queue = MAX_LOG_QUEUE;
};

class SyslogStream : public LogStreamConnector
{
public:
    SyslogStream(const std::string &_address, int _port, I_Socket::SocketType protocol);
    ~SyslogStream();
    void sendLog(const Report &log) override;

protected:
    void connect() override;
    void updateSettings() override;

private:
    void init();
    void sendLog(const std::vector<char> &data);
    I_MainLoop::RoutineID log_send_routine = -1;
};

class CefStream : public LogStreamConnector
{
public:
    CefStream(const std::string &_address, int _port, I_Socket::SocketType _protocol);
    ~CefStream();
    void sendLog(const Report &log) override;

protected:
    void connect() override;
    void updateSettings() override;
private:
    void init();
};

#endif // __LOG_STREAMS_H__
