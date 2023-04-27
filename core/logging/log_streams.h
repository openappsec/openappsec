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

class K8sSvcStream : public Stream
{
public:
    K8sSvcStream();
    ~K8sSvcStream();

    void sendLog(const Report &log) override;
    void sendLog(const LogBulkRest &logs, bool persistance_only) override;

private:
    std::string genHeader();
    I_Messaging *i_msg = nullptr;
};

class SyslogStream : public Stream
{
public:
    SyslogStream(const std::string &_address, int _port, I_Socket::SocketType protocol);
    ~SyslogStream();

    void sendLog(const Report &log) override;

private:
    void sendLog(const std::vector<char> &data);
    void connect();

    I_Socket *i_socket = nullptr;
    I_MainLoop *mainloop = nullptr;
    std::string address;
    int port;
    I_Socket::SocketType protocol = I_Socket::SocketType::UDP;
    I_MainLoop::RoutineID log_send_routine = -1;
    Maybe<I_Socket::socketFd> socket = genError("Not set yet");
};

class CefStream : public Stream
{
public:
    CefStream(const std::string &_address, int _port, I_Socket::SocketType _protocol);
    ~CefStream();

    void sendLog(const Report &log) override;

private:
    void connect();

    I_Socket *i_socket = nullptr;
    std::string address;
    int port;
    I_Socket::SocketType protocol = I_Socket::SocketType::UDP;
    Maybe<I_Socket::socketFd> socket = genError("Not set yet");
};

#endif // __LOG_STREAMS_H__
