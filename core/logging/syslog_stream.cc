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

#include "log_streams.h"
#include "logging_comp.h"

using namespace std;

USE_DEBUG_FLAG(D_REPORT);

SyslogStream::SyslogStream(const string &_ip_address, int _port)
        :
    i_socket(Singleton::Consume<I_Socket>::by<LoggingComp>()),
    mainloop(Singleton::Consume<I_MainLoop>::by<LoggingComp>()),
    ip_address(_ip_address),
    port(_port)
{
    connect();
    if (!socket.ok()) {
        dbgWarning(D_REPORT) << "Failed to connect to the syslog server";
    }
}

SyslogStream::~SyslogStream()
{
    if (mainloop != nullptr && mainloop->doesRoutineExist(log_send_routine)) mainloop->stop(log_send_routine);
    if (socket.ok()) {
        i_socket->closeSocket(const_cast<int &>(*socket));
        socket = genError("Closed socket");
    }
}

void
SyslogStream::sendLog(const Report &log)
{
    if (!socket.ok()) {
        connect();
        if (!socket.ok()) {
            dbgWarning(D_REPORT) << "Failed to connect to the syslog server, Log will not be sent.";
            return;
        }
        dbgTrace(D_REPORT) << "Successfully connect to the syslog server";
    }

    string syslog_report = log.getSyslog();
    vector<char> data(syslog_report.begin(), syslog_report.end());
    mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::Offline,
        [this, data] ()
        {
            int tries = 1;
            for (; tries <=3; tries++) {
                if (i_socket->writeData(socket.unpack(), data)) {
                    dbgTrace(D_REPORT) << "log was sent to syslog server";
                    return;
                } else {
                    dbgWarning(D_REPORT) << "Failed to send log to syslog server";
                }
            }
        },
        "Logging Syslog stream messaging"
    );
}

void
SyslogStream::connect()
{
    auto syslog_ip_address = getProfileAgentSettingWithDefault<string>(ip_address, "agent.config.log.syslogServer.IP");
    auto syslog_port = getProfileAgentSettingWithDefault<uint>(port, "agent.config.log.syslogServer.port");

    if (syslog_ip_address.empty()) {
        dbgWarning(D_REPORT) << "Cannot connect to Syslog server, IP is not configured.";
        return;
    }

    socket = i_socket->genSocket(
        I_Socket::SocketType::UDP,
        false,
        false,
        syslog_ip_address + ":" + to_string(syslog_port)
    );
}
