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

#include <arpa/inet.h>

#include "log_streams.h"
#include "logging_comp.h"

using namespace std;

USE_DEBUG_FLAG(D_REPORT);

static string lookup_cmd = "nslookup ";
static string line_selection_cmd = "| grep Address | sed -n 2p";
static string parsing_cmd = "| cut -f2 -d' ' | tr -d '\n'";

SyslogStream::SyslogStream(const string &_address, int _port, I_Socket::SocketType _protocol)
        :
    i_socket(Singleton::Consume<I_Socket>::by<LoggingComp>()),
    mainloop(Singleton::Consume<I_MainLoop>::by<LoggingComp>()),
    address(_address),
    port(_port),
    protocol(_protocol)
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
    string syslog_report = log.getSyslog();
    if (protocol == I_Socket::SocketType::TCP) {
        syslog_report = to_string(syslog_report.length()) + " " + syslog_report;
    }
    vector<char> data(syslog_report.begin(), syslog_report.end());
    mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::Offline,
        [this, data] () { sendLog(data); },
        "Logging Syslog stream messaging"
    );
}

void
SyslogStream::sendLog(const vector<char> &data)
{
    for (int tries = 0; tries < 3; ++tries) {
        if (!socket.ok()) {
            connect();
            if (!socket.ok()) {
                dbgWarning(D_REPORT) << "Failed to connect to the syslog server, Log will not be sent.";
                return;
            }
            dbgTrace(D_REPORT) << "Successfully connect to the syslog server";
        }

        if (i_socket->writeData(socket.unpack(), data)) {
            dbgTrace(D_REPORT) << "log was sent to syslog server";
            return;
        }
    }
    dbgWarning(D_REPORT) << "Failed to send log to syslog server";
}

void
SyslogStream::connect()
{
    auto syslog_address = getProfileAgentSettingWithDefault<string>(address, "agent.config.log.syslogServer.IP");
    auto syslog_port = getProfileAgentSettingWithDefault<uint>(port, "agent.config.log.syslogServer.port");

    if (syslog_address.empty()) {
        dbgWarning(D_REPORT) << "Cannot connect to Syslog server, Address IP/Domain not configured.";
        return;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, syslog_address.data(), &addr) != 1) {
        I_ShellCmd *shell_cmd = Singleton::Consume<I_ShellCmd>::by<LoggingComp>();
        string host_cmd = lookup_cmd + syslog_address + line_selection_cmd + parsing_cmd;
        Maybe<string> res = shell_cmd->getExecOutput(host_cmd, 500);
        if (!res.ok()) {
            dbgWarning(D_REPORT)
                << "Failed to execute domain lookup command. "
                << "SYSLOG Domain: "
                << syslog_address
                << "Error: "
                << res.getErr();
            return;
        }

        if (res.unpack().empty()) {
            dbgWarning(D_REPORT)
                << "Got en empty ip address from lookup command. "
                << "SYSLOG Domain: "
                << syslog_address
                << "Got bad ip address: "
                << res.unpack();
            return;
        }

        dbgDebug(D_REPORT) << "SYSLOG Domain lookup result: " << res.unpack();
        if (inet_pton(AF_INET, res.unpack().data(), &addr) != 1) {
            dbgWarning(D_REPORT)
                << "Got a faulty ip address from lookup command. "
                << "SYSLOG Domain: "
                << syslog_address
                << "Got bad ip address: "
                << res.unpack();
            return;
        }

        syslog_address = res.unpack();
    }

    socket = i_socket->genSocket(
        protocol,
        false,
        false,
        syslog_address + ":" + to_string(syslog_port)
    );
}
