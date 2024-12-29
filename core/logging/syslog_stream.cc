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
static string SYSLOG_NAME = "Syslog";

SyslogStream::SyslogStream(const string &_address, int _port, I_Socket::SocketType _protocol)
        :
    LogStreamConnector(_address, _port, _protocol, SYSLOG_NAME)
{
    socket = genError("Not set yet");
    init();
}

SyslogStream::~SyslogStream()
{
    sendAllLogs();
    if (mainloop != nullptr && mainloop->doesRoutineExist(log_send_routine)) mainloop->stop(log_send_routine);
    if (mainloop != nullptr && mainloop->doesRoutineExist(connecting_routine)) mainloop->stop(connecting_routine);

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
    log_send_routine = mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::Offline,
        [this, data] () { sendLog(data); },
        "Logging Syslog stream messaging"
    );
}

void
SyslogStream::sendLog(const vector<char> &data)
{
    dbgTrace(D_REPORT) << "Sending Syslog log." << " Max logs per send: " << max_logs_per_send;
    sendLogWithQueue(data);
}


void
SyslogStream::init() {
    updateSettings();
    maintainConnection();

    auto syslog_retry_interval = getProfileAgentSettingWithDefault<uint>(
        RETRY_CONNECT_INTERVAL,
        "agent.config.log.syslogServer.connect_retry_interval");
    chrono::seconds connect_retry_interval = chrono::seconds(syslog_retry_interval);
    connecting_routine = mainloop->addRecurringRoutine(
        I_MainLoop::RoutineType::Offline,
        connect_retry_interval,
        [this] ()
        {
            dbgTrace(D_REPORT) << SYSLOG_CONNECT_NAME;
            maintainConnection();
        },
        SYSLOG_CONNECT_NAME
    );
}

void
SyslogStream::connect()
{
    dbgDebug(D_REPORT)
        << "Connecting to Syslog server"
        << " Address: "
        << address
        << " Port: "
        << port;

    if (address.empty()) {
        dbgWarning(D_REPORT) << "Cannot connect to Syslog server, Address IP/Domain not configured.";
        return;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, address.data(), &addr) != 1) {
        I_ShellCmd *shell_cmd = Singleton::Consume<I_ShellCmd>::by<LoggingComp>();
        string host_cmd = lookup_cmd + address + line_selection_cmd + parsing_cmd;
        Maybe<string> res = shell_cmd->getExecOutput(host_cmd, 500);
        if (!res.ok()) {
            dbgWarning(D_REPORT)
                << "Failed to execute domain lookup command. "
                << "SYSLOG Domain: "
                << address
                << "Error: "
                << res.getErr();
            return;
        }

        if (res.unpack().empty()) {
            dbgWarning(D_REPORT)
                << "Got en empty ip address from lookup command. "
                << "SYSLOG Domain: "
                << address
                << "Got bad ip address: "
                << res.unpack();
            return;
        }

        dbgDebug(D_REPORT) << "SYSLOG Domain lookup result: " << res.unpack();
        if (inet_pton(AF_INET, res.unpack().data(), &addr) != 1) {
            dbgWarning(D_REPORT)
                << "Got a faulty ip address from lookup command. "
                << "SYSLOG Domain: "
                << address
                << "Got bad ip address: "
                << res.unpack();
            return;
        }

        address = res.unpack();
    }

    socket = i_socket->genSocket(
        protocol,
        false,
        false,
        address + ":" + to_string(port)
    );
}

void
SyslogStream::updateSettings()
{
    max_logs_per_send = getProfileAgentSettingWithDefault<int>(
        NUMBER_OF_LOGS_PER_SEND,
        "agent.config.log.syslogServer.MaxLogsPerSend"
    );
    if (max_logs_per_send < 0) {
        max_logs_per_send = NUMBER_OF_LOGS_PER_SEND;
    }
    address = getProfileAgentSettingWithDefault<string>(address, "agent.config.log.syslogServer.IP");
    port = getProfileAgentSettingWithDefault<uint>(port, "agent.config.log.syslogServer.port");
    max_data_in_queue =
        getProfileAgentSettingWithDefault<uint>(MAX_LOG_QUEUE, "agent.config.log.syslogServer.MaxLogQueue");

    dbgTrace(D_REPORT)
        << "Syslog server settings updated. "
        << "Address: "
        << address
        << " Port: "
        << port
        << " Max logs per send: "
        << max_logs_per_send
        << " Max data in queue: "
        << max_data_in_queue;
}
