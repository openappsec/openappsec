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

#include "logging_comp.h"
#include "log_streams.h"

using namespace std;
using namespace cereal;

USE_DEBUG_FLAG(D_REPORT);

static string lookup_cmd = "nslookup ";
static string line_selection_cmd = "| grep Address | sed -n 2p";
static string parsing_cmd = "| cut -f2 -d' ' | tr -d '\n'";

CefStream::CefStream(const string &_address, int _port, I_Socket::SocketType _protocol)
        :
    i_socket(Singleton::Consume<I_Socket>::by<LoggingComp>()),
    address(_address),
    port(_port),
    protocol(_protocol)
{
    connect();
    if (!socket.ok()) {
        dbgWarning(D_REPORT) << "Failed to connect to the CEF server";
    }
}

CefStream::~CefStream()
{
    if (socket.ok()) {
        i_socket->closeSocket(const_cast<int &>(*socket));
        socket = genError("Closed socket");
    }
}

void
CefStream::sendLog(const Report &log)
{
    if (!socket.ok()) {
        connect();
        if (!socket.ok()) {
            dbgWarning(D_REPORT) << "Failed to connect to the CEF server, log will not be sent.";
            return;
        }
    }
    dbgTrace(D_REPORT) << "Connected to socket.";
    string cef_report = log.getCef();
    if (protocol == I_Socket::SocketType::TCP) {
        cef_report = to_string(cef_report.length()) + " " + cef_report;
    }
    vector<char> data(cef_report.begin(), cef_report.end());
    for (size_t tries = 0; tries < 3; tries++) {
        if (i_socket->writeData(socket.unpack(), data)) {
            dbgTrace(D_REPORT) << "log was sent to CEF server";
            return;
        } else {
            dbgWarning(D_REPORT) << "Failed to send log to CEF server";
        }
    }
}

void
CefStream::connect()
{
    auto cef_address = getProfileAgentSettingWithDefault<string>(address, "agent.config.log.cefServer.IP");
    auto cef_port = getProfileAgentSettingWithDefault<uint>(port, "agent.config.log.cefServer.port");

    if (cef_address.empty()) {
        dbgWarning(D_REPORT) << "Cannot connect to CEF server, IP/Domain is not configured.";
        return;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, cef_address.data(), &addr) != 1) {
        I_ShellCmd *shell_cmd = Singleton::Consume<I_ShellCmd>::by<LoggingComp>();
        string host_cmd = lookup_cmd + cef_address + line_selection_cmd + parsing_cmd;
        Maybe<string> res = shell_cmd->getExecOutput(host_cmd, 500);
        if (!res.ok()) {
            dbgWarning(D_REPORT)
                << "Failed to execute domain lookup command. "
                << "CEF Domain: "
                << cef_address
                << "Error: "
                << res.getErr();
            return;
        }

        if (res.unpack().empty()) {
            dbgWarning(D_REPORT)
                << "Got en empty ip address from lookup command. "
                << "CEF Domain: "
                << cef_address
                << "Got bad ip address: "
                << res.unpack();
            return;
        }

        dbgDebug(D_REPORT) << "CEF Domain lookup result: " << res.unpack();
        if (inet_pton(AF_INET, res.unpack().data(), &addr) != 1) {
            dbgWarning(D_REPORT)
                << "Got a faulty ip address from lookup command. "
                << "CEF Domain: "
                << cef_address
                << "Got bad ip address: "
                << res.unpack();
            return;
        }
        
        cef_address = res.unpack();
    }

    socket = i_socket->genSocket(
        protocol,
        false,
        false,
        cef_address + ":" + to_string(cef_port)
    );
}
