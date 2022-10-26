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

#include "logging_comp.h"
#include "log_streams.h"

using namespace std;
using namespace cereal;

USE_DEBUG_FLAG(D_REPORT);

CefStream::CefStream(const string &_ip_address, int _port)
        :
    i_socket(Singleton::Consume<I_Socket>::by<LoggingComp>()),
    ip_address(_ip_address),
    port(_port)
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
    auto cef_ip_address = getProfileAgentSettingWithDefault<string>(ip_address, "agent.config.log.cefServer.IP");
    auto cef_port = getProfileAgentSettingWithDefault<uint>(port, "agent.config.log.cefServer.port");

    if (cef_ip_address.empty()) {
        dbgWarning(D_REPORT) << "Cannot connect to CEF server, IP is not configured.";
        return;
    }
    socket = i_socket->genSocket(
        I_Socket::SocketType::UDP,
        false,
        false,
        cef_ip_address + ":" + to_string(cef_port)
    );
}
