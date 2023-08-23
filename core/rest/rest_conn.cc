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

#include "rest_conn.h"

#include <unistd.h>
#include <sstream>
#include <sys/socket.h>

#include "debug.h"

using namespace std;

USE_DEBUG_FLAG(D_API);

RestConn::RestConn(int _fd, I_MainLoop *_mainloop, const I_RestInvoke *_invoke)
        :
    fd(_fd),
    mainloop(_mainloop),
    invoke(_invoke)
{}

RestConn::~RestConn()
{
}

static bool
compareStringCaseInsensitive(const string &s1, const string &s2)
{
    if (s1.size() != s2.size()) return false;

    for (size_t index = 0; index < s1.size(); ++index) {
        if (tolower(s1[index]) != tolower(s2[index])) return false;
    }

    return true;
}

void
RestConn::parseConn() const
{
    char ch;

    if (recv(fd, &ch, sizeof(char), MSG_PEEK) != sizeof(char)) {
        dbgDebug(D_API) << "Socket " << fd << " ended";
        stop();
    }

    string line = readLine();
    stringstream os;
    os.str(line);
    string method;
    os >> method;

    if (method!="POST" && method!="GET") {
        dbgWarning(D_API) << "Unsupported REST method: " << method;
        sendResponse("405 Method Not Allowed", "Method " + method + " is not supported");
        return;
    }

    string uri;
    os >> uri;
    string identifier = uri.substr(uri.find_first_of('/') + 1);
    dbgDebug(D_API) << "Call identifier: " << identifier;

    uint len = 0;
    while (true) {
        line = readLine();
        if (line.size() < 3) break;

        os.str(line);
        string head, data;
        os >> head >> data;
        if (compareStringCaseInsensitive(head, "Content-Length:")) {
            try {
                len = stoi(data, nullptr);
            } catch (...) {
            }
        }
    }

    dbgDebug(D_API) << "Message length: " << len;

    if (method=="POST" && len==0) {
        dbgWarning(D_API) << "No length was found - could be chunked, but we still do not support that";
        sendResponse("411 Length Required", "");
        stop();
    }

    stringstream body;
    body.str(readSize(len));

    dbgTrace(D_API) << "Message content: " << body.str();

    Maybe<string> res = (method == "POST") ? invoke->invokeRest(identifier, body) : invoke->getSchema(identifier);

    if (res.ok()) {
        sendResponse("200 OK", res.unpack());
    } else {
        sendResponse("500 Internal Server Error", res.getErr());
    }
}

void
RestConn::stop() const
{
    close(fd);
    mainloop->stop();
}

string
RestConn::readLine() const
{
    string res;
    char ch = 0;
    while (ch != '\n') {
        if (read(fd, &ch, sizeof(char)) != sizeof(char)) {
            dbgWarning(D_API) << "Failed to read from socket " << fd;
            sendResponse("598 Network read timeout error", "");
            stop();
        }
        res += ch;
    }

    return res;
}

string
RestConn::readSize(int len) const
{
    string res;
    for (int i = 0; i < len; i++) {
        char ch;
        if (read(fd, &ch, sizeof(char)) != sizeof(char)) {
            dbgWarning(D_API) << "Failed to read from socket " << fd;
            sendResponse("598 Network read timeout error", "");
            stop();
        }
        res += ch;
    }
    return res;
}

void
RestConn::sendResponse(const string &status, const string &body) const
{
    stringstream stream;
    stream <<
        "HTTP/1.1 " << status << "\r\n" <<
        "Content-Type: application/json\r\n" <<
        "Content-Length: " << (body.size() + 2) << "\r\n" <<
        "\r\n" <<
        body << "\r\n";


    string res = stream.str();
    while (res.size() > 0 ) {
        auto written = write(fd, res.c_str(), res.size());
        if (written < 1) {
            dbgWarning(D_API) << "Failed to write to socket " << fd;
            stop();
        }
        res = res.substr(written);
    }
}
