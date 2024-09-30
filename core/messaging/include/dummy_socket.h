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

#ifndef __DUMMY_SOCKET_H__
#define __DUMMY_SOCKET_H__

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <thread>
#include <fcntl.h>
#include <poll.h>

#include "singleton.h"
#include "i_mainloop.h"
#include "agent_core_utilities.h"

class DummySocket : Singleton::Consume<I_MainLoop>
{
public:
    ~DummySocket()
    {
        if (server_fd != -1) close(server_fd);
        if (connection_fd != -1) close(connection_fd);
    }

    void
    init()
    {
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        dbgAssert(server_fd >= 0) << AlertInfo(AlertTeam::CORE, "messaging i/s") << "Failed to open a socket";
        int socket_enable = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &socket_enable, sizeof(int));

        struct sockaddr_in addr;
        bzero(&addr, sizeof(addr));

        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(8080);
        bind(server_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
        listen(server_fd, 100);
    }

    void
    acceptSocket()
    {
        if (connection_fd == -1) connection_fd = accept(server_fd, nullptr, nullptr);
    }

    std::string
    readFromSocket()
    {
        acceptSocket();

        std::string res;
        char buffer[1024];
        while (int bytesRead = readRaw(buffer, sizeof(buffer))) {
            res += std::string(buffer, bytesRead);
        }
        return res;
    }

    void
    writeToSocket(const std::string &msg)
    {
        acceptSocket();
        EXPECT_EQ(write(connection_fd, msg.data(), msg.size()), static_cast<int>(msg.size()));
    }

private:
    int
    readRaw(char *buf, uint len)
    {
        struct pollfd s_poll;
        s_poll.fd = connection_fd;
        s_poll.events = POLLIN;
        s_poll.revents = 0;

        if (poll(&s_poll, 1, 0) <= 0 || (s_poll.revents & POLLIN) == 0) return 0;

        return read(connection_fd, buf, len);
    }

    int server_fd = -1;
    int connection_fd = -1;
};

#endif // __DUMMY_SOCKET_H__
