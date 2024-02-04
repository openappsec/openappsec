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

#ifndef __I_SOCKET_IS_H__
#define __I_SOCKET_IS_H__

#include <string.h>
#include <vector>

#include "maybe_res.h"

class I_Socket
{
public:
    enum class SocketType { UNIX, UNIXDG, TCP, UDP };
    using socketFd = int;

    virtual Maybe<socketFd>
    genSocket(SocketType type, bool is_blocking, bool is_server, const std::string &address) = 0;

    virtual Maybe<socketFd> acceptSocket(
        socketFd server_socket_fd,
        bool is_blocking,
        const std::string &authorized_ip = ""
    ) = 0;

    virtual void closeSocket(socketFd &socket) = 0;
    virtual bool writeData(socketFd socket, const std::vector<char> &data) = 0;
    virtual Maybe<std::vector<char>> receiveData(socketFd socket, uint data_size, bool is_blocking = true) = 0;
    virtual bool isDataAvailable(socketFd socket) = 0;

protected:
    virtual ~I_Socket() {}
};

#endif // __I_SOCKET_IS_H__
