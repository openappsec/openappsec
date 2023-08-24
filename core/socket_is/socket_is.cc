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

#include "socket_is.h"

#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <set>
#include <algorithm>
#include <sys/stat.h>
#include <errno.h>
#include "debug.h"

static const uint udp_max_packet_size = 1024 * 64;

USE_DEBUG_FLAG(D_SOCKET);

using namespace std;

class SocketInternal
{
public:
    SocketInternal() = default;

    SocketInternal(const SocketInternal &other) = delete;

    SocketInternal(SocketInternal &&from)
    {
        is_blocking = from.is_blocking;
        is_server_socket = from.is_server_socket;
        socket_int = from.socket_int;
        from.socket_int = -1;
    }

    virtual ~SocketInternal()
    {
        if (socket_int > 0) {
            close(socket_int);
            socket_int = -1;
            if (is_server_socket) cleanServer();
        }
    }

    virtual void cleanServer() {}

    SocketInternal & operator=(const SocketInternal &) = delete;

    SocketInternal &
    operator=(SocketInternal &&from)
    {
        is_blocking = from.is_blocking;
        is_server_socket = from.is_server_socket;
        socket_int = from.socket_int;
        from.socket_int = -1;
        return *this;
    }

    bool isBlocking() const { return is_blocking; }
    bool isServerSock() const { return is_server_socket; }
    int getSocket() const { return socket_int; }

    bool
    writeData(const vector<char> &data)
    {
        uint32_t bytes_sent = 0;
        bool is_first_iter = true;
        while (bytes_sent  < data.size()) {
            if (!is_first_iter && !is_blocking) {
                dbgTrace(D_SOCKET)
                    << "Trying to yield before writing to socket again. Bytes written: "
                    << bytes_sent
                    << ", Total bytes: "
                    << data.size();

                Singleton::Consume<I_MainLoop>::by<SocketIS>()->yield(false);
            }
            is_first_iter = false;

            int res = send(socket_int, data.data() + bytes_sent, data.size() - bytes_sent, MSG_NOSIGNAL);
            if (res <= 0) {
                dbgWarning(D_SOCKET) << "Failed to send data, Error: " << strerror(errno);
                return false;
            }

            bytes_sent += res;
        }

        return true;
    }

    bool
    isDataAvailable()
    {
        struct pollfd s_poll;
        s_poll.fd = socket_int;
        s_poll.events = POLLIN;
        s_poll.revents = 0;
        return poll(&s_poll, 1, 0) > 0 && (s_poll.revents & POLLIN) != 0;
    }

    virtual Maybe<vector<char>>
    receiveDataBlocking(uint data_size)
    {
        uint bytes_read = 0;
        vector<char> param_to_read(data_size, 0);
        while (bytes_read  < data_size) {
            if (bytes_read > 0 && !isDataAvailable()) {
                return genError("Failed to read data after " + to_string(bytes_read) + " bytes");
            }
            int res = read(socket_int, param_to_read.data() + bytes_read, data_size - bytes_read);
            if (res <= 0) return genError("Failed to read data");

            bytes_read += res;
        }

        return param_to_read;
    }

    virtual Maybe<vector<char>>
    receiveDataNonBlocking(uint data_size)
    {
        uint bytes_read = 0;
        bool is_first_iter = true;
        vector<char> param_to_read(data_size, 0);
        while (bytes_read  < data_size) {
            if (!is_first_iter && !is_blocking) {
                dbgTrace(D_SOCKET)
                    << "Trying to yield before reading from socket again. Bytes read: "
                    << bytes_read
                    << ", Total bytes: "
                    << data_size;

                Singleton::Consume<I_MainLoop>::by<SocketIS>()->yield(false);
            }

            if (bytes_read > 0 && !isDataAvailable()) {
                return genError("Failed to read data after " + to_string(bytes_read) + " bytes");
            }
            is_first_iter = false;

            int res = recv(socket_int, param_to_read.data() + bytes_read, data_size - bytes_read, MSG_DONTWAIT);
            if (res == 0) {
                return genError("Client closed connection");
            }
            if (res == -1) {
                string error_message = strerror(errno);
                return genError(
                    "Failed to read data, Error: " + error_message
                );
            }

            bytes_read += res;
        }

        return param_to_read;
    }

    Maybe<unique_ptr<SocketInternal>>
    acceptConn(bool is_blocking, const string &authorized_ip = "")
    {
        dbgAssert(is_server_socket) << "Failed to accept new connections from a client socket";
        dbgAssert(socket_int > 0) << "Called with uninitialized server socket";

        dbgDebug(D_SOCKET) << "Attempt to accept new socket. Server Socket FD: " << socket_int;
        int client_socket;
        if (!authorized_ip.empty()) {
            struct sockaddr_in clientaddr;
            socklen_t clientaddr_size = sizeof(clientaddr);
            client_socket = accept(socket_int, (struct sockaddr *)&clientaddr, &clientaddr_size);
            auto authorized_client_ip = getAuthorizedIP(clientaddr, client_socket, authorized_ip);
            if (!authorized_client_ip.ok()) return genError(authorized_client_ip.getErr());
        } else {
            client_socket = accept(socket_int, nullptr, nullptr);
        }

        static const string err_msg = "Failed to accept new socket";
        if (client_socket < 0) {
            dbgWarning(D_SOCKET) << err_msg << ": " << strerror(errno);
            return genError(err_msg);
        }

        dbgDebug(D_SOCKET)
            << "Successfully accepted new connection."
            <<  string(authorized_ip.empty() ? "" : "Client IP: " + authorized_ip);

        return make_unique<SocketInternal>(is_blocking, false, client_socket);
    }

    SocketInternal(bool _is_blocking, bool _is_server_socket, int _socket = -1)
            :
        is_blocking(_is_blocking),
        is_server_socket(_is_server_socket),
        socket_int(_socket)
    {}

protected:
    bool is_blocking = false;
    bool is_server_socket = true;
    int socket_int = -1;

private:
    Maybe<string>
    getAuthorizedIP(
        const struct sockaddr_in &clientaddr,
        int client_socket,
        const string &authorized_ip = "")
    {
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientaddr.sin_addr), client_ip, INET_ADDRSTRLEN);

        if (!authorized_ip.empty() && authorized_ip.compare(client_ip) != 0) {
            close(client_socket);
            static const string err_msg = "Failed to accept new socket";
            dbgWarning(D_SOCKET) << err_msg << ": " << "Unauthorized client IP: " << client_ip;
            return genError(err_msg);
        }
        return string(client_ip);
    }
};

class TCPSocket : public SocketInternal
{
public:
    static Maybe<unique_ptr<TCPSocket>>
    connectSock(bool _is_blocking, bool _is_server, const string &_address)
    {
        size_t delimiter_pos = _address.find_last_of(':');
        if (delimiter_pos == string::npos) {
            return genError("The provided address is not valid (expected <ip>:<port>). Path: " + _address);
        }
        unique_ptr<TCPSocket> tcp_socket(make_unique<TCPSocket>(_is_blocking, _is_server));
        if (tcp_socket->getSocket() < 0) return genError("Failed to create socket");
        string ip_addr_string = _address.substr(0, delimiter_pos);
        if(inet_pton(AF_INET, ip_addr_string.c_str(), &(tcp_socket->server.sin_addr)) <= 0) {
            return genError("The provided IP address is not valid. IP: " + ip_addr_string);
        }

        string port_string = _address.substr(delimiter_pos + 1);
        if (port_string.empty() || !all_of(port_string.begin(), port_string.end(), ::isdigit)) {
            return genError("The provided Port is not valid. Port: " + port_string);
        }

        tcp_socket->server.sin_family = AF_INET;
        uint16_t port = stoi(port_string);
        tcp_socket->server.sin_port = htons(port);

        if (!tcp_socket->isServerSock()) {
            if (connect(
                    tcp_socket->getSocket(),
                    reinterpret_cast<struct sockaddr *>(&tcp_socket->server),
                    sizeof(struct sockaddr_in)
                ) == -1
            ) {
                return genError("Failed to connect socket");
            }
            return move(tcp_socket);
        }

        static const int on = 1;
        static const int options = SO_REUSEADDR | SO_REUSEPORT;
        if (setsockopt(tcp_socket->getSocket(), SOL_SOCKET, options, (char *)&on, sizeof(on)) < 0) {
            dbgWarning(D_SOCKET) << "Failed to set the socket descriptor as reusable";
            return genError("Failed to set the socket descriptor as reusable");
        }

        if (bind(
                tcp_socket->getSocket(),
                reinterpret_cast<struct sockaddr *>(&tcp_socket->server),
                sizeof(struct sockaddr_un)
            ) < 0
        ) {
            dbgWarning(D_SOCKET) << "Failed to bind the socket: " << strerror(errno);
            return genError("Failed to bind the socket");
        }

        const int listen_backlog = 32;
        if (listen(tcp_socket->getSocket(), listen_backlog) == -1) {
            dbgWarning(D_SOCKET) << "Failed to set the listening socket: " << strerror(errno);
            return genError("Failed to set the listening socket");
        }

        return move(tcp_socket);
    }

    void cleanServer() override {}

    TCPSocket(bool _is_blocking, bool _is_server_socket)
            :
        SocketInternal(_is_blocking, _is_server_socket)
    {
        socket_int = socket(AF_INET, SOCK_STREAM, 0);
    }

private:
    struct sockaddr_in server;
};

class UDPSocket : public SocketInternal
{
public:
    static Maybe<unique_ptr<UDPSocket>>
    connectSock(bool _is_blocking, bool _is_server, const string &_address)
    {
        size_t delimiter_pos = _address.find_last_of(':');
        if (delimiter_pos == string::npos) {
            return genError("The provided address is not valid (expected <ip>:<port>). Path: " + _address);
        }

        unique_ptr<UDPSocket> udp_socket(make_unique<UDPSocket>(_is_blocking, _is_server));
        if (udp_socket->getSocket() < 0) return genError("Failed to create socket");

        string ip_addr_string = _address.substr(0, delimiter_pos);
        if(inet_pton(AF_INET, ip_addr_string.c_str(), &(udp_socket->server.sin_addr)) <= 0) {
            return genError("The provided IP address is not valid. IP: " + ip_addr_string);
        }

        string port_string = _address.substr(delimiter_pos + 1);
        if (port_string.empty() || !all_of(port_string.begin(), port_string.end(), ::isdigit)) {
            return genError("The provided Port is not valid. Port: " + port_string);
        }

        udp_socket->server.sin_family = AF_INET;
        uint16_t port = stoi(port_string);
        udp_socket->server.sin_port = htons(port);

        if (!udp_socket->isServerSock()) {
            if (connect(
                    udp_socket->getSocket(),
                    reinterpret_cast<struct sockaddr *>(&udp_socket->server),
                    sizeof(struct sockaddr_in)
                ) == -1
            ) {
                return genError("Failed to connect socket");
            }
            return move(udp_socket);
        }

        static const int on = 1;
        static const int options = SO_REUSEADDR | SO_REUSEPORT;
        if (setsockopt(udp_socket->getSocket(), SOL_SOCKET, options, (char *)&on, sizeof(on)) < 0) {
            dbgWarning(D_SOCKET) << "Failed to set the socket descriptor as reusable";
            return genError("Failed to set the socket descriptor as reusable");
        }

        if (bind(
                udp_socket->getSocket(),
                reinterpret_cast<struct sockaddr *>(&(udp_socket->server)),
                sizeof(struct sockaddr_un)
            ) < 0
        ) {
            dbgWarning(D_SOCKET) << "Failed to bind the socket: " << strerror(errno);
            return genError("Failed to bind the socket");
        }

        return move(udp_socket);
    }

    Maybe<vector<char>>
    receiveDataBlocking(uint data_size) override
    {
        return receiveData(data_size, MSG_DONTWAIT);
    }

    Maybe<vector<char>>
    receiveDataNonBlocking(uint data_size) override
    {
        return receiveData(data_size, 0);
    }

    void cleanServer() override {}

    UDPSocket(bool _is_blocking, bool _is_server_socket)
            :
        SocketInternal(_is_blocking, _is_server_socket)
    {
        socket_int = socket(AF_INET, SOCK_DGRAM, 0);
    }

private:
    struct sockaddr_in server;
    Maybe<vector<char>>
    receiveData(uint data_size, int flag) {
        if (data_size == 0) data_size = udp_max_packet_size;
        dbgDebug(D_SOCKET) << "data_size: " << data_size;
        vector<char> param_to_read(data_size, 0);
        int res = recv(socket_int, param_to_read.data(), data_size, flag);

        if (res == -1) {
            string error_message = strerror(errno);
            dbgWarning(D_SOCKET) << "Failed to read data, Error: " + error_message;
            return genError(
                "Failed to read data, Error: " + error_message
            );
        }
        param_to_read.resize(res);
        return param_to_read;
    }
};

class UnixSocket : public SocketInternal
{
public:
    static Maybe<unique_ptr<UnixSocket>>
    connectSock(bool _is_blocking, bool _is_server, const string &_address)
    {
        unique_ptr<UnixSocket> unix_socket(make_unique<UnixSocket>(_is_blocking, _is_server));
        if (unix_socket->getSocket() <= 0) return genError("Failed to create socket");

        unix_socket->server.sun_family = AF_UNIX;
        strncpy(unix_socket->server.sun_path, _address.c_str(), sizeof(unix_socket->server.sun_path) - 1);

        if (!unix_socket->isServerSock()) {
            if (connect(
                    unix_socket->getSocket(),
                    reinterpret_cast<struct sockaddr *>(&unix_socket->server),
                    sizeof(struct sockaddr_un)
                ) == -1
            ) {
                return genError("Failed to connect socket");
            }
            return move(unix_socket);
        }

        static const int on = 1;
        if (setsockopt(unix_socket->getSocket(), SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0) {
            dbgWarning(D_SOCKET) << "Failed to set the socket descriptor as reusable";
            return genError("Failed to set the socket descriptor as reusable");
        }

        const int priority = 6;
        if (setsockopt(unix_socket->getSocket(), SOL_SOCKET, SO_PRIORITY, (char *)&priority, sizeof(priority)) < 0) {
            dbgWarning(D_SOCKET) << "Failed to set the socket priority to highest";
            return genError("Failed to set the socket priority to highest");
        }

        if (ioctl(unix_socket->getSocket(), FIONBIO, (char *)&on) < 0) {
            dbgWarning(D_SOCKET) << "Failed to set the socket as non-blocking";
            return genError("Failed to set the socket as non-blocking");
        }

        unlink(unix_socket->server.sun_path);
        if (bind(
                unix_socket->getSocket(),
                reinterpret_cast<struct sockaddr *>(&unix_socket->server),
                sizeof(struct sockaddr_un)
            ) == -1) {
            dbgWarning(D_SOCKET) << "Failed to bind the socket: " << strerror(errno);
            return genError("Failed to bind the socket");
        }

        const int listen_backlog = 32;
        if (listen(unix_socket->getSocket(), listen_backlog) == -1) {
            dbgWarning(D_SOCKET) << "Failed to set the listening socket: " << strerror(errno);
            return genError("Failed to set the listening socket");
        }

        chmod(unix_socket->server.sun_path, 0666);

        return move(unix_socket);
    }

    void cleanServer() override
    {
        unlink(server.sun_path);
    }

    UnixSocket(bool _is_blocking, bool _is_server_socket) : SocketInternal(_is_blocking, _is_server_socket)
    {
        socket_int = socket(AF_UNIX, SOCK_STREAM, 0);
    }

private:
    struct sockaddr_un server;
};

class UnixDGSocket : public SocketInternal
{
public:
    static Maybe<unique_ptr<UnixDGSocket>>
    connectSock(bool _is_blocking, bool _is_server, const string &_address)
    {
        unique_ptr<UnixDGSocket> unix_socket(make_unique<UnixDGSocket>(_is_blocking, _is_server));
        if (unix_socket->getSocket() <= 0) return genError("Failed to create socket");

        unix_socket->server.sun_family = AF_UNIX;
        strncpy(unix_socket->server.sun_path, _address.c_str(), sizeof(unix_socket->server.sun_path) - 1);

        if (!unix_socket->isServerSock()) {
            if (connect(
                    unix_socket->getSocket(),
                    reinterpret_cast<struct sockaddr *>(&unix_socket->server),
                    sizeof(struct sockaddr_un)
                ) == -1
            ) {
                return genError("Failed to connect socket");
            }
            return move(unix_socket);
        }

        static const int on = 1;
        if (setsockopt(unix_socket->getSocket(), SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0) {
            dbgWarning(D_SOCKET) << "Failed to set the socket descriptor as reusable";
            return genError("Failed to set the socket descriptor as reusable");
        }

        const int priority = 6;
        if (setsockopt(unix_socket->getSocket(), SOL_SOCKET, SO_PRIORITY, (char *)&priority, sizeof(priority)) < 0) {
            dbgWarning(D_SOCKET) << "Failed to set the socket priority to highest";
            return genError("Failed to set the socket priority to highest");
        }

        if (ioctl(unix_socket->getSocket(), FIONBIO, (char *)&on) < 0) {
            dbgWarning(D_SOCKET) << "Failed to set the socket as non-blocking";
            return genError("Failed to set the socket as non-blocking");
        }

        unlink(unix_socket->server.sun_path);
        if (bind(
                unix_socket->getSocket(),
                reinterpret_cast<struct sockaddr *>(&unix_socket->server),
                sizeof(struct sockaddr_un)
            ) == -1) {
            dbgWarning(D_SOCKET) << "Failed to bind the socket: " << strerror(errno);
            return genError("Failed to bind the socket");
        }

        chmod(unix_socket->server.sun_path, 0666);

        return move(unix_socket);
    }

    void cleanServer() override
    {
        unlink(server.sun_path);
    }

    Maybe<vector<char>>
    receiveDataBlocking(uint data_size) override
    {
        return receiveDGData(data_size, MSG_DONTWAIT);
    }

    Maybe<vector<char>>
    receiveDataNonBlocking(uint data_size) override
    {
        return receiveDGData(data_size, 0);
    }

    Maybe<vector<char>>
    receiveDGData(uint data_size, int flag)
    {
        if (data_size == 0) data_size = udp_max_packet_size;
        dbgDebug(D_SOCKET) << "data_size: " << data_size;
        vector<char> param_to_read(data_size, 0);
        int res = recv(socket_int, param_to_read.data(), data_size, flag);

        if (res == -1) {
            string error_message = strerror(errno);
            dbgWarning(D_SOCKET) << "Failed to read data, Error: " + error_message;
            return genError(
                "Failed to read data, Error: " + error_message
            );
        }
        param_to_read.resize(res);
        return param_to_read;
    }

    UnixDGSocket(bool _is_blocking, bool _is_server_socket)
        :
        SocketInternal(_is_blocking, _is_server_socket)
    {
        socket_int = socket(AF_UNIX, SOCK_DGRAM, 0);
    }

private:
    struct sockaddr_un server;
};

class SocketIS::Impl
        :
    Singleton::Provide<I_Socket>::From<SocketIS>
{
public:
    Impl() {};

    void fini();

    Maybe<socketFd>
    genSocket(SocketType type, bool is_blocking, bool is_server, const string &address) override;
    Maybe<socketFd>
    acceptSocket(socketFd server_socket_fd, bool is_blocking, const string &authorized_ip = "") override;

    void closeSocket(socketFd &socket_fd) override;
    bool writeData(socketFd socket_fd, const vector<char> &data) override;
    Maybe<vector<char>> receiveData(socketFd socket_fd, uint data_size, bool is_blocking = true) override;
    bool isDataAvailable(socketFd socket) override;

private:
    map<socketFd, unique_ptr<SocketInternal>> active_sockets;
};

Maybe<I_Socket::socketFd>
SocketIS::Impl::genSocket(
    SocketType type,
    bool is_blocking,
    bool is_server,
    const string &address)
{
    unique_ptr<SocketInternal> new_sock;
    string socketTypeName("unknown");

    if (type == SocketType::UNIX) {
        Maybe<unique_ptr<SocketInternal>> unix_sock = UnixSocket::connectSock(is_blocking, is_server, address);
        if (!unix_sock.ok()) return unix_sock.passErr();
        new_sock = unix_sock.unpackMove();
        socketTypeName = "UNIX";
    } else if (type ==  SocketType::UNIXDG) {
        Maybe<unique_ptr<SocketInternal>> unix_dg_sock = UnixDGSocket::connectSock(is_blocking, is_server, address);
        if (!unix_dg_sock.ok()) return unix_dg_sock.passErr();
        new_sock = unix_dg_sock.unpackMove();
        socketTypeName = "UNIXDG";
    } else if (type == SocketType::TCP) {
        Maybe<unique_ptr<SocketInternal>> tcp_sock = TCPSocket::connectSock(is_blocking, is_server, address);
        if (!tcp_sock.ok()) return tcp_sock.passErr();
        new_sock = tcp_sock.unpackMove();
        socketTypeName = "TCP";
    } else if (type == SocketType::UDP) {
        Maybe<unique_ptr<SocketInternal>> udp_sock = UDPSocket::connectSock(is_blocking, is_server, address);
        if (!udp_sock.ok()) return udp_sock.passErr();
        new_sock = udp_sock.unpackMove();
        socketTypeName = "UDP";
    } else {
        return genError("Trying to instantiate socket of unknown type");
    }

    socketFd socket_fd = new_sock->getSocket();
    active_sockets.insert(make_pair(socket_fd, move(new_sock)));

    dbgTrace(D_SOCKET)
        << "Successfully initialized socket. "
        << "Socket FD: "
        << socket_fd
        << ", Type: "
        << socketTypeName
        << ", Is blocking: "
        << (is_blocking ? "true" : "false")
        << ", Is Server: "
        << (is_server ? "true" : "false")
        << ", Address: "
        << address;

    return socket_fd;
}

Maybe<I_Socket::socketFd>
SocketIS::Impl::acceptSocket(socketFd server_socket_fd, bool is_blocking, const string &authorized_ip)
{
    auto server_sock = active_sockets.find(server_socket_fd);
    if (server_sock == active_sockets.end()) return genError("The provided server socket fd does not exist");
    if (!server_sock->second->isServerSock()) {
        return genError("The provided socket file descriptor does not represent a server socket");
    }

    Maybe<unique_ptr<SocketInternal>> client_sock = server_sock->second->acceptConn(is_blocking, authorized_ip);
    if (!client_sock.ok()) return client_sock.passErr();

    socketFd socket_fd = client_sock.unpack()->getSocket();
    active_sockets[socket_fd] = client_sock.unpackMove();
    return socket_fd;
}

void
SocketIS::Impl::closeSocket(socketFd &socket_fd)
{
    auto sock = active_sockets.find(socket_fd);
    if (sock != active_sockets.end()) {
        active_sockets.erase(socket_fd);
        socket_fd = -1;
    }
}

bool
SocketIS::Impl::writeData(socketFd socket_fd, const vector<char> &data)
{
    auto sock = active_sockets.find(socket_fd);
    if (sock == active_sockets.end()) {
        dbgWarning(D_SOCKET) << "The provided socket file descriptor does not exist. Socket FD: " << socket_fd;
        return false;
    }

    return sock->second->writeData(data);
}

Maybe<vector<char>>
SocketIS::Impl::receiveData(socketFd socket_fd, uint data_size, bool is_blocking)
{
    auto sock = active_sockets.find(socket_fd);
    if (sock == active_sockets.end()) {
        dbgWarning(D_SOCKET) << "The provided socket file descriptor does not exist. Socket FD: " << socket_fd;
        return genError("The provided socket fd does not exist");
    }

    return is_blocking ?
        sock->second->receiveDataBlocking(data_size) :
        sock->second->receiveDataNonBlocking(data_size);
}

bool
SocketIS::Impl::isDataAvailable(socketFd socket)
{
    auto sock = active_sockets.find(socket);
    if (sock == active_sockets.end()) {
        dbgWarning(D_SOCKET) << "The provided socket file descriptor does not exist. Socket FD: " << socket;
        return false;
    }

    return sock->second->isDataAvailable();
}

void
SocketIS::Impl::fini()
{
    active_sockets.clear();
}

SocketIS::SocketIS()
        :
    Component("SocketIS"),
    pimpl(make_unique<Impl>())
{
}

SocketIS::~SocketIS()
{
}

void
SocketIS::fini()
{
    pimpl->fini();
}
