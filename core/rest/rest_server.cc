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

#include "rest_server.h"

#include <arpa/inet.h>
#include <unistd.h>

#include "common.h"
#include "singleton.h"
#include "config.h"
#include "debug.h"
#include "rest_conn.h"
#include "i_rest_invoke.h"

#include <syslog.h>

using namespace std;

USE_DEBUG_FLAG(D_API);

static const int listen_limit = 100;
static const chrono::milliseconds bind_retry_interval_msec = chrono::milliseconds(500);
static const AlertInfo alert(AlertTeam::CORE, "rest i/s");

#include <iostream>

class RestServer::Impl
        :
    Singleton::Provide<I_RestApi>::From<RestServer>,
    I_RestInvoke
{
public:
    void init();
    void fini();

    void startNewConnection() const;

    bool bindRestServerSocket(struct sockaddr_in &addr, vector<uint16_t> port_range);
    bool bindRestServerSocket(struct sockaddr_in6 &addr, vector<uint16_t> port_range);
    bool addRestCall(RestAction oper, const string &uri, unique_ptr<RestInit> &&init) override;
    bool addGetCall(const string &uri, const function<string()> &cb) override;
    bool addWildcardGetCall(const string &uri, const function<string(const string &)> &callback);
    uint16_t getListeningPort() const override { return listening_port; }
    Maybe<string> getSchema(const string &uri) const override;
    Maybe<string> invokeRest(const string &uri, istream &in) const override;
    bool isGetCall(const string &uri) const override;
    string invokeGet(const string &uri) const override;

private:
    void prepareConfiguration();
    Maybe<uint, Context::Error> getPortConfig(const string &config) const;

    string changeActionToString(RestAction oper);

    int fd = -1;
    I_MainLoop::RoutineID id;
    I_MainLoop *mainloop;
    map<string, unique_ptr<RestInit>> rest_calls;
    map<string, function<string()>> get_calls;
    map<string, function<string(const string &)>> wildcard_get_calls;
    uint16_t listening_port = 0;
    vector<uint16_t> port_range;
};

bool
RestServer::Impl::bindRestServerSocket(struct sockaddr_in &addr, vector<uint16_t> port_range)
{
    dbgFlow(D_API) << "Binding IPv4 socket";
    for (uint16_t port : port_range) {
        addr.sin_port = htons(port);

        if (bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == 0) return true;

        if (errno == EADDRINUSE) {
            dbgDebug(D_API) << "Port " << port << " is already in use";
        } else {
            dbgDebug(D_API) << "Failed to bind to port " << port << " with error: " << strerror(errno);
        }
    }

    return false;
}

bool
RestServer::Impl::bindRestServerSocket(struct sockaddr_in6 &addr, vector<uint16_t> port_range)
{
    dbgFlow(D_API) << "Binding IPv6 socket";
    for (uint16_t port : port_range) {
        addr.sin6_port = htons(port);

        if (bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in6)) == 0) return true;

        if (errno == EADDRINUSE) {
            dbgDebug(D_API) << "Port " << port << " is already in use";
        } else {
            dbgDebug(D_API) << "Failed to bind to port " << port << " with error: " << strerror(errno);
        }
    }

    return false;
}

Maybe<uint, Context::Error>
RestServer::Impl::getPortConfig(const string &config) const
{
    auto conf_value = getConfiguration<uint>("connection", config);
    if (conf_value.ok()) return *conf_value;
    return Singleton::Consume<I_Environment>::by<RestServer>()->get<uint>(config);
}

void
RestServer::Impl::prepareConfiguration()
{
    auto primary_port = getPortConfig("Nano service API Port Primary");
    auto alternative_port = getPortConfig("Nano service API Port Alternative");
    if (primary_port.ok() && alternative_port.ok()) {
        port_range.push_back(*primary_port);
        port_range.push_back(*alternative_port);
    } else {
        auto range_start = getPortConfig("Nano service API Port Range start");
        auto range_end = getPortConfig("Nano service API Port Range end");
        if (!(range_start.ok() && range_end.ok()) || !(*range_start < *range_end)) {
            dbgAssertOpt(range_start.ok() && range_end.ok()) << alert << "Rest port configuration was not provided";
            dbgAssertOpt(*range_start < *range_end)
                << alert
                << "Rest port range corrupted (lower bound higher then upper bound)";
            range_start = 0;
            range_end = 1;
        }
        port_range.resize(*range_end - *range_start);
        for (uint16_t i = 0, port = *range_start; i < port_range.size(); i++, port++) {
            port_range[i] = port;
        }
    }
}

void
RestServer::Impl::init()
{
    mainloop = Singleton::Consume<I_MainLoop>::by<RestServer>();

    auto init_connection = [this] () {
        auto allow_external_conn = "Nano service API Allow Get From External IP";
        auto conf_value = getConfiguration<bool>("connection", allow_external_conn);
        bool accept_get_from_external_ip = false;
        if (conf_value.ok()) {
            accept_get_from_external_ip = *conf_value;
        } else {
            auto env_value = Singleton::Consume<I_Environment>::by<RestServer>()->get<bool>(allow_external_conn);
            if (env_value.ok()) {
                accept_get_from_external_ip = *env_value;
            }
        }

        bool is_ipv6 = getProfileAgentSettingWithDefault(false, "enable_ipv6");
        if (is_ipv6) {
            fd = socket(AF_INET6, SOCK_STREAM, 0);
        } else {
            fd = socket(AF_INET, SOCK_STREAM, 0);
        }

        dbgAssert(fd >= 0) << alert << "Failed to open a socket";

        int socket_enable = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &socket_enable, sizeof(int)) < 0) {
            dbgWarning(D_API) << "Could not set the socket options";
        }

        if (is_ipv6) {
            dbgDebug(D_API) << "IPv6 socket opened successfully";
            int option = 0;
            if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &option, sizeof(option)) < 0) {
                dbgWarning(D_API) << "Could not set the IPV6_V6ONLY option";
            }

            struct sockaddr_in6 addr6;
            bzero(&addr6, sizeof(addr6));
            addr6.sin6_family = AF_INET6;
            addr6.sin6_addr = in6addr_any;
            dbgDebug(D_API) << "Socket listening on any address";

            while (!bindRestServerSocket(addr6, port_range)) {
                mainloop->yield(bind_retry_interval_msec);
            }
            listening_port = ntohs(addr6.sin6_port);
        } else {
            dbgDebug(D_API) << "IPv4 socket opened successfully";
            struct sockaddr_in addr;
            bzero(&addr, sizeof(addr));
            addr.sin_family = AF_INET;
            if (accept_get_from_external_ip) {
                addr.sin_addr.s_addr = htonl(INADDR_ANY);
                dbgDebug(D_API) << "Socket listening on any address";
            } else {
                addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                dbgDebug(D_API) << "Socket listening on local address";
            }

            while (!bindRestServerSocket(addr, port_range)) {
                mainloop->yield(bind_retry_interval_msec);
            }
            listening_port = ntohs(addr.sin_port);
        }

        listen(fd, listen_limit);

        auto is_primary = Singleton::Consume<I_Environment>::by<RestServer>()->get<bool>("Is Rest primary routine");
        id = mainloop->addFileRoutine(
            I_MainLoop::RoutineType::Offline,
            fd,
            [&] () { this->startNewConnection(); },
            "REST server listener",
            is_primary.ok() && *is_primary
        );
        dbgInfo(D_API)
            << "REST server started: "
            << listening_port
            << ". Accepting: "
            << (accept_get_from_external_ip ? "external" : "loopback")
            << " connections";
        Singleton::Consume<I_Environment>::by<RestServer>()->registerValue<int>("Listening Port", listening_port);
    };

    prepareConfiguration();
    mainloop->addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, init_connection, "REST server startup");
}

void
RestServer::Impl::fini()
{
    dbgInfo(D_API) << "Stoping the REST server";
    if (fd != -1) {
        close(fd);
        fd = -1;
    }
    if (mainloop->doesRoutineExist(id)) mainloop->stop(id);
    port_range.clear();
}

void
RestServer::Impl::startNewConnection() const
{
    dbgFlow(D_API) << "Starting a new connection";
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    int new_socket = accept(fd, (struct sockaddr *)&addr, &addr_len);
    if (new_socket < 0) {
        dbgWarning(D_API) << "Failed to accept a new socket: " << strerror(errno);
        return;
    }

    dbgDebug(D_API) << "Starting a new socket: " << new_socket;
    bool is_external = false;
    if (addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *) &addr;
        if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
            struct in_addr ipv4_addr;
            memcpy(&ipv4_addr, &addr_in6->sin6_addr.s6_addr[12], sizeof(ipv4_addr));
            is_external = ipv4_addr.s_addr != htonl(INADDR_LOOPBACK);
        } else {
            is_external = memcmp(&addr_in6->sin6_addr, &in6addr_loopback, sizeof(in6addr_loopback)) != 0;
        }
    } else {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)&addr;
        is_external = addr_in->sin_addr.s_addr != htonl(INADDR_LOOPBACK);
    }
    RestConn conn(new_socket, mainloop, this, is_external);
    mainloop->addFileRoutine(
        I_MainLoop::RoutineType::Offline,
        new_socket,
        [conn] () { conn.parseConn(); },
        "REST server connection handler"
    );
}

bool
RestServer::Impl::addRestCall(RestAction oper, const string &uri, unique_ptr<RestInit> &&rest)
{
    string full_uri = changeActionToString(oper) + uri;
    if (get_calls.find(full_uri) != get_calls.end()) return false;
    return rest_calls.emplace(make_pair(full_uri, move(rest))).second;
}

bool
RestServer::Impl::addGetCall(const string &uri, const function<string()> &callback)
{
    if (rest_calls.find(uri) != rest_calls.end()) return false;
    return get_calls.emplace(uri, callback).second;
}

bool
RestServer::Impl::addWildcardGetCall(const string &uri, const function<string(const string&)> &callback)
{
    if (rest_calls.find(uri) != rest_calls.end()) return false;
    return wildcard_get_calls.emplace(uri, callback).second;
}

Maybe<string>
RestServer::Impl::getSchema(const string &uri) const
{
    auto iter = rest_calls.find(uri);
    if (iter == rest_calls.end()) return genError("No matching REST call was found");

    auto instance = iter->second->getRest();
    stringstream out;
    instance->performOutputingSchema(out);
    return out.str();
}

Maybe<string>
RestServer::Impl::invokeRest(const string &uri, istream &in) const
{
    auto iter = rest_calls.find(uri);
    if (iter == rest_calls.end()) return genError("No matching REST call was found");
    auto instance = iter->second->getRest();
    return instance->performRestCall(in);
}

bool
RestServer::Impl::isGetCall(const string &uri) const
{
    if (get_calls.find(uri) != get_calls.end()) return true;

    for (const auto &wildcard : wildcard_get_calls) {
        if (!uri.find(wildcard.first)) return true;
    }

    return false;
}

string
RestServer::Impl::invokeGet(const string &uri) const
{
    auto instance = get_calls.find(uri);
    if (instance != get_calls.end()) return instance->second();

    for (const auto &wildcard : wildcard_get_calls) {
        if (!uri.find(wildcard.first)) return wildcard.second(uri);
    }

    return "";
}

string
RestServer::Impl::changeActionToString(RestAction oper)
{
    switch(oper) {
        case RestAction::ADD: {
            return "add-";
        }
        case RestAction::SET: {
            return "set-";
        }
        case RestAction::SHOW: {
            return "show-";
        }
        case RestAction::DELETE: {
            return "delete-";
        }
        default: {
            dbgAssertOpt(false) << alert << "Unknown REST action";
            return "unknown-";
        }
    }
}

RestServer::RestServer() : Component("RestServer"), pimpl(make_unique<RestServer::Impl>()) {}

RestServer::~RestServer() {}

void
RestServer::init()
{
    pimpl->init();
}

void
RestServer::fini()
{
    pimpl->fini();
}

void
RestServer::preload()
{
    registerExpectedConfiguration<uint>("connection", "Nano service API Port Primary");
    registerExpectedConfiguration<uint>("connection", "Nano service API Port Alternative");
    registerExpectedConfiguration<uint>("connection", "Nano service API Port Range start");
    registerExpectedConfiguration<uint>("connection", "Nano service API Port Range end");
    registerExpectedConfiguration<bool>("connection", "Nano service API Allow Get From External IP");
}
