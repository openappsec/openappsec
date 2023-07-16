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
    bool addRestCall(RestAction oper, const string &uri, unique_ptr<RestInit> &&init) override;
    uint16_t getListeningPort() const override { return listening_port; }
    Maybe<std::string> getSchema(const std::string &uri) const override;
    Maybe<std::string> invokeRest(const std::string &uri, istream &in) const override;

private:
    void prepareConfiguration();
    Maybe<uint, Context::Error> getPortConfig(const string &config) const;

    string changeActionToString(RestAction oper);

    int fd = -1;
    I_MainLoop::RoutineID id;
    I_MainLoop *mainloop;
    map<string, unique_ptr<RestInit>> rest_calls;
    uint16_t listening_port = 0;
    vector<uint16_t> port_range;
};

bool
RestServer::Impl::bindRestServerSocket(struct sockaddr_in &addr, vector<uint16_t> port_range)
{
    for (uint16_t port : port_range) {
        addr.sin_port = htons(port);

        if (bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == 0) return true;
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
        dbgAssert(range_start.ok() && range_end.ok()) << "Rest port configuration was not provided";
        dbgAssert(*range_start < *range_end) << "Rest port range corrupted (lower bound higher then upper bound)";

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
        fd = socket(AF_INET, SOCK_STREAM, 0);
        dbgAssert(fd >= 0) << "Failed to open a socket";
        int socket_enable = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &socket_enable, sizeof(int)) < 0) {
            dbgWarning(D_API) << "Could not set the socket options";
        }

        struct sockaddr_in addr;
        bzero(&addr, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        while (!bindRestServerSocket(addr, port_range)) {
            mainloop->yield(bind_retry_interval_msec);
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

        listening_port = ntohs(addr.sin_port);
        dbgInfo(D_API) << "REST server started: " << listening_port;
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
    int new_socket = accept(fd, nullptr, nullptr);
    if (new_socket < 0) {
        dbgWarning(D_API) << "Failed to accept a new socket";
        return;
    }
    dbgDebug(D_API) << "Starting a new socket: " << new_socket;

    RestConn conn(new_socket, mainloop, this);
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
    return rest_calls.emplace(make_pair(full_uri, move(rest))).second;
}

Maybe<std::string>
RestServer::Impl::getSchema(const std::string &uri) const
{
    auto iter = rest_calls.find(uri);
    if (iter == rest_calls.end()) return genError("No matching REST call was found");

    auto instance = iter->second->getRest();
    stringstream out;
    instance->performOutputingSchema(out);
    return out.str();
}

Maybe<std::string>
RestServer::Impl::invokeRest(const std::string &uri, istream &in) const
{
    auto iter = rest_calls.find(uri);
    if (iter == rest_calls.end()) return genError("No matching REST call was found");
    auto instance = iter->second->getRest();
    return instance->performRestCall(in);
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
            dbgAssert(false) << "Unknown REST action";
            return "";
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
}
