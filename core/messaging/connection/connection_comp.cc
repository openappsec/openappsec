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

#include "connection_comp.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <algorithm>
#include <fstream>
#include <string>

#include "connection.h"
#include "maybe_res.h"
#include "messaging.h"
#include "smart_bio.h"

using namespace std;

USE_DEBUG_FLAG(D_CONNECTION);

class ConnectionComponent::Impl : Singleton::Provide<I_MessagingConnection>::From<ConnectionComponent>
{
public:
    void
    init()
    {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
    }

    Maybe<Connection>
    establishConnection(const MessageMetadata &metadata, MessageCategory category) override
    {
        if (metadata.isProxySet()) return establishNewProxyConnection(metadata, category);
        return establishNewConnection(metadata, category);
    }

    Maybe<Connection>
    getPersistentConnection(const string &host_name, uint16_t port, MessageCategory category) override
    {
        auto conn = persistent_connections.find(MessageConnectionKey(host_name, port, category));
        if (conn == persistent_connections.end()) return genError("No persistent connection found");
        if (conn->second.shouldCloseConnection()) {
            persistent_connections.erase(conn);
            return genError("The connection needs to reestablish");
        }
        return conn->second;
    }

    Maybe<Connection>
    getFogConnectionByCategory(MessageCategory category) override
    {
        auto maybe_fog_domain = Singleton::Consume<I_AgentDetails>::by<Messaging>()->getFogDomain();
        if (!maybe_fog_domain.ok()) {
            return genError("Failed to retrieve FOG domain " + maybe_fog_domain.getErr());
        }
        auto maybe_fog_port = Singleton::Consume<I_AgentDetails>::by<Messaging>()->getFogPort();
        if (!maybe_fog_port.ok()) {
            return genError("Failed to retrieve FOG port " + maybe_fog_port.getErr());
        }

        return getPersistentConnection(*maybe_fog_domain, *maybe_fog_port, category);
    }

    Maybe<HTTPResponse, HTTPResponse>
    sendRequest(Connection &connection, HTTPRequest request) override
    {
        return connection.sendRequest(request.toString());
    }

private:
    Maybe<Connection>
    establishNewConnection(const MessageMetadata &metadata, MessageCategory category)
    {
        dbgFlow(D_CONNECTION)
            << "Establishing a new connection. Host: "
            << metadata.getHostName()
            << ", port: "
            << metadata.getPort();
        MessageConnectionKey conn_key(metadata.getHostName(), metadata.getPort(), category);
        Connection conn(conn_key, metadata);

        const auto &external_certificate = metadata.getExternalCertificate();
        if (!external_certificate.empty()) conn.setExternalCertificate(external_certificate);

        auto connected = conn.establishConnection();
        if (!metadata.getConnectionFlags().isSet(MessageConnectionConfig::ONE_TIME_FOG_CONN)) {
            persistent_connections.emplace(conn_key, conn);
        }

        if (!connected.ok()) {
            string connection_err = "Failed to establish connection. Error: " + connected.getErr();
            dbgWarning(D_CONNECTION) << connection_err;
            return genError(connection_err);
        }

        dbgTrace(D_CONNECTION) << "Connection establish succssesfuly";
        return conn;
    }

    Maybe<Connection>
    establishNewProxyConnection(const MessageMetadata &metadata, MessageCategory category)
    {
        dbgTrace(D_CONNECTION)
            << "Establishing a new connection over proxy. Host: "
            << metadata.getHostName()
            << ", port: "
            << metadata.getPort()
            << ", proxy host: "
            << metadata.getProxySettings().getProxyHost()
            << ", proxy port: "
            << metadata.getProxySettings().getProxyPort();

        const auto &proxy = metadata.getProxySettings();
        MessageConnectionKey conn_key(metadata.getHostName(), metadata.getPort(), category);
        Connection conn(conn_key, metadata);

        auto is_proxy = conn.setProxySettings(proxy);
        if (!is_proxy.ok()) {
            string proxy_err = "Failed to set proxy settings. Error: " + is_proxy.getErr();
            return genError(proxy_err);
        }

        auto is_connected = conn.establishConnection();
        if (!is_connected.ok()) {
            string connection_err = "Failed to establish connection over proxy. Error: " + is_connected.getErr();
            dbgWarning(D_CONNECTION) << connection_err;
            return genError(connection_err);
        }

        dbgTrace(D_CONNECTION) << "Connection over proxy established succssesfuly";
        if (!metadata.getConnectionFlags().isSet(MessageConnectionConfig::ONE_TIME_FOG_CONN)) {
            persistent_connections.emplace(conn_key, conn);
        }
        return conn;
    }

    std::map<MessageConnectionKey, Connection> persistent_connections;
};

ConnectionComponent::ConnectionComponent() : pimpl(make_unique<Impl>())
{}

ConnectionComponent::~ConnectionComponent()
{}

void
ConnectionComponent::init()
{
    pimpl->init();
}
