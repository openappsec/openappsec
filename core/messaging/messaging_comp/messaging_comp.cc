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

#include "messaging_comp.h"

#include <fstream>
#include <string>

#include "agent_core_utilities.h"
#include "connection_comp.h"
#include "rest.h"
#include "debug.h"
#include "messaging_buffer.h"

using namespace std;

USE_DEBUG_FLAG(D_MESSAGING);

class FogConnectionChecker : public ServerRest
{
public:
    void
    doCall() override
    {
        dbgTrace(D_MESSAGING) << "Checking connection to the FOG";
        auto response = Singleton::Consume<I_Messaging>::from<Messaging>()->sendSyncMessage(
            HTTPMethod::GET,
            "/access-manager/health/live",
            string("")
        );
        if (!response.ok()) {
            dbgTrace(D_MESSAGING) << "Failed to check connection to the FOG";
            connected_to_fog = false;
            error = response.getErr().toString();
            return;
        }
        if (response.unpack().getHTTPStatusCode() == HTTPStatusCode::HTTP_OK) {
            dbgTrace(D_MESSAGING) << "Connected to the FOG";
            connected_to_fog = true;
            error = "";
        } else {
            dbgTrace(D_MESSAGING) << "No connection to the FOG";
            connected_to_fog = false;
            error = response.unpack().toString();
        }
    }

private:
    S2C_PARAM(bool, connected_to_fog);
    S2C_PARAM(string, error);
};

void
MessagingComp::init()
{
    i_conn = Singleton::Consume<I_MessagingConnection>::from<ConnectionComponent>();
    i_messaging_buffer = Singleton::Consume<I_MessageBuffer>::from<MessagingBufferComponent>();
    agent_details = Singleton::Consume<I_AgentDetails>::by<Messaging>();

    auto i_mainloop = Singleton::Consume<I_MainLoop>::by<Messaging>();
    auto i_time_get = Singleton::Consume<I_TimeGet>::by<Messaging>();
    auto cache_timeout = getConfigurationWithDefault<int>(40, "message", "Cache timeout");
    fog_get_requests_cache.startExpiration(chrono::seconds(cache_timeout), i_mainloop, i_time_get);

    should_buffer_failed_messages = getConfigurationWithDefault<bool>(
        getProfileAgentSettingWithDefault<bool>(true, "eventBuffer.bufferFailedRequests"),
        "message",
        "Buffer Failed Requests"
    );

    if (Singleton::exists<I_RestApi>()) {
        Singleton::Consume<I_RestApi>::by<Messaging>()->addRestCall<FogConnectionChecker>(
            RestAction::SHOW,
            "check-fog-connection"
        );
    }
}

static bool
isMessageToFog(const MessageMetadata message_metadata)
{
    return message_metadata.isToFog();
}

Maybe<Connection>
MessagingComp::getConnection(MessageCategory category, const MessageMetadata &metadata)
{
    auto persistant_conn = getPersistentConnection(metadata, category);
    if (persistant_conn.ok()) {
        dbgTrace(D_MESSAGING) << "Found a persistant connection";
        return persistant_conn;
    }
    dbgDebug(D_MESSAGING) << persistant_conn.getErr();

    auto maybe_conn = i_conn->establishConnection(metadata, category);
    if (!maybe_conn.ok()) {
        dbgWarning(D_MESSAGING) << maybe_conn.getErr();
    }
    return maybe_conn;
}

Maybe<HTTPResponse, HTTPResponse>
MessagingComp::sendMessage(
    HTTPMethod method,
    const string &uri,
    const string &body,
    MessageCategory category,
    const MessageMetadata &message_metadata
)
{
    auto maybe_conn = getConnection(category, message_metadata);
    if (!maybe_conn.ok()) {
        dbgWarning(D_MESSAGING) << "Failed to get connection. Error: " << maybe_conn.getErr();
        return genError<HTTPResponse>(HTTPStatusCode::HTTP_UNKNOWN, maybe_conn.getErr());
    }

    Connection conn = maybe_conn.unpack();
    if (conn.isSuspended()) return suspendMessage(body, method, uri, category, message_metadata);

    bool is_to_fog = isMessageToFog(message_metadata);
    auto metadata = message_metadata;
    if (is_to_fog) {
        if (method == HTTPMethod::GET && fog_get_requests_cache.doesKeyExists(uri)) {
            HTTPResponse res = fog_get_requests_cache.getEntry(uri);
            dbgTrace(D_MESSAGING) << "Response returned from Fog cache. res body: " << res.getBody();

            return fog_get_requests_cache.getEntry(uri);
        }

        auto i_env = Singleton::Consume<I_Environment>::by<Messaging>();
        metadata.insertHeader("User-Agent", "Infinity Next (a7030abf93a4c13)");
        metadata.insertHeaders(i_env->getCurrentHeadersMap());
    }

    auto req = HTTPRequest::prepareRequest(
        conn,
        method,
        uri,
        metadata.getHeaders(),
        body,
        metadata.shouldSendAccessToken());
    if (!req.ok()) return genError(HTTPResponse(HTTPStatusCode::HTTP_UNKNOWN, req.getErr()));

    auto response = i_conn->sendRequest(conn, *req);
    if (!response.ok()) return response.passErr();

    auto response_data = response.unpack();

    if (response_data.getHTTPStatusCode() == HTTPStatusCode::HTTP_TOO_MANY_REQUESTS) {
        dbgDebug(D_MESSAGING) << "Too many requests. Suspend the message";
        auto rate_limit_metadata = message_metadata;
        uint retry_after_sec = 60;
        auto retry_after_header = response_data.getHeaderVal("retry-after");
        if (retry_after_header.ok()) {
            retry_after_sec = stoi(*retry_after_header);
        }
        rate_limit_metadata.setShouldBufferMessage(true);
        rate_limit_metadata.setRateLimitBlock(retry_after_sec);
        return suspendMessage(body, method, uri, category, rate_limit_metadata);
    }

    if (is_to_fog && method == HTTPMethod::GET) fog_get_requests_cache.emplaceEntry(uri, *response);
    return response;
}

Maybe<HTTPResponse, HTTPResponse>
MessagingComp::sendSyncMessage(
    HTTPMethod method,
    const string &uri,
    const string &body,
    MessageCategory category,
    const MessageMetadata &message_metadata
)
{
    Maybe<HTTPResponse, HTTPResponse> is_msg_send = sendMessage(method, uri, body, category, message_metadata);

    if (is_msg_send.ok()) return *is_msg_send;

    if (should_buffer_failed_messages && message_metadata.shouldBufferMessage()) {
        dbgTrace(D_MESSAGING) << "After sending error, buffering the message";
        i_messaging_buffer->pushNewBufferedMessage(body, method, uri, category, message_metadata, false);
    }
    return is_msg_send.passErr();
}

void
MessagingComp::sendAsyncMessage(
    HTTPMethod method,
    const string &uri,
    const string &body,
    MessageCategory category,
    const MessageMetadata &message_metadata,
    bool force_buffering
)
{
    MessageMetadata new_message_metadata = message_metadata;
    new_message_metadata.setShouldBufferMessage(force_buffering);
    i_messaging_buffer->pushNewBufferedMessage(body, method, uri, category, new_message_metadata, false);
}

Maybe<void, HTTPResponse>
MessagingComp::downloadFile(
    HTTPMethod method,
    const string &uri,
    const string &download_file_path,
    MessageCategory category,
    const MessageMetadata &message_metadata
)
{
    dbgTrace(D_MESSAGING) << "Send download file message";
    string parent_directory = download_file_path.substr(0, download_file_path.find_last_of("/\\"));
    if (!NGEN::Filesystem::exists(parent_directory)) {
        if (!NGEN::Filesystem::makeDirRecursive(parent_directory)) {
            string creation_err = "Failed to create the parent directory. Path: " + parent_directory;
            dbgWarning(D_MESSAGING) << creation_err;
            return genError(HTTPResponse(HTTPStatusCode::HTTP_UNKNOWN, creation_err));
        }
    }

    auto response = sendSyncMessage(method, uri, "", category, message_metadata);
    if (!response.ok()) return response.passErr();
    if (response.unpack().getHTTPStatusCode() != HTTPStatusCode::HTTP_OK) {
        return genError(HTTPResponse(response.unpack().getHTTPStatusCode(), response.unpack().getBody()));
    }
    ofstream file_stream(download_file_path);
    if (!file_stream.is_open()) {
        string open_err = "Failed to open the destination file. Path: " + download_file_path;
        dbgWarning(D_MESSAGING) << open_err;
        return genError(HTTPResponse(HTTPStatusCode::HTTP_UNKNOWN, open_err));
    }
    file_stream << response.unpack().getBody();
    file_stream.close();

    dbgTrace(D_MESSAGING) << "Successfully downloaded and save file to: " << download_file_path;
    return Maybe<void, HTTPResponse>();
}

Maybe<void, HTTPResponse>
MessagingComp::uploadFile(
    const string &uri,
    const string &upload_file_path,
    MessageCategory category,
    const MessageMetadata &message_metadata
)
{
    dbgTrace(D_MESSAGING) << "Send upload file message";

    ifstream file(upload_file_path);
    if (!file.is_open()) {
        string open_err = "Failed to open the file to upload. Path: " + upload_file_path;
        dbgWarning(D_MESSAGING) << open_err;
        return genError(HTTPResponse(HTTPStatusCode::HTTP_UNKNOWN, open_err));
    }

    stringstream buffer;
    buffer << file.rdbuf();
    file.close();

    Maybe<HTTPResponse, HTTPResponse> response =
        sendSyncMessage(HTTPMethod::PUT, uri, buffer.str(), category, message_metadata);

    if (!response.ok()) return response.passErr();
    if (response.unpack().getHTTPStatusCode() != HTTPStatusCode::HTTP_OK) {
        return genError(HTTPResponse(response.unpack().getHTTPStatusCode(), response.unpack().getBody()));
    }

    dbgTrace(D_MESSAGING) << "Successfully upload file from: " << upload_file_path;
    return Maybe<void, HTTPResponse>();
}

bool
MessagingComp::setFogConnection(const string &host, uint16_t port, bool is_secure, MessageCategory category)
{
    dbgTrace(D_MESSAGING) << "Setting a fog connection to " << host << ":" << port;
    MessageMetadata metadata(host, port, true);

    I_ProxyConfiguration *proxy_configuration = Singleton::Consume<I_ProxyConfiguration>::by<Messaging>();
    auto load_env_proxy = proxy_configuration->loadProxy();
    if (!load_env_proxy.ok()) {
        dbgDebug(D_MESSAGING)
            << "Could not initialize load proxy from environment, Error: "
            << load_env_proxy.getErr();
    }

    ProxyProtocol proxy_protocol = is_secure ? ProxyProtocol::HTTPS : ProxyProtocol::HTTP;
    if (proxy_configuration->getProxyExists(proxy_protocol)) {
        auto proxy_host = proxy_configuration->getProxyDomain(proxy_protocol);
        auto proxy_port = proxy_configuration->getProxyPort(proxy_protocol);
        auto maybe_proxy_auth = proxy_configuration->getProxyAuthentication(proxy_protocol);

        if (proxy_host.ok() && proxy_port.ok()) {
            string proxy_auth = maybe_proxy_auth.ok() ? *maybe_proxy_auth : "";
            dbgDebug(D_MESSAGING) << "Setting proxy address: " << *proxy_host << ":" << *proxy_port;
            MessageProxySettings proxy_settings(proxy_host.unpack(), proxy_auth, proxy_port.unpack());
            metadata.setProxySettings(proxy_settings);
        }
    }

    I_MessagingConnection *i_conn = Singleton::Consume<I_MessagingConnection>::from<ConnectionComponent>();
    auto conn = i_conn->establishConnection(metadata, category);
    if (!conn.ok()) {
        dbgWarning(D_MESSAGING) << "Failed to establish connection to fog: " << conn.getErr();
        return false;
    }

    dbgInfo(D_MESSAGING)
        << "Successfully connected to the Fog: "
        << host
        << ":"
        << port
        << " via "
        << (metadata.isProxySet() ? "proxy, using " : "")
        << (is_secure ? "secure" : "clear")
        << " connection";

    return true;
}

bool
MessagingComp::setFogConnection(MessageCategory category)
{
    I_AgentDetails *agent_details = Singleton::Consume<I_AgentDetails>::by<Messaging>();

    if (agent_details->getOrchestrationMode() == OrchestrationMode::OFFLINE) {
        dbgDebug(D_MESSAGING) << "Agent Is in offline mode and would not attempt connecting to the fog";
        return true;
    }

    if (!agent_details->readAgentDetails()) {
        dbgWarning(D_MESSAGING) << "Cannot establish connection to the Fog, failed to read agent details";
        return false;
    }

    auto domain = agent_details->getFogDomain();
    auto port = agent_details->getFogPort();
    auto is_secure_connection = agent_details->getSSLFlag();

    if (!domain.ok() || *domain == "" || !port.ok() || port == 0) {
        dbgWarning(D_MESSAGING) << "Cannot establish connection to the Fog, failed to get host and port details";
        return false;
    }

    return setFogConnection(*domain, *port, is_secure_connection, category);
}

Maybe<Connection>
MessagingComp::getPersistentConnection(const MessageMetadata &metadata, MessageCategory category) const
{
    if (!metadata.isToFog()) {
        auto maybe_conn = i_conn->getPersistentConnection(metadata.getHostName(), metadata.getPort(), category);
        if (maybe_conn.ok()) return *maybe_conn;
        return genError("Failed to get persistant connection based on host and port");
    }

    auto maybe_conn = i_conn->getFogConnectionByCategory(category);
    if (maybe_conn.ok()) return maybe_conn;
    return genError("Failed to get persistant connection to the fog");
}

Maybe<HTTPResponse, HTTPResponse>
MessagingComp::suspendMessage(
    const string &body,
    HTTPMethod method,
    const string &uri,
    MessageCategory category,
    const MessageMetadata &message_metadata
) const
{
    if (message_metadata.isRateLimitBlock()) {
        dbgInfo(D_MESSAGING) << "Rate limit block is active, message is suspended, message is buffered.";
        i_messaging_buffer->pushNewBufferedMessage(body, method, uri, category, message_metadata, false);
        return genError<HTTPResponse>(
            HTTPStatusCode::HTTP_TOO_MANY_REQUESTS,
            "The connection is suspended due to rate limit block, message is buffered."
        );
    }

    if (message_metadata.shouldBufferMessage()) {
        dbgWarning(D_MESSAGING) << "Buffering message due to connection suspended";
        i_messaging_buffer->pushNewBufferedMessage(body, method, uri, category, message_metadata, false);
        return genError<HTTPResponse>(
            HTTPStatusCode::HTTP_SUSPEND,
            "The connection is suspended due to consecutive message sending errors, message is buffered."
        );
    }

    return genError<HTTPResponse>(
        HTTPStatusCode::HTTP_SUSPEND, "The connection is suspended due to consecutive message sending errors."
    );
}
