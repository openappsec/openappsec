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

#include "proto_message_comp.h"

#include <algorithm>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "boost/regex.hpp"
#include <boost/algorithm/string.hpp>
#include <stdio.h>
#include <stdlib.h>
#include <poll.h>
#include <netdb.h>
#include <sstream>
#include <fstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <map>
#include <set>
#include <stdexcept>
#include <string>

#include "common.h"
#include "singleton.h"
#include "debug.h"
#include "rest.h"
#include "config.h"
#include "cache.h"
#include "messaging/http_core.h"
#include "http_encoder.h"
#include "http_decoder.h"
#include "agent_details.h"
#include "messaging_buffer/http_request_event.h"
#include "boost/asio.hpp"
#include "message_metric.h"
#include "smart_bio.h"
#include "connkey.h"
#include "agent_core_utilities.h"

using namespace std;
using namespace chrono;
using namespace smartBIO;

USE_DEBUG_FLAG(D_COMMUNICATION);
USE_DEBUG_FLAG(D_HTTP_REQUEST);

static string
tagToString(MessageTypeTag tag)
{
    switch(tag) {
        case MessageTypeTag::GENERIC: return "generic";
        case MessageTypeTag::LOG: return "log";
        case MessageTypeTag::DEBUG: return "debug";
        case MessageTypeTag::METRIC: return "metric";
        case MessageTypeTag::REPORT: return "report";
        case MessageTypeTag::WAAP_LEARNING: return "waap learning";
        case MessageTypeTag::INTELLIGENCE: return "intelligence";
        case MessageTypeTag::BUFFERED_MESSAGES: return "buffered messages";

        case MessageTypeTag::COUNT: break;
    }
    dbgAssert(false) << "Unsupported message type tag " << static_cast<int>(tag);
    return "";
}

class MessageConnection
{
public:
    MessageConnection(MessageConnection &&other);
    ~MessageConnection();
    // To prevent wrong usage
    MessageConnection() = delete;
    MessageConnection(const MessageConnection &other) = delete;
    MessageConnection& operator=(const MessageConnection &other) = delete;
    MessageConnection& operator=(MessageConnection &&other) = delete;

    static Maybe<MessageConnection>
    startNewConnection(
        const string &host,
        const uint16_t port,
        const bool _is_secure,
        MessageTypeTag _tag,
        const bool over_proxy = false,
        bool _is_external = false,
        bool is_ssl_ignore_validation = false
    );

    bool lock();
    bool unlock();

    bool sendData(const string &data) const;

    template<class T>
    Maybe<T> receiveResponse(I_MessageDecoder<T> &decoder);

    Maybe<void> reconnect(bool should_lock = true);
    const string & getHost() const { return host; }
    uint16_t getPort() const { return port_num; }
    MessageTypeTag getTag() const { return tag; }
    bool shouldYieldOnFailure() const { return should_yield_on_failure; }
    bool overProxy() const { return over_proxy; }
    bool isSecure() const { return is_secure; }
    bool isExternal() const { return is_external; }
    bool isReady() const;

    void setShouldYieldOnFailure(const bool should_yield) { should_yield_on_failure = should_yield; }
    void waitForQueue();
    void releaseQueue();

    ostream & print(ostream &os) const;

    static I_MainLoop *mainloop;
    static I_TimeGet *timer;
    static I_Encryptor *encryptor;
    static string proxy_host;
    static uint16_t proxy_port;
    static string proxy_auth;

private:
    MessageConnection(
        const string &_host,
        const uint16_t _port,
        bool _is_secure,
        const bool _over_proxy,
        bool _is_external,
        MessageTypeTag _tag,
        bool _is_ssl_ignore_validation = false
    )
            :
        is_secure(_is_secure),
        is_external(_is_external),
        over_proxy(_over_proxy),
        host(_host),
        port_num(_port),
        current_messaging_queue_pos(0),
        available_messaging_queue_pos(0),
        tag(_tag),
        is_ssl_ignore_validation(_is_ssl_ignore_validation)
    {}

    Maybe<void> doHandshake(const BioUniquePtr<BIO> &bio);
    bool verifyCert();
    bool encrypt();
    bool setCnVerification();
    bool setCtx();
    bool setSocket();
    bool connect(const string &host, const string &overwrite_port);
    bool shouldIgnoreSslValidation()const;
    bool isBioSocketReady() const;
    Maybe<string> calculatePublicKey(const BioUniquePtr<X509> &cert) const;
    Maybe<string> getPinnedCertificate();
    bool verifyCertPinning(const BioUniquePtr<X509> &cert);
    Maybe<void> establishConnection();
    Maybe<void> establishConnectionOverProxy();
    void getIpFromHostname(const string &hostname);
    static string printData(const string &data);
    static uint getConnectionTimeout();

    bool            is_secure;
    bool            is_external;
    bool            over_proxy;
    bool            connection_lock = false;
    bool            should_yield_on_failure = false;
    string          ca_chain_dir;
    string          host;
    string          pinned_cert_pub_key;
    uint16_t        port_num;
    uint64_t        current_messaging_queue_pos = 0;
    uint64_t        available_messaging_queue_pos = 0;
    MessageTypeTag  tag;
    string          filesystem_prefix = "";
    vector<string>  current_ips;
    bool            is_ssl_ignore_validation;
    uint            connection_closed_count = 0;

public:
    SSL                     *ssl_socket = nullptr;
    BioUniquePtr<SSL_CTX>   ssl_ctx = nullptr;
    BioUniquePtr<BIO>       bio = nullptr;
    static uint64_t         metrics_current_size;
};

I_MainLoop * MessageConnection::mainloop         = nullptr;
I_TimeGet * MessageConnection::timer             = nullptr;
I_Encryptor * MessageConnection::encryptor       = nullptr;
string MessageConnection::proxy_host             = "";
uint16_t MessageConnection::proxy_port           = 0;
string MessageConnection::proxy_auth             = "";
uint64_t MessageConnection::metrics_current_size = 0;

class ProtoMessageComp::Impl
        :
    Singleton::Provide<I_Messaging>::From<ProtoMessageComp>
{
    using Method = I_Messaging::Method;
    using MessageConnKey = tuple<string, uint16_t, MessageTypeTag>;
public:
    Impl() : active_connections() {}

    ~Impl() {}

    void
    init()
    {
        initSSL();
        timer = Singleton::Consume<I_TimeGet>::by<ProtoMessageComp>();
        encryptor = Singleton::Consume<I_Encryptor>::by<ProtoMessageComp>();
        MessageConnection::encryptor = Singleton::Consume<I_Encryptor>::by<ProtoMessageComp>();
        msg_buffer = Singleton::Consume<I_MessagingBuffer>::by<ProtoMessageComp>();
        MessageConnection::timer = Singleton::Consume<I_TimeGet>::by<ProtoMessageComp>();
        agent_details = Singleton::Consume<I_AgentDetails>::by<ProtoMessageComp>();
        proxy_configuration = Singleton::Consume<I_ProxyConfiguration>::by<ProtoMessageComp>();
        agent_details->readAgentDetails();

        if (!setActiveFog()) {
            dbgDebug(D_COMMUNICATION) << "Could not initialize active fog connection";
        }

        mainloop = Singleton::Consume<I_MainLoop>::by<ProtoMessageComp>();
        MessageConnection::mainloop = Singleton::Consume<I_MainLoop>::by<ProtoMessageComp>();

        auto cache_timeout = getConfigurationWithDefault<int>(2, "message", "Cache timeout");
        cache.startExpiration(seconds(cache_timeout), mainloop, timer);

        auto metrics_debugs_interval =
            chrono::seconds(getConfigurationWithDefault<uint64_t>(
                600,
                "message",
                "Metrics Routine Interval"
            )
        );
        message_queue_metric.init(
            "Message queue elements",
            ReportIS::AudienceTeam::AGENT_CORE,
            ReportIS::IssuingEngine::AGENT_CORE,
            metrics_debugs_interval,
            false
        );
        message_queue_metric.registerListener();

        mainloop->addOneTimeRoutine(
            I_MainLoop::RoutineType::System,
            [&] ()
            {
                while (true) {
                    if (
                        agent_details->getOrchestrationMode() == OrchestrationMode::OFFLINE ||
                        handleBufferedEvents() == 0
                    ) {
                        uint tmo = getConfigurationWithDefault<uint>(5, "message", "send event retry in sec");
                        mainloop->yield(chrono::seconds(tmo));
                    } else {
                        mainloop->yield(false);
                    }
                }
            },
            "Persistent messaging stream",
            false
        );
    }

    void
    fini()
    {
        MessageConnection::proxy_host = "";
        MessageConnection::proxy_port = 0;
        MessageConnection::proxy_auth = "";
        MessageConnection::encryptor = nullptr;
        MessageConnection::mainloop = nullptr;
        MessageConnection::timer = nullptr;
    }

    // LCOV_EXCL_START Reason: No proxy for ut
    void
    setFogProxy(const string &host, const uint16_t port, ProxyProtocol proto)
    {
        dbgTrace(D_COMMUNICATION) << "Proxy was set. Proxy: " << host << ":" << port;
        MessageConnection::proxy_host = host;
        MessageConnection::proxy_port = port;
        auto proxy_auth = proxy_configuration->getProxyCredentials(proto);
        if (proxy_auth.ok()) {
            MessageConnection::proxy_auth = proxy_auth.unpack();
        }
    }
    // LCOV_EXCL_STOP

    bool
    setActiveFog(const string &host, const uint16_t port, bool is_secure, MessageTypeTag tag) override
    {
        MessageConnKey fog_key = make_tuple("fog", 0, tag);
        proxy_protocol = is_secure ? ProxyProtocol::HTTPS : ProxyProtocol::HTTP;

        auto load_env_proxy = proxy_configuration->loadProxy();
        if (!load_env_proxy.ok()) {
            dbgDebug(D_COMMUNICATION)
                << "Could not initialize load proxy from environment, Error: "
                << load_env_proxy.getErr();
        }

        if (proxy_configuration->getProxyExists(proxy_protocol)) {
            auto proxy_host = proxy_configuration->getProxyDomain(proxy_protocol);
            auto proxy_port = proxy_configuration->getProxyPort(proxy_protocol);
            if (proxy_host.ok() && proxy_port.ok()) {
                setFogProxy(proxy_host.unpack(), proxy_port.unpack(), proxy_protocol);
            }
        }

        Maybe<MessageConnection> conn = MessageConnection::startNewConnection(
            host, port, is_secure, tag, proxy_configuration->getProxyExists(proxy_protocol)
        );
        if (!conn.ok()) {
            dbgWarning(D_COMMUNICATION)
                << "Failed to establish connection to the Fog: "
                << conn.getErr();
            return false;
        }

        if (active_connections.find(fog_key) == active_connections.end()) {
            active_connections.emplace(fog_key, conn.unpackMove());
        }

        dbgInfo(D_COMMUNICATION)
            << "Successfully connected to the Fog: "
            <<  host
            << ":"
            << port
            << " via "
            << (proxy_configuration->getProxyExists(proxy_protocol) ? "proxy, using " : "")
            << (is_secure ? "secure" : "clear")
            << " connection";

        tag_to_active_conn_key[tag] = fog_key;
        return true;
    }

    bool
    setActiveFog(MessageTypeTag tag = MessageTypeTag::GENERIC) override
    {
        string fog_host = "";
        uint16_t fog_port = 0;
        bool is_secure_connection = false;
        if (agent_details->readAgentDetails()) {
            auto domain = agent_details->getFogDomain();
            auto port = agent_details->getFogPort();
            is_secure_connection = agent_details->getSSLFlag();
            if (domain.ok() && port.ok()) {
                fog_host = domain.unpack();
                fog_port = port.unpack();
            }
        }

        if (agent_details->getOrchestrationMode() == OrchestrationMode::OFFLINE) {
            dbgDebug(D_COMMUNICATION) << "Agent Is in offline mode and would not attempt connecting to the fog";
            return true;
        }

        if(fog_host.empty() || fog_port == 0) {
            dbgWarning(D_COMMUNICATION)
                << "Cannot establish connection to the Fog: "
                << "failed to get host and port details";
            return false;
        }

        return setActiveFog(
            fog_host,
            fog_port,
            is_secure_connection,
            tag
        );
    }

    string
    buildFogHeaders(const string &headers)
    {
        string modified_headers = headers;
        modified_headers += "User-Agent: Infinity Next (a7030abf93a4c13)\r\n";
        auto i_env = Singleton::Consume<I_Environment>::by<ProtoMessageComp>();
        modified_headers += i_env->getCurrentHeaders();
        return modified_headers;
    }

    Maybe<string>
    sendPersistentMessage(
        bool get_reply,
        const string &&body,
        Method method,
        const string &url,
        const string &headers,
        bool should_yield,
        MessageTypeTag tag = MessageTypeTag::GENERIC,
        bool skip_sending = false) override
    {
        if (agent_details->getOrchestrationMode() == OrchestrationMode::OFFLINE) {
            return genError("Agent is in offline mode and cannot communicate with the fog");
        }

        string method_as_string;
        switch (method)
        {
            case Method::GET: {
                method_as_string = "GET";
                break;
            }
            case Method::POST: {
                method_as_string = "POST";
                break;
            }
            case Method::PUT: {
                method_as_string = "PUT";
                break;
            }
            case Method::PATCH: {
                method_as_string = "PATCH";
                break;
            }
            case Method::CONNECT: {
                method_as_string = "CONNECT";
                break;
            }
        }
        HTTPRequestSignature req_sig(method_as_string, url, tagToString(tag));

        bool should_buffer = false;
        if (pending_signatures.find(req_sig) != pending_signatures.end()) {
            dbgDebug(D_COMMUNICATION) << "Previous HTTP Request is already in queue. Buffering the request";
            should_buffer = true;
        }

        bool is_rejected = false;
        if (!should_buffer && !skip_sending) {
            ErrorCB fog_server_err = [&] (HTTPStatusCode http_status_code) mutable
            {
                is_rejected =
                    http_status_code == HTTPStatusCode::HTTP_PAYLOAD_TOO_LARGE ||
                    http_status_code == HTTPStatusCode::HTTP_MULTI_STATUS ||
                    http_status_code == HTTPStatusCode::HTTP_BAD_REQUEST;
            };
            pending_signatures.insert(req_sig);
            try {
                auto res = sendMessage(get_reply, body, method, url, headers, fog_server_err, should_yield, tag);
                pending_signatures.erase(req_sig);
                if (res.ok()) return res;

                bool should_buffer_default = getProfileAgentSettingWithDefault<bool>(
                    true,
                    "eventBuffer.bufferFailedRequests"
                );
                if (!getConfigurationWithDefault<bool>(should_buffer_default, "message", "Buffer Failed Requests")) {
                    dbgWarning(D_COMMUNICATION) << "Failed to send Request.";
                    return res;
                }
            } catch (...) {
                dbgWarning(D_COMMUNICATION) << "Can't send a persistent message, mainloop has been stopped";
                return genError("mainloop has been stopped");
            }
            dbgWarning(D_COMMUNICATION) << "Failed to send Request. Buffering the request.";
        }

        HTTPRequestEvent request_event(move(req_sig), headers, move(body));
        msg_buffer->bufferNewRequest(request_event, is_rejected);
        return genError("HTTP Request is buffered");
    }

    Maybe<string>
    sendMessage(
        bool get_reply,
        const string &body,
        Method method,
        const string &url,
        const string &headers,
        ErrorCB err_callback,
        bool should_yield,
        MessageTypeTag tag = MessageTypeTag::GENERIC) override
    {
        bool reuse_conns = getConfigurationWithDefault<bool>(true, "message", "Reuse connection");

        if (agent_details->getOrchestrationMode() == OrchestrationMode::OFFLINE) {
            return genError("Agent is in offline mode and cannot communicate with the fog");
        }

        if (tag_to_active_conn_key.find(tag) == tag_to_active_conn_key.end()) {
            if (!setActiveFog(tag)) {
                dbgWarning(D_COMMUNICATION)
                    << "Connection to fog for tag "
                    << tagToString(tag)
                    << " does not exist.";
                return genError("Cannot send message to the Fog");
            }
            reuse_conns = true;
        }

        MessageConnection &curr_conn = active_connections.at(tag_to_active_conn_key[tag]);

        if (!reuse_conns) {
            Maybe<void> res = curr_conn.reconnect();
            if(!res.ok()) {
                active_connections.erase(tag_to_active_conn_key[tag]);
                tag_to_active_conn_key.erase(tag);
                return genError(
                    "Cannot send message after failure in establishing new connection with the fog: " +
                    res.getErr()
                );
            }
        }

        ErrorCB fog_server_err = [this, err_callback, &curr_conn] (HTTPStatusCode http_status_code) {
            bool is_server_error = (
                http_status_code >= HTTPStatusCode::HTTP_INTERNAL_SERVER_ERROR &&
                http_status_code <= HTTPStatusCode::HTTP_NETWORK_AUTHENTICATION_REQUIRED
            );

            if (is_server_error) {
                if (last_fog_server_error == chrono::microseconds(0)) {
                    last_fog_server_error = timer->getMonotonicTime();
                }
                chrono::seconds dead_fog_timeout(
                    getConfigurationWithDefault<uint32_t>(
                        300,
                        "message",
                        "Internal Fog error timeout"
                    )
                );
                if (last_fog_server_error + chrono::microseconds(dead_fog_timeout) < timer->getMonotonicTime()) {
                    curr_conn.reconnect();
                    dbgWarning(D_COMMUNICATION)
                        << "Restarting the Fog connection after Fog error persists for more than "
                        << dead_fog_timeout.count()
                        << " seconds";
                    last_fog_server_error == chrono::microseconds(0);
                }
            }
            if (err_callback != nullptr) err_callback(http_status_code);
        };

        auto fog_res = sendMessage(
            curr_conn,
            get_reply,
            body,
            method,
            url,
            buildFogHeaders(headers),
            fog_server_err,
            should_yield
        );

        if (fog_res.ok()) last_fog_server_error = chrono::microseconds(0);

        return fog_res;
    }

    Maybe<string>
    sendMessage(
        bool get_reply,
        const string &body,
        Method method,
        const string &host,
        uint16_t port,
        Flags<MessageConnConfig> &conn_flags,
        const string &url,
        const string &headers,
        ErrorCB err_call_back,
        MessageTypeTag tag = MessageTypeTag::GENERIC) override
    {
        const MessageConnKey key = make_tuple(host, port, tag);
        bool is_one_time_conn = conn_flags.isSet(MessageConnConfig::ONE_TIME_CONN);
        bool is_secure_conn = conn_flags.isSet(MessageConnConfig::SECURE_CONN);
        bool is_external = conn_flags.isSet(MessageConnConfig::EXTERNAL);
        bool is_ssl_ignore_validation = conn_flags.isSet(MessageConnConfig::IGNORE_SSL_VALIDATION);

        auto reuse_conns = getConfigurationWithDefault<bool>(true, "message", "Reuse connection");
        if (reuse_conns) {
            map<MessageConnKey, MessageConnection>::iterator conn_iter = active_connections.find(key);
            if (conn_iter != active_connections.end()) {
                return sendMessage(conn_iter->second, get_reply, body, method, url, headers, err_call_back);
            }
        }
        auto load_env_proxy = proxy_configuration->loadProxy();
        if (!load_env_proxy.ok()) return genError(load_env_proxy.getErr());

        Maybe<MessageConnection> conn = MessageConnection::startNewConnection(
            host,
            port,
            is_secure_conn,
            tag,
            false,
            is_external,
            is_ssl_ignore_validation
        );
        if (!conn.ok()) return conn.passErr();

        if (!is_one_time_conn) {
            active_connections.emplace(key, conn.unpackMove());
            return sendMessage(
                active_connections.find(key)->second,
                get_reply,
                body,
                method,
                url,
                headers,
                err_call_back
            );
        }
        MessageConnection active_conn = conn.unpackMove();
        return sendMessage(active_conn, get_reply, body, method, url, headers, err_call_back);
    }

private:
    Maybe<string>
    sendMessage(
        MessageConnection &conn,
        bool get_reply,
        const string &body,
        Method method,
        const string &url,
        const string &headers,
        ErrorCB err_call_back,
        bool should_yield = true)
    {
        dbgDebug(D_COMMUNICATION) << "Sending a new message";

        if (conn.getHost() == "") return genError("No host provided");

        if (mainloop && should_yield) mainloop->yield(false);

        string full_url = conn.getHost() + url;
        if (method == Method::GET && cache.doesKeyExists(full_url)) return cache.getEntry(full_url);

        while (!conn.lock()) { mainloop->yield(true); }

        conn.setShouldYieldOnFailure(should_yield);
        Maybe<HTTPResponse> response = sendHTTPRequest(conn, body, method, url, headers);
        conn.unlock();

        if (response.ok()) {
            auto response_data = response->getResponse();
            if (response_data.ok()) {
                if (get_reply && method == Method::GET) cache.emplaceEntry(full_url, response_data.unpack());
            } else {
                if (err_call_back != nullptr) err_call_back(response->getStatusCode());
            }
            return response_data;
        }
        number_of_send_failure += 1;
        dbgTrace(D_COMMUNICATION) << "Number of a failed attempt to send a message " << number_of_send_failure;
        return response.passErr();
    }

    Maybe<HTTPResponse>
    sendHTTPRequest(
        MessageConnection &conn,
        const string &body,
        Method method,
        const string &url,
        const string &headers)
    {
        auto maybe_data = buildHTTPRequest(method, url, headers, body, conn);
        if (!maybe_data.ok()) {
            return maybe_data.passErr();
        }
        string data = maybe_data.unpack();

        uint num_of_retries = 0;
        const uint max_retries = 2;
        while (num_of_retries < max_retries) {
            Maybe<HTTPResponse> response = sendMessage(conn, data);
            if (response.ok()) return response;

            dbgDebug(D_COMMUNICATION)
                << "Failed to send HTTP request, trying to restart the connection. "
                << "Error: "
                << response.getErr();

            Maybe<void> connection_result = conn.reconnect(false);
            number_of_reconnects += 1;
            dbgTrace(D_COMMUNICATION) << "Number of an attempt to reconnect is " << number_of_reconnects;
            if (!connection_result.ok()) {
                number_of_reconnect_failures += 1;
                dbgTrace(D_COMMUNICATION)
                    << "Number of a failed attempt to reconnect is "
                    << number_of_reconnect_failures;
                return
                    genError(
                        string("Failed to reconnect after send request failure. Error: ") +
                        connection_result.getErr()
                    );
            }
            dbgDebug(D_COMMUNICATION) << "Successfully reconnected after a failure to send a request.";
            num_of_retries++;
        }

        return genError("Failed to send an HTTP request, reached the maximum number of retries " + max_retries);
    }

    Maybe<HTTPResponse>
    sendMessage(MessageConnection &conn, const string &data)
    {
        dbgTrace(D_COMMUNICATION) << "Acquiring connection lock. Connection: " << conn;

        if (!conn.isReady()) {
            dbgTrace(D_COMMUNICATION) << "Cannot send data over uninitialized connection";
            return genError("Failed to send HTTP request. The connection is uninitialized.");
        }

        conn.waitForQueue();
        auto release_queue_on_exit = make_scope_exit([&conn] () { conn.releaseQueue(); });
        if (conn.sendData(data)) {
            return getHttpResponse(conn);
        }

        return genError("Failed to send HTTP request");
    }

    string
    base64Decode(const string &input) const
    {
        string out;
        vector<int> T(256, -1);
        static const string base = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < 64; i++) { T[base[i]] = i; }

        int val = 0, val_balancer = -8;
        for (unsigned char c : input) {
            if (T[c] == -1) break;
            val = (val << 6) + T[c];
            val_balancer += 6;
            if (val_balancer >= 0) {
                out.push_back(char((val >> val_balancer) & 0xFF));
                val_balancer -= 8;
            }
        }
        return out;
    }

    void
    initSSL()
    {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
    }

    Maybe<HTTPResponse>
    getHttpResponse(MessageConnection &conn)
    {
        HTTPDecoder http_decoder(Method::GET);
        return conn.receiveResponse<HTTPResponse>(http_decoder);
    }

    Maybe<string>
    buildHTTPRequest(
        Method _method,
        const string &url,
        const string &headers,
        const string &body,
        const MessageConnection &conn)
    {
        HTTPRequest req;
        HTTPEncoder http_encoder(conn.getHost(), to_string(conn.getPort()));

        if (conn.isSecure()) http_encoder.isOverSSL();
        if (conn.overProxy()) http_encoder.isOverProxy();

        switch (_method)
        {
            case Method::GET: {
                req = http_encoder.Get(url);
                break;
            }
            case Method::POST: {
                req = http_encoder.Post(url);
                break;
            }
            case Method::PATCH: {
                req = http_encoder.Patch(url);
                break;
            }
            case Method::PUT: {
                req = http_encoder.Put(url);
                break;
            }
            case Method::CONNECT: {
                return http_encoder.Connect().toString();
            }
        }

        const string &access_token = agent_details->getAccessToken();

        if (!conn.isExternal() && !access_token.empty() && headers.find("Authorization") == std::string::npos) {
            req.insertHeader("Authorization", "Bearer " + access_token);
        }
        // Proxy-Authorization
        if (conn.overProxy() && !conn.isSecure()) {
            if (!MessageConnection::proxy_auth.empty()) {
                req.insertHeader(
                    "Proxy-Authorization",
                    "Basic " + encryptor->base64Encode(MessageConnection::proxy_auth)
                );
            } else {
                return genError("Failed to authenticate on a proxy with empty token.");
            }
        }

        req.insertHeader("Content-Length", to_string(body.size()));
        req.insertHeader("Content-type: application/json");
        req.insertHeader("Accept-Encoding: identity");
        if(headers.find("Connection:") == std::string::npos){
            req.insertHeader("Connection: keep-alive");
        }

        req.insertHeaders(headers);
        req.insertBody(body);

        return req.toString();
    }

    int
    handleBufferedEvents()
    {
        bool should_buffer_default = getProfileAgentSettingWithDefault<bool>(
            true,
            "eventBuffer.bufferFailedRequests"
        );
        if (!getConfigurationWithDefault<bool>(
                should_buffer_default,
                "message",
                "Buffer Failed Requests"
            )
        ) {
            return 0;
        }

        int count = 0;
        Maybe<HTTPRequestEvent> event = genError("empty");
        while ((event = msg_buffer->peekRequest()).ok()) {
            dbgTrace(D_COMMUNICATION) << "Trying to send HTTPEvent " << event.unpack().getSignature();

            bool is_rejected = false;
            // LCOV_EXCL_START Reason: We can't check it, since we don't control the response on ut yet
            ErrorCB fog_server_err = [&] (HTTPStatusCode http_status_code) mutable
            {
                is_rejected =
                    http_status_code == HTTPStatusCode::HTTP_PAYLOAD_TOO_LARGE ||
                    http_status_code == HTTPStatusCode::HTTP_MULTI_STATUS ||
                    http_status_code == HTTPStatusCode::HTTP_BAD_REQUEST;
            };
            // LCOV_EXCL_STOP

            auto maybe_method = stringToMethod(event.unpack().getMethod());
            if (!maybe_method.ok()) {
                dbgTrace(D_COMMUNICATION) << "Failed to sent the buffered request. Error: " << maybe_method.getErr();
                msg_buffer->popRequest();
                count++;
                mainloop->yield(false);
                continue;
            }

            auto resp = sendMessage(
                false,
                event.unpack().getBody(),
                *maybe_method,
                event.unpack().getURL(),
                event.unpack().getHeaders(),
                fog_server_err,
                false,
                MessageTypeTag::BUFFERED_MESSAGES
            );

            if (resp.ok()) {
                dbgTrace(D_COMMUNICATION) << "Successfully sent the buffered request" << event.unpack().getSignature();
                msg_buffer->popRequest();
                count++;
                mainloop->yield(false);
            } else {
                if (!is_rejected) {
                    dbgWarning(D_COMMUNICATION) << "Failed to send HTTPEvent " << event.unpack().getSignature();
                    return count;
                }
                msg_buffer->popRequest();
                msg_buffer->bufferNewRequest(*event, is_rejected);
                dbgWarning(D_COMMUNICATION) << "HTTPEvent " << event.unpack().getSignature() << " was rejected";
                mainloop->yield(false);
            }
        }
        return count;
    }

    Maybe<Method>
    stringToMethod(const string &name)
    {
        if (name == "GET") return Method::GET;
        if (name == "POST") return Method::POST;
        if (name == "PATCH") return Method::PATCH;
        if (name == "CONNECT") return Method::CONNECT;
        if (name == "PUT") return Method::PUT;

        return genError("Cannot convert unknown HTTP method to Enum. Method name: " + name);
    }

    bool is_proxy_configured_via_settings     = false;
    uint64_t number_of_reconnects             = 0;
    uint64_t number_of_reconnect_failures     = 0;
    uint64_t number_of_send_failure           = 0;
    I_AgentDetails *agent_details             = nullptr;
    I_MainLoop *mainloop                      = nullptr;
    I_TimeGet *timer                          = nullptr;
    I_Encryptor *encryptor                    = nullptr;
    I_MessagingBuffer *msg_buffer             = nullptr;
    I_ProxyConfiguration *proxy_configuration = nullptr;
    map<MessageConnKey, MessageConnection> active_connections;
    map<MessageTypeTag, MessageConnKey> tag_to_active_conn_key;
    ProxyProtocol proxy_protocol;
    TemporaryCache<string, string> cache;
    static const map<ProxyProtocol, string> proxyProtocolToString;
    set<HTTPRequestSignature> pending_signatures;
    chrono::microseconds last_fog_server_error = chrono::microseconds(0);
    MessageQueueMetric message_queue_metric;
    string filesystem_prefix = "";
};

MessageConnection::MessageConnection(MessageConnection &&other)
        :
    is_secure(other.is_secure),
    is_external(other.is_external),
    over_proxy(other.over_proxy),
    host(other.host),
    pinned_cert_pub_key(other.pinned_cert_pub_key),
    port_num(other.port_num),
    current_messaging_queue_pos(other.current_messaging_queue_pos),
    available_messaging_queue_pos(other.available_messaging_queue_pos),
    tag(other.tag),
    is_ssl_ignore_validation(other.is_ssl_ignore_validation),
    connection_closed_count(other.connection_closed_count),
    ssl_socket(move(other.ssl_socket)),
    ssl_ctx(move(other.ssl_ctx)),
    bio(move(other.bio))
{
    other.ssl_socket = nullptr;
    other.ssl_ctx = nullptr;
    other.bio = nullptr;
}

bool
MessageConnection::lock()
{
    if (connection_lock) return false;
    connection_lock = true;
    dbgTrace(D_COMMUNICATION) << "The connection lock was taken. Connection: " << this;
    return true;
}

bool
MessageConnection::unlock()
{
    if (!connection_lock) return false;
    connection_lock = false;
    dbgTrace(D_COMMUNICATION) << "The connection lock was released. Connection: " << *this;
    return true;
}

// LCOV_EXCL_START Reason: No proxy for ut
bool
MessageConnection::shouldIgnoreSslValidation() const
{
    if(is_ssl_ignore_validation) {
        dbgTrace(D_COMMUNICATION) << "Ignoring SSL validation";
        return true;
    }

    bool ignore_ssl_validation = getProfileAgentSettingWithDefault<bool>(
        false,
        "agent.config.message.ignoreSslValidation");

    if (ignore_ssl_validation) {
        dbgTrace(D_COMMUNICATION)
            << "ignoreSslValidation: "
            << (ignore_ssl_validation ? "true, Ignoring ssl validation of the current connection" : "false");
    }

    return ignore_ssl_validation;
}
// LCOV_EXCL_START Reason: No proxy for ut

bool
MessageConnection::verifyCert()
{
    dbgFlow(D_COMMUNICATION);
    BioUniquePtr<X509> cert = BioUniquePtr<X509>(SSL_get_peer_certificate(ssl_socket));
    // In this case cert returned null from SSL_get_peer_certificate

    if (shouldIgnoreSslValidation()) return true;

    if (cert.get() == nullptr) {
        dbgWarning(D_COMMUNICATION) << "Server did not provide a certificate during handshake";
        return false;
    }
    // Verify the result of chain verification
    int res = SSL_get_verify_result(ssl_socket);
    if (res != X509_V_OK) {
        dbgWarning(D_COMMUNICATION)
            << "Failed to verify server certificate. OpenSSL error: "
            << string(ERR_error_string(res, nullptr))
            << ", OpenSSL error code: " << res;
        return false;
    }

    auto verify_pining_required = getConfigurationWithDefault<bool>(false, "message", "Verify SSL pinning");
    if (verify_pining_required && !verifyCertPinning(cert)) {
        dbgWarning(D_COMMUNICATION) << "Couldn't verify server public certificate (pinning)";
        return false;
    }

    return true;
}

Maybe<string>
MessageConnection::calculatePublicKey(const BioUniquePtr<X509> &cert) const
{
    if (cert.get() == nullptr)  return genError("Certificate is null");

    BioUniquePtr<BIO> outbio = BioUniquePtr<BIO>(BIO_new(BIO_s_mem()));
    BioUniquePtr<EVP_PKEY> pkey = BioUniquePtr<EVP_PKEY>(X509_get_pubkey(cert.get()));

    if (pkey.get() == nullptr) {
        return genError("Error getting public key from certificate");
    }
    if(!PEM_write_bio_PUBKEY(outbio.get(), pkey.get())) {
        return genError("Error writing public key data in PEM format");
    }

    char *buf;
    size_t len = BIO_get_mem_data(outbio.get(), &buf);
    dbgTrace(D_COMMUNICATION) << "Provide public key has been loaded";
    return move(string(buf, len));
}

Maybe<string>
MessageConnection::getPinnedCertificate()
{
    if (!pinned_cert_pub_key.empty()) return pinned_cert_pub_key;

    filesystem_prefix = getFilesystemPathConfig();
    dbgTrace(D_COMMUNICATION) << "MessageConnection, file systen prefix: " << filesystem_prefix << endl;
    string public_key_path =
        getConfigurationWithDefault<string>(
            filesystem_prefix + "/certs/public-key.pem",
            "message",
            "Public key path"
        );
    dbgTrace(D_COMMUNICATION) << "Load public key path. Path: " << public_key_path;
    ifstream pinned_public_file(public_key_path);
    if (!pinned_public_file.is_open()) {
        return genError("Failed to open pinned public key file");
    }
    stringstream pinned_public_key_steam;
    pinned_public_key_steam << pinned_public_file.rdbuf();
    pinned_cert_pub_key = pinned_public_key_steam.str();

    dbgTrace(D_COMMUNICATION) << "Pinned public key has been loaded";
    return pinned_cert_pub_key;
}

bool
MessageConnection::verifyCertPinning(const BioUniquePtr<X509> &cert)
{
    dbgFlow(D_COMMUNICATION);

    if (cert.get() == nullptr) {
        dbgWarning(D_COMMUNICATION) << "Certificate is missing";
        return false;
    }

    auto public_key = calculatePublicKey(cert);
    if (!public_key.ok()) {
        dbgWarning(D_COMMUNICATION) << "The provided public key is not valid. Error: " << public_key.getErr();
        return false;
    }

    auto pinned_key = getPinnedCertificate();
    if (!pinned_key.ok()) {
        dbgWarning(D_COMMUNICATION) << "The pinned public key is not valid. Error: " << pinned_key.getErr();
        return false;
    }

    if(public_key.unpackMove().compare(pinned_key.unpack()) != 0) {
        dbgWarning(D_COMMUNICATION) << "The provided public key and the pinned public key are diffrent";
        return false;
    }

    dbgTrace(D_COMMUNICATION) << "The provided public key is valid";
    return true;
}

Maybe<void>
MessageConnection::doHandshake(const BioUniquePtr<BIO> &bio)
{
    auto timeout = chrono::microseconds(
        getConfigurationWithDefault<uint>(500000, "message", "Connection handshake timeout")
    );
    auto end_time = timer->getMonotonicTime() + timeout;
    while (timer->getMonotonicTime() < end_time) {
        if (!isBioSocketReady()) {
            dbgDebug(D_COMMUNICATION) << "Socket is not ready for use.";
            if (mainloop != nullptr) mainloop->yield(true);
            continue;
        }
        if (BIO_do_handshake(bio.get()) > 0 || shouldIgnoreSslValidation()) {
            return Maybe<void>();
        }
        if (!BIO_should_retry(bio.get())) {
            unsigned long ssl_err = ERR_get_error();
            return genError(
                "Failed to obtain a successful SSL handshake. OpenSSL error: "
                    + string(ERR_error_string(ssl_err, nullptr))
                    + ", OpenSSL error code: "
                    + to_string(ssl_err)
            );
        }
    }
    return genError("SSL handshake timed out");
}

bool
MessageConnection::setCnVerification()
{
    SSL_set_hostflags(ssl_socket, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    return SSL_set1_host(ssl_socket, host.c_str()) != 0;
}

bool
MessageConnection::encrypt()
{
    if (ssl_ctx.get() == nullptr) {
        dbgWarning(D_COMMUNICATION) << "SSL context does not exist";
        return false;
    }

    BioUniquePtr<BIO> s_bio = BioUniquePtr<BIO>(BIO_new_ssl(ssl_ctx.get(), 1));
    if (s_bio.get() == nullptr) {
        dbgWarning(D_COMMUNICATION) << "Failed to create encrypted BIO socket";
        return false;
    }

    bio = BioUniquePtr<BIO>(BIO_push(s_bio.release(), bio.release()));
    BIO_get_ssl(bio.get(), &ssl_socket);
    if (!ssl_socket) {
        dbgWarning(D_COMMUNICATION) << "Failed to locate SSL pointer";
        return false;
    }

    if (!setCnVerification()) {
        dbgWarning(D_COMMUNICATION) << "Failed to set host name (CN) verification";
        return false;
    }

    auto handshake_result = doHandshake(bio);
    if (!handshake_result.ok()) {
        dbgWarning(D_COMMUNICATION) << handshake_result.getErr();
        return false;
    }

    if (!verifyCert()) {
        dbgWarning(D_COMMUNICATION) << "Failed to verify the certificate";
        return false;
    }

    dbgTrace(D_COMMUNICATION) << "Successfully secured BIO socket for connection " << *this;
    return true;
}
// LCOV_EXCL_STOP

bool
MessageConnection::setSocket()
{
    auto is_secure_conn = (is_secure && !over_proxy);
    bio =  is_secure_conn ?
        BioUniquePtr<BIO>(BIO_new_ssl_connect(ssl_ctx.get())) :
        BioUniquePtr<BIO>(BIO_new(BIO_s_connect()));

    if (!bio.get()) {
        dbgWarning(D_COMMUNICATION)
            << "Failed to create new "
            << (is_secure_conn ? "secure" : "clear")
            << " BIO connection";
        return false;
    }

    if (is_secure_conn) {
        BIO_get_ssl(bio.get(), &ssl_socket);
        if (!ssl_socket) {
            dbgWarning(D_COMMUNICATION) << "Failed to locate SSL pointer";
            return false;
        }

        SSL_set_mode(ssl_socket, SSL_MODE_AUTO_RETRY);
        if (!setCnVerification()) {
            dbgWarning(D_COMMUNICATION) << "Failed to set host name (CN) verification";
            return false;
        }
        if (!SSL_set_tlsext_host_name(ssl_socket, host.c_str())) {
            dbgWarning(D_COMMUNICATION) << "Failed to set TLS host name extension (SNI)";
            return false;
        }
    }

    return true;
}

bool
MessageConnection::isBioSocketReady() const
{
    auto fd = BIO_get_fd(bio.get(), nullptr);

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    struct timeval tv = { 0, 0 };

    return select(fd + 1, nullptr, &rfds, nullptr, &tv) == 1;
}


bool
MessageConnection::connect(const string &host, const string &overwrite_port)
{
    string address = host + ":" + overwrite_port;
    BIO_set_conn_hostname(bio.get(), address.c_str());
    BIO_set_nbio(bio.get(), 1);

    auto timer = Singleton::Consume<I_TimeGet>::by<ProtoMessageComp>();
    auto conn_timeout = chrono::microseconds(getConnectionTimeout());
    auto end_time = timer->getMonotonicTime() + conn_timeout;
    int counter = 0;

    while (timer->getMonotonicTime() < end_time) {
        counter++;
        if (BIO_do_connect(bio.get()) > 0) {
            dbgDebug(D_COMMUNICATION)
                << "Successfully established new BIO connection. "
                << "Number of attempts: "
                << counter;
            if (is_secure && !over_proxy) {
                auto handshake_result = doHandshake(bio);
                if (!handshake_result.ok()) {
                    dbgWarning(D_COMMUNICATION) << handshake_result.getErr();
                    return false;
                }
                return verifyCert();
            }
            return true;
        }

        if (!BIO_should_retry(bio.get())) {
            int bio_err = ERR_get_error();
            dbgWarning(D_COMMUNICATION)
                << "Failed completely to establish new BIO connection (BIO won't retry!)."
                << "trying next address. OpenSSL error: "
                << string(ERR_error_string(bio_err, nullptr))
                << ", OpenSSL error code: " << bio_err
                << ", Number of attempts: "
                << counter;
            return false;
        }

        if (mainloop != nullptr && (counter % 10) == 0) mainloop->yield(true);
    }
    dbgWarning(D_COMMUNICATION)
        << "Failed to establish new connection after reaching timeout. "
        << "address: "
        << address
        << ", Number of attempts: "
        << counter;
    return false;
}

template<class T>
Maybe<T>
MessageConnection::receiveResponse(I_MessageDecoder<T> &decoder)
{
    auto end_time =
        timer->getMonotonicTime() + chrono::microseconds(getConnectionTimeout());
    uint counter = 0;
    char buf[1000];
    while (timer->getMonotonicTime() < end_time) {
        if (!isBioSocketReady()) {
            dbgDebug(D_COMMUNICATION) << "Socket is not ready for use.";
            if (mainloop != nullptr) mainloop->yield(true);
            continue;
        }
        int len_or_error_ret_val = BIO_read(bio.get(), buf, sizeof(buf) - 1);
        if (len_or_error_ret_val <= 0) {
            if (!BIO_should_retry(bio.get())) {
                if (len_or_error_ret_val == 0) {
                    if (connection_closed_count == 1) {
                        dbgWarning(D_COMMUNICATION)
                            << "Connection closed. Type: "
                            << tagToString(tag)
                            << ", Count: "
                            << connection_closed_count;
                    } else {
                        dbgDebug(D_COMMUNICATION)
                            << "Connection closed. Type: "
                            << tagToString(tag)
                            << ", Count: "
                            << connection_closed_count;
                    }
                    auto maybe_message = decoder.decodeBytes(string());
                    if (maybe_message.ok()) {
                        return maybe_message.unpackMove();
                    }
                }

                if (connection_closed_count == 1) {
                    dbgWarning(D_COMMUNICATION)
                        << "Failed to read data from BIO socket. Type: "
                        << tagToString(tag)
                        << ", Count: "
                        << connection_closed_count
                        << ", Error code: "
                        << len_or_error_ret_val;
                } else {
                    dbgDebug(D_COMMUNICATION)
                        << "Failed to read data from BIO socket. Type: "
                        << tagToString(tag)
                        << ", Count: "
                        << connection_closed_count
                        << ", Error code: "
                        << len_or_error_ret_val;
                }

                connection_closed_count++;

                return genError("Error reading from BIO socket");
            }
            if (mainloop != nullptr) mainloop->yield(true);
            continue;
        }

        if (connection_closed_count > 0) {
            dbgTrace(D_COMMUNICATION)
                << "Connection was reconnected. Type: "
                << tagToString(tag)
                << ",  number of attempts: "
                << connection_closed_count;
            connection_closed_count = 0;
        }

        string data = string(buf, len_or_error_ret_val);
        dbgTrace(D_HTTP_REQUEST) << "Received the following data:\n" << data;

        auto maybe_message = decoder.decodeBytes(data);
        if (maybe_message.ok()) {
            return maybe_message.unpackMove();
        }

        if (mainloop != nullptr && (counter++ % 5) == 0) mainloop->yield(true);
    }

    dbgWarning(D_COMMUNICATION) << "Failed to receive data after reaching timeout";
    return genError("Reading took too long");
}

Maybe<MessageConnection>
MessageConnection::startNewConnection(
    const string &host,
    const uint16_t port_num,
    const bool is_secure,
    MessageTypeTag tag,
    const bool over_proxy,
    bool is_external,
    bool is_ssl_ignore_validation
)
{
    MessageConnection conn = MessageConnection(
        host,
        port_num,
        is_secure,
        over_proxy,
        is_external,
        tag,
        is_ssl_ignore_validation
    );
    Maybe<void> conn_res = conn.establishConnection();
    if (!conn_res.ok()) return conn_res.passErr();
    dbgTrace(D_COMMUNICATION) << "Started new connection for tag: " << tagToString(tag);
    return move(conn);
}

MessageConnection::~MessageConnection() {}

bool
MessageConnection::setCtx()
{
    if (!is_secure) return true;

    ssl_ctx = BioUniquePtr<SSL_CTX>(SSL_CTX_new(TLS_client_method()));
    if (ssl_ctx.get() == nullptr) {
        dbgWarning(D_COMMUNICATION) << "Failed to initialize SSL context";
        return false;
    }

    if (shouldIgnoreSslValidation()) return true;

    SSL_CTX_set_verify(ssl_ctx.get(), SSL_VERIFY_PEER, nullptr);

    filesystem_prefix = getFilesystemPathConfig();
    dbgTrace(D_COMMUNICATION) << "MessageConnection, file systen prefix: " << filesystem_prefix << endl;
    string cert_file_path = getConfigurationWithDefault<string>(
        filesystem_prefix + "/certs/fog.pem",
        "message",
        "Certificate chain file path"
    );

    string openssl_dir = "/usr/lib/ssl/certs/";
    auto openssl_dir_maybe = Singleton::Consume<I_AgentDetails>::by<ProtoMessageComp>()->getOpenSSLDir();
    if (openssl_dir_maybe.ok()) openssl_dir = openssl_dir_maybe.unpack();

    auto trusted_ca_directory = getConfigurationWithDefault<string>(
        openssl_dir,
        "message",
        "Trusted CA directory"
    );
    const char *ca_dir_path = nullptr;
    if (!trusted_ca_directory.empty()) {
        ca_dir_path = trusted_ca_directory.c_str();
    }

    if (SSL_CTX_load_verify_locations(ssl_ctx.get(), cert_file_path.c_str(), ca_dir_path) == 1) {
        return true;
    }

    dbgWarning(D_COMMUNICATION) << "Failed to load fog's certificate file. Path: " << cert_file_path;

    return false;
}

bool
MessageConnection::isReady() const
{
    dbgFlow(D_COMMUNICATION);
    if (!bio.get()) {
        dbgTrace(D_COMMUNICATION) << "Bio is uninitialized";
        return false;
    }

    if (!is_secure) return true;

    if (!ssl_socket) {
        dbgTrace(D_COMMUNICATION) << "SSL socket is uninitialized";
        return false;
    }

    if (!ssl_ctx.get()) {
        dbgTrace(D_COMMUNICATION) << "SSL context is uninitialized";
        return false;
    }

    return true;
}

string
MessageConnection::printData(const string &data)
{
    auto type = getConfigurationWithDefault<string>("chopped", "message", "Data printout type");
    if (type == "chopped") return data.substr(0, 10) + (data.size() > 10 ? " ..." : "");
    if (type == "full") return data;
    if (type == "size") return to_string(data.size()) + " bytes";
    if (type == "none") return "";

    dbgWarning(D_COMMUNICATION) << "Unknown data printout option '" << type << "' - going with 'chopped' instead.";
    return data.substr(0, 10) + (data.size() > 10 ? " ..." : "");
}

uint
MessageConnection::getConnectionTimeout()
{
    I_Environment *environment = Singleton::Consume<I_Environment>::by<ProtoMessageComp>();
    auto tmo_override = environment->get<uint>("Connection timeout Override");
    uint conf_tmo =
        tmo_override.ok() ?
            *tmo_override :
            getConfigurationWithDefault<uint>(2000000, "message", "Connection timeout");

    uint profile_setting_tmo = getProfileAgentSettingWithDefault<uint>(
        conf_tmo,
        "agent.config.message.connectionTimeout"
    );

    auto executable = environment->get<string>("Service Name");
    auto nano_service_name_tmo = getProfileAgentSetting<string>("agent.config.message.connectionTimeoutServiceName");
    if (!nano_service_name_tmo.ok() || !executable.ok()) {
        dbgTrace(D_COMMUNICATION)
            << "Could not identify service name. Executable env state: "
            << (executable.ok() ? "true" : "false")
            << ", state of nano service name from settings: "
            << (nano_service_name_tmo.ok() ? "true" : "false")
            << ", timeout value to use: "
            << conf_tmo;
        return conf_tmo;
    }
    if (*nano_service_name_tmo == *executable) {
        dbgTrace(D_COMMUNICATION)
            << "Using profile setting for specific nano service. "
            << " nano service name: "
            << *nano_service_name_tmo
            << ", timeout value used: "
            << profile_setting_tmo;
        return profile_setting_tmo;
    }

    dbgTrace(D_COMMUNICATION)
        << "Using non profile config setting for nano service. "
        << " profile configuration for nano service name: "
        << *nano_service_name_tmo
        << ", actual service name: "
        << *executable
        << ", timeout value used: "
        << conf_tmo;
    return conf_tmo;
}

bool
MessageConnection::sendData(const string &data) const
{
    dbgTrace(D_HTTP_REQUEST) << "Sending the following data " << *this << ":\n" << printData(data);

    auto end_time = timer->getMonotonicTime() + chrono::microseconds(getConnectionTimeout());

    uint counter = 0;
    int remaining_data_len = data.length();
    while (timer->getMonotonicTime() < end_time) {
        int offset = data.length() - remaining_data_len;
        if (!isBioSocketReady()) {
            dbgDebug(D_COMMUNICATION) << "Socket is not ready for use.";
            if (mainloop != nullptr) mainloop->yield(true);
            continue;
        }
        int data_sent_len = BIO_write(bio.get(), data.c_str() + offset, remaining_data_len);
        if (data_sent_len > 0) {
            if (remaining_data_len - data_sent_len < 0) {
                dbgWarning(D_COMMUNICATION)
                    << "Sent data length exceeded actual data length ("
                    << to_string(data_sent_len)
                    << " > "
                    << to_string(remaining_data_len)
                    << ")";

                return false;
            }

            dbgTrace(D_COMMUNICATION)
                << "Successfully sent "
                << to_string(data_sent_len)
                << " bytes of data out of total "
                << to_string(data.length())
                << " bytes.";

            remaining_data_len -= data_sent_len;
            if (remaining_data_len == 0) return true;
            if (mainloop != nullptr && (counter++ % 5) == 0) mainloop->yield(true);
            continue;
        }

        if(!BIO_should_retry(bio.get())) {
            dbgWarning(D_COMMUNICATION) << "Failed to Write data into BIO socket. Error code: " << data_sent_len;
            return false;
        }
        dbgTrace(D_COMMUNICATION) << "Temporarily cannot send data. Will retry.";
        if (mainloop != nullptr) mainloop->yield(true);
    }

    dbgWarning(D_COMMUNICATION) << "Failed to send data after reaching timeout";
    return false;
}

ostream &
MessageConnection::print(ostream &os) const
{
    os << "<" << host << ":" << port_num << " over " << (is_secure? "secure" : "clear") << " socket>";
    return os;
}

ostream & operator<<(ostream &os, const MessageConnection &conn) { return conn.print(os); }


void
MessageConnection::getIpFromHostname(const string &hostname)
{
    struct addrinfo *servinfo = nullptr;
    auto __scope_exit = make_scope_exit([&servinfo] () { if (servinfo) freeaddrinfo(servinfo); });

    struct addrinfo hints;
    memset (&hints, 0, sizeof (hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;
    hints.ai_protocol = IPPROTO_TCP;
    vector<string> res;
    if (IPAddr::isValidIPAddr(hostname)) {
        dbgDebug(D_COMMUNICATION) << "Provided host name is already an IP address. Host: " << hostname;
        current_ips.clear();
        current_ips.push_back(hostname);
        return;
    }

    if (getaddrinfo(hostname.c_str(), nullptr, &hints, &servinfo) != 0) {
        dbgWarning(D_COMMUNICATION) << "IP address was not found for the given host name. Host: " << hostname;
        return;
    }

    for(struct addrinfo *addr_iter = servinfo; addr_iter != nullptr; addr_iter = addr_iter->ai_next) {
        char buf[INET6_ADDRSTRLEN];
        const char *formatted_addr;

        if (addr_iter->ai_addr->sa_family == AF_INET) {
            struct in_addr addr = reinterpret_cast<struct sockaddr_in *>(addr_iter->ai_addr)->sin_addr;
            formatted_addr = inet_ntop(AF_INET, &addr, buf, sizeof(buf));
        } else if (addr_iter->ai_addr->sa_family == AF_INET6) {
            struct in6_addr addr = reinterpret_cast<struct sockaddr_in6 *>(addr_iter->ai_addr)->sin6_addr;
            formatted_addr = inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
        } else {
            continue;
        }

        res.push_back(string(formatted_addr));
        dbgDebug(D_COMMUNICATION)
            << "Successfully resolved host name to IP address. Host: "
            << hostname
            << ", IP: "
            << res.back();
    }

    if (res.empty()) {
        dbgWarning(D_COMMUNICATION) << "No IPv4 / IPv6 addresses were found for the given host. Host: " << hostname;
        return;
    }

    current_ips = res;
    return;
}

Maybe<void>
MessageConnection::establishConnection()
{
    if (!setCtx()) return genError("Failed to initialize SSL context");
    dbgDebug(D_COMMUNICATION) << "Succesfully initialized SSL context";

    if (!setSocket()) return genError("Failed to create new socket");
    dbgDebug(D_COMMUNICATION) << "Succesfully created new socket";

    string conn_host = over_proxy ? proxy_host : host;
    string conn_port = over_proxy ? to_string(proxy_port) : to_string(port_num);

    getIpFromHostname(conn_host);
    Maybe<void> is_connected = genError("Failed to establish new connection with: " + conn_host + ":" + conn_port);

    for (const string &address : current_ips) {
        if (is_connected.ok()) break;
        dbgDebug(D_COMMUNICATION) << "Trying to connect to " << address << ":" << conn_port;
        if (!connect(address, conn_port)) {
            dbgWarning(D_COMMUNICATION) << "Failed to connect " << address << ":" << conn_port;
            continue;
        }
        is_connected = (over_proxy && is_secure) ? establishConnectionOverProxy() : Maybe<void>();
        if (!is_connected.ok()) {
            dbgWarning(D_COMMUNICATION) << "Failed to connect " << address << ":" << conn_port;
            continue;
        }

        dbgDebug(D_COMMUNICATION) << "Successfully connected to " << address << ":" << conn_port;
    }
    return is_connected;
}

// LCOV_EXCL_START Reason: No proxy for ut
Maybe<void>
MessageConnection::establishConnectionOverProxy()
{
    HTTPEncoder http_encoder(host, to_string(port_num));
    HTTPRequest req = http_encoder.Connect();
    if (!proxy_auth.empty()) req.insertHeader("Proxy-Authorization", "Basic " +  encryptor->base64Encode(proxy_auth));
    waitForQueue();
    auto release_queue_on_exit = make_scope_exit([this] () { releaseQueue(); });
    if (!sendData(req.toString())) {
        return genError("Failed to send CONNECT request to proxy");
    }

    HTTPDecoder http_decoder(I_Messaging::Method::CONNECT);
    Maybe<HTTPResponse> response = receiveResponse(http_decoder);
    if (!response.ok()) {
        return genError("Failed to receive a response from proxy");
    }

    auto response_data = response->getResponse();
    if (!response_data.ok()) {
        return genError("Failed to connect via proxy");
    }

    if (!encrypt()) {
        return genError("Failed to encrypt the socket after the CONNECT request");
    }
    return Maybe<void>();
}
// LCOV_EXCL_STOP

Maybe<void>
MessageConnection::reconnect(bool should_lock)
{
    if (should_lock) {
        while (!lock()) { mainloop->yield(true); }
    }

    auto res = establishConnection();
    if (should_lock) {
        unlock();
    }
    return res;
}

void
MessageConnection::waitForQueue()
{
    dbgTrace(D_COMMUNICATION) << "Pending queue position";
    while (available_messaging_queue_pos == UINT64_MAX) {
        mainloop->yield(true);
    }

    uint64_t messaging_queue_pos = available_messaging_queue_pos++;
    dbgTrace(D_COMMUNICATION) << "Received an available queue position: " << messaging_queue_pos;
    metrics_current_size++;

    MessageQueueEvent queue_event;
    queue_event.setMessageQueueSize(metrics_current_size);
    queue_event.notify();

    while (messaging_queue_pos != current_messaging_queue_pos) {
        mainloop->yield(true);
    }

    dbgTrace(D_COMMUNICATION) << "Reached the current queue position: " << messaging_queue_pos;
    return;
}

void
MessageConnection::releaseQueue()
{
    dbgTrace(D_COMMUNICATION) << "Released the queue position " << current_messaging_queue_pos;

    current_messaging_queue_pos++;
    if (current_messaging_queue_pos == UINT64_MAX) {
        current_messaging_queue_pos = 0;
        available_messaging_queue_pos = 0;
    }
    metrics_current_size--;
    dbgTrace(D_COMMUNICATION) << "Queue position was advanced";
}

ProtoMessageComp::ProtoMessageComp() : Component("ProtoMessageComp"), pimpl(make_unique<Impl>()) {}
ProtoMessageComp::~ProtoMessageComp() {}

void ProtoMessageComp::init() { pimpl->init(); }
void ProtoMessageComp::fini() { pimpl->fini(); }

void
ProtoMessageComp::preload()
{
    registerExpectedConfiguration<int>("message",      "Cache timeout");
    registerExpectedConfiguration<uint>("message",     "Connection timeout");
    registerExpectedConfiguration<uint>("message",     "send event retry in sec");
    registerExpectedConfiguration<bool>("message",     "Reuse connection");
    registerExpectedConfiguration<bool>("message",     "Verify SSL pinning");
    registerExpectedConfiguration<bool>("message",     "Buffer Failed Requests");
    registerExpectedConfiguration<string>("message",   "Certificate chain file path");
    registerExpectedConfiguration<string>("message",   "Trusted CA directory");
    registerExpectedConfiguration<string>("message",   "Public key path");
    registerExpectedConfiguration<string>("message",   "Metrics Routine Interval");
    registerExpectedConfiguration<string>("message",   "Data printout type");
    registerExpectedConfiguration<uint32_t>("message", "Internal Fog error timeout");
}
