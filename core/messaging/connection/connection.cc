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

#include "time_print.h"
#include "connection.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <fstream>
#include <sstream>
#include <string>

#include "config.h"
#include "http_request.h"
#include "maybe_res.h"
#include "messaging.h"
#include "response_parser.h"
#include "scope_exit.h"
#include "smart_bio.h"

using namespace std;
using namespace smartBIO;

USE_DEBUG_FLAG(D_CONNECTION);

static const HTTPResponse sending_timeout(HTTPStatusCode::HTTP_UNKNOWN, "Failed to send all data in time");
static const HTTPResponse receving_timeout(HTTPStatusCode::HTTP_UNKNOWN, "Failed to receive all data in time");
static const HTTPResponse parsing_error(HTTPStatusCode::HTTP_UNKNOWN, "Failed to parse the HTTP response");
static const HTTPResponse close_error(
    HTTPStatusCode::HTTP_UNKNOWN,
    "The previous request failed to receive a response. Closing the connection"
);

const string &
MessageConnectionKey::getHostName() const
{
    return host_name;
}

uint16_t
MessageConnectionKey::getPort() const
{
    return port;
}

const MessageCategory &
MessageConnectionKey::getCategory() const
{
    return category;
}

bool
MessageConnectionKey::operator<(const MessageConnectionKey &other) const
{
    if (host_name != other.host_name) return host_name < other.host_name;
    if (port != other.port) return port < other.port;
    return category < other.category;
}

enum class ConnectionFlags
{
    UNSECURE,
    ONE_TIME,
    IGNORE_SSL_VALIDATION,
    PROXY,

    COUNT
};

class Connection::Impl
{
public:
    Impl(const MessageConnectionKey &_key, const MessageMetadata &metadata) : key(_key)
    {
        auto metadata_flags = metadata.getConnectionFlags();
        if (metadata_flags.isSet(MessageConnectionConfig::UNSECURE_CONN)) flags.setFlag(ConnectionFlags::UNSECURE);
        if (metadata_flags.isSet(MessageConnectionConfig::ONE_TIME_CONN)) flags.setFlag(ConnectionFlags::ONE_TIME);
        if (metadata_flags.isSet(MessageConnectionConfig::IGNORE_SSL_VALIDATION)) {
            flags.setFlag(ConnectionFlags::IGNORE_SSL_VALIDATION);
        }
    }

    void
    setProxySettings(const MessageProxySettings &_settings)
    {
        flags.setFlag(ConnectionFlags::PROXY);
        settings = _settings;
    }

    void
    setConnectMessage(const string &connect_msg)
    {
        connect_message = connect_msg;
    }

    void
    setExternalCertificate(const string &_certificate)
    {
        certificate = _certificate;
    }

    const MessageProxySettings &
    getProxySettings() const
    {
        return settings;
    }

    const string &
    getExternalCertificate() const
    {
        return certificate;
    }

    const MessageConnectionKey &
    getConnKey() const
    {
        return key;
    }

    bool
    shouldCloseConnection() const
    {
        return should_close_connection;
    }

    bool
    isOverProxy() const
    {
        return flags.isSet(ConnectionFlags::PROXY);
    }

    bool
    isUnsecure() const
    {
        return flags.isSet(ConnectionFlags::UNSECURE);
    }

    bool
    isSuspended()
    {
        if (active.ok()) return false;

        I_TimeGet *i_time = Singleton::Consume<I_TimeGet>::by<Messaging>();
        auto curr_time = chrono::duration_cast<chrono::seconds>(i_time->getMonotonicTime());

        if (active.getErr() > curr_time) {
            dbgTrace(D_MESSAGING) << "Connection is suspended for another " << (active.getErr() - curr_time);
            return true;
        }

        if (establishConnection().ok()) {
            dbgDebug(D_MESSAGING) << "Reestablish connection";
            return false;
        }

        dbgWarning(D_MESSAGING) << "Reestablish connection failed";
        active = genError(curr_time + chrono::seconds(300));
        return true;
    }

    Maybe<void>
    establishConnection()
    {
        dbgFlow(D_CONNECTION) << "Establishing a new connection";
        auto set_socket = setSocket();
        if (!set_socket.ok()) {
            dbgWarning(D_CONNECTION) << "Failed to set socket: " << set_socket.getErr();
            return set_socket;
        }

        auto connect = connectToHost();
        if (!connect.ok()) {
            dbgWarning(D_CONNECTION) << "Failed to connect to host: " << connect.getErr();
            return connect;
        }

        if (flags.isSet(ConnectionFlags::PROXY)) {
            dbgDebug(D_CONNECTION) << "Sending a CONNECT request: " << connect_message;
            auto res = sendAndReceiveData(connect_message, true);
            if (!res.ok()) {
                string connect_error = res.getErr().getBody();
                dbgWarning(D_CONNECTION) << "Failed to connect to proxy: " << connect_error;
                return genError(connect_error);
            }

            if (!isUnsecure()) {
                auto encrypt_res = encryptProxyConnection();
                if (!encrypt_res.ok()) {
                    return genError("Failed to encrypt the socket after the CONNECT request" + encrypt_res.getErr());
                }
            }
        }

        dbgDebug(D_CONNECTION)
            << "Successfully connected to "
            << key.getHostName()
            << ':'
            << key.getPort()
            << (isOverProxy() ? ", Over proxy: " + settings.getProxyHost() + ":" + to_string(key.getPort()) : "");
        active = Maybe<void, chrono::seconds>();
        should_close_connection = false;
        return Maybe<void>();
    }

    Maybe<HTTPResponse, HTTPResponse>
    sendRequest(const string &request)
    {
        dbgFlow(D_CONNECTION)
            << "Send request to "
            << key.getHostName()
            << ':'
            << key.getPort()
            << ":\n"
            << printOut(request);

        auto result = sendAndReceiveData(request, false);
        if (!result.ok()) {
            establishConnection();
            result = sendAndReceiveData(request, false);
        }

        if (!result.ok()) {
            ++failed_attempts;
            if (failed_attempts > 10) {
                I_TimeGet *i_time = Singleton::Consume<I_TimeGet>::by<Messaging>();
                auto curr_time = chrono::duration_cast<chrono::seconds>(i_time->getMonotonicTime());
                active = genError(curr_time + chrono::seconds(300));
            }
            return result.passErr();
        }

        failed_attempts = 0;
        return result;
    }

private:
    Maybe<void>
    setSSLContext()
    {
        dbgFlow(D_CONNECTION) << "Setting SSL context";
        if (isUnsecure()) {
            dbgTrace(D_CONNECTION) << "Connection is unsecure. Skipping SSL context creation";
            return Maybe<void>();
        }
        ssl_ctx = BioUniquePtr<SSL_CTX>(SSL_CTX_new(TLS_client_method()));
        if (!ssl_ctx.get()) return genError("Failed to initialize SSL context");
        if (shouldIgnoreSslValidation()) {
            dbgTrace(D_CONNECTION) << "Ignoring SSL validation";
            return Maybe<void>();
        }

        SSL_CTX_set_verify(ssl_ctx.get(), SSL_VERIFY_PEER, nullptr);

        auto defualt_cert_path = getFilesystemPathConfig() + "/certs/fog.pem";
        auto cert_path = getConfigurationWithDefault(defualt_cert_path, "message", "Certificate chain file path");
        const char *cert = cert_path.c_str();

        auto details_ssl_dir = Singleton::Consume<I_AgentDetails>::by<Messaging>()->getOpenSSLDir();
        auto openssl_dir = details_ssl_dir.ok() ? *details_ssl_dir : "/usr/lib/ssl/certs/";
        auto configured_ssl_dir = getConfigurationWithDefault(openssl_dir, "message", "Trusted CA directory");
        const char *ca_dir = configured_ssl_dir.empty() ? nullptr : configured_ssl_dir.c_str();

        if (SSL_CTX_load_verify_locations(ssl_ctx.get(), cert, ca_dir) != 1) {
            return genError("Failed to load certificate locations");
        }

        dbgDebug(D_CONNECTION) << "SSL context set successfully. Certificate: " << cert << ", CA dir: " << ca_dir;
        return Maybe<void>();
    }

    Maybe<void>
    setSocket()
    {
        dbgFlow(D_CONNECTION) << "Setting socket";
        if (isUnsecure()) {
            bio = BioUniquePtr<BIO>(BIO_new(BIO_s_connect()));
            if (!bio.get()) return genError("Failed to create new BIO connection");
            return Maybe<void>();
        }

        auto build_ssl = setSSLContext();
        if (!build_ssl.ok()) return build_ssl;

        if (isOverProxy()) {
            bio = BioUniquePtr<BIO>(BIO_new(BIO_s_connect()));
            if (!bio.get()) return genError("Failed to create new BIO connection");
            return Maybe<void>();
        }

        bio = BioUniquePtr<BIO>(BIO_new_ssl_connect(ssl_ctx.get()));
        BIO_get_ssl(bio.get(), &ssl_socket);
        if (!ssl_socket) return genError("Failed to locate SSL pointer");

        SSL_set_mode(ssl_socket, SSL_MODE_AUTO_RETRY);
        SSL_set_hostflags(ssl_socket, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

        auto host = key.getHostName().c_str();
        if (!SSL_set1_host(ssl_socket, host)) {
            return genError("Failed to set host name verification. Host: " + string(host));
        }
        if (!SSL_set_tlsext_host_name(ssl_socket, host)) {
            return genError("Failed to set TLS host name extension. Host: " + string(host));
        }

        return Maybe<void>();
    }

    static chrono::microseconds
    getConnectionTimeout()
    {
        I_Environment *env = Singleton::Consume<I_Environment>::by<Messaging>();

        auto executable = env->get<string>("Service Name");
        auto service_name = getProfileAgentSetting<string>("agent.config.message.connectionTimeoutServiceName");

        if (executable.ok() && service_name.ok() && *executable == *service_name) {
            auto service_timeout = getProfileAgentSetting<uint>("agent.config.message.connectionTimeout");
            if (service_timeout.ok()) return chrono::microseconds(*service_timeout);
        }

        auto env_timeout = env->get<uint>("Connection timeout Override");
        if (env_timeout.ok()) return chrono::microseconds(*env_timeout);

        return chrono::microseconds(getConfigurationWithDefault<uint>(10000000, "message", "Connection timeout"));
    }

    bool
    shouldIgnoreSslValidation() const
    {
        if (flags.isSet(ConnectionFlags::UNSECURE)) return true;
        if (flags.isSet(ConnectionFlags::IGNORE_SSL_VALIDATION)) return true;
        return getProfileAgentSettingWithDefault<bool>(false, "agent.config.message.ignoreSslValidation");
    }

    bool
    isBioSocketReady() const
    {
        if (!bio.get()) return false;

        auto fd = BIO_get_fd(bio.get(), nullptr);
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        struct timeval tv = { 0, 0 };

        return select(fd + 1, nullptr, &rfds, nullptr, &tv) == 1;
    }

// LCOV_EXCL_START Reason: No ssl ut
    Maybe<void>
    verifyCertPinning(const BioUniquePtr<X509> &cert) const
    {
        BioUniquePtr<BIO> outbio = BioUniquePtr<BIO>(BIO_new(BIO_s_mem()));
        if (!outbio.get()) return genError("Failed to allocate new BIO");
        BioUniquePtr<EVP_PKEY> pkey = BioUniquePtr<EVP_PKEY>(X509_get_pubkey(cert.get()));
        if (!pkey.get()) return genError("Error getting public key from certificate");

        if (!PEM_write_bio_PUBKEY(outbio.get(), pkey.get())) return genError("Error writing key in PEM format");

        char *buf;
        auto len = BIO_get_mem_data(outbio.get(), &buf);
        string recieved_public_key(buf, len);
        dbgTrace(D_CONNECTION) << "Received public key " << recieved_public_key;

        auto defualt_key_path = getFilesystemPathConfig() + "/certs/public-key.pem";
        auto key_path = getConfigurationWithDefault(defualt_key_path, "message", "Public key path");
        dbgTrace(D_CONNECTION) << "Load public key path. Path: " << key_path;

        ifstream pinned_public_file(key_path);
        if (!pinned_public_file.is_open()) return genError("Failed to open pinned public key file");

        stringstream pinned_key;
        pinned_key << pinned_public_file.rdbuf();
        dbgTrace(D_CONNECTION) << "Saved public key: " << pinned_key.str();

        if (recieved_public_key != pinned_key.str()) return genError("Received and pinned keys don't match");

        return Maybe<void>();
    }

    Maybe<void>
    verifyCert()
    {
        dbgFlow(D_CONNECTION) << "Verifying certificate";

        if (shouldIgnoreSslValidation()) {
            dbgTrace(D_CONNECTION) << "Ignoring SSL validation";
            return Maybe<void>();
        }

        BioUniquePtr<X509> cert = BioUniquePtr<X509>(SSL_get_peer_certificate(ssl_socket));
        if (!cert.get() || cert.get() == nullptr) return genError("Server did not provide a cert during handshake");

        if (SSL_get_verify_result(ssl_socket) != X509_V_OK) {
            string error = ERR_error_string(ERR_get_error(), nullptr);
            return genError("Failed to verify server certificate. OpenSSL error: " + error);
        }

        if (!getConfigurationWithDefault<bool>(false, "message", "Verify SSL pinning")) return Maybe<void>();

        return verifyCertPinning(cert);
    }

    Maybe<void>
    performHandshakeAndVerifyCert(I_TimeGet *i_time, I_MainLoop *i_mainloop)
    {
        dbgFlow(D_CONNECTION) << "Performing SSL handshake";
        auto handshake_timeout = getConfigurationWithDefault<uint>(500000, "message", "Connection handshake timeout");
        auto handshake_end_time = i_time->getMonotonicTime() + chrono::microseconds(handshake_timeout);

        while (i_time->getMonotonicTime() < handshake_end_time) {
            if (!isBioSocketReady()) {
                dbgTrace(D_CONNECTION) << "Socket is not ready for use.";
                i_mainloop->yield(true);
                continue;
            }

            if (BIO_do_handshake(bio.get()) > 0) return verifyCert();
            if (!BIO_should_retry(bio.get())) {
                string error = ERR_error_string(ERR_get_error(), nullptr);
                return genError("Failed to obtain a successful SSL handshake. OpenSSL error: " + error);
            }
        }

        return genError("SSL handshake reached timed out");
    }
// LCOV_EXCL_STOP

    Maybe<void>
    connectToHost()
    {
        string full_address;
        if (isOverProxy()) {
            full_address = settings.getProxyHost() + ":" + to_string(settings.getProxyPort());
        } else {
            full_address = key.getHostName() + ":" + to_string(key.getPort());
        }

        dbgFlow(D_CONNECTION) << "Connecting to " << full_address;
        BIO_set_conn_hostname(bio.get(), full_address.c_str());
        BIO_set_nbio(bio.get(), 1);

        I_MainLoop *i_mainloop = Singleton::Consume<I_MainLoop>::by<Messaging>();
        I_TimeGet *i_time = Singleton::Consume<I_TimeGet>::by<Messaging>();

        auto bio_connect = BIO_do_connect(bio.get());
        uint attempts_count = 0;
        auto conn_end_time = i_time->getMonotonicTime() + getConnectionTimeout();
        while (i_time->getMonotonicTime() < conn_end_time && bio_connect <= 0) {
            if (!BIO_should_retry(bio.get())) {
                auto curr_time = chrono::duration_cast<chrono::seconds>(i_time->getMonotonicTime());
                active = genError(curr_time + chrono::seconds(60));
                string bio_error = ERR_error_string(ERR_get_error(), nullptr);
                return genError(
                    "Failed to connect to: " +
                    full_address +
                    ", error: " +
                    bio_error +
                    ". Connection suspended for 60 seconds");
            }
            attempts_count++;
            if (!isBioSocketReady()) {
                i_mainloop->yield((attempts_count % 10) == 0);
                continue;
            }
            bio_connect = BIO_do_connect(bio.get());
        }
        if (bio_connect > 0) {
            if (isUnsecure() || isOverProxy()) return Maybe<void>();
            return performHandshakeAndVerifyCert(i_time, i_mainloop);
        }
        auto curr_time = chrono::duration_cast<chrono::seconds>(i_time->getMonotonicTime());
        active = genError(curr_time + chrono::seconds(60));
        return genError(
            "Failed to establish new connection to: " +
            full_address +
            " after reaching timeout." +
            " Connection suspended for 60 seconds");
    }

    Maybe<uint, HTTPResponse>
    sendData(const string &request, size_t data_left_to_send) const
    {
        if (!isBioSocketReady()) return 0;

        dbgTrace(D_MESSAGING) << "Sending request: " << printOut(request);
        size_t offset = request.length() - data_left_to_send;
        auto curr_data_to_send = request.c_str() + offset;
        int data_sent_len = BIO_write(bio.get(), curr_data_to_send, data_left_to_send);

        if (data_sent_len >= 0) {
            dbgTrace(D_CONNECTION) << "Sent " << data_sent_len << " bytes, out of: " << data_left_to_send << " bytes.";
            return data_sent_len;
        }

        if (BIO_should_retry(bio.get())) {
            dbgTrace(D_CONNECTION) << "Failed to send data - retrying";
            return 0;
        }

        char error_buf[256];
        ERR_error_string(ERR_get_error(), error_buf);
        string error = "Failed to write data into BIO socket. Error: " + string(error_buf);
        dbgWarning(D_CONNECTION) << error;
        return genError(HTTPResponse(HTTPStatusCode::HTTP_UNKNOWN, error));
    }

    Maybe<string, HTTPResponse>
    receiveData() const
    {
        if (!isBioSocketReady()) return string();

        char buffer[1000];
        int receive_len = BIO_read(bio.get(), buffer, sizeof(buffer) - 1);

        if (receive_len > 0) {
            dbgTrace(D_CONNECTION) << "Received " << receive_len << " bytes";
            return string(buffer, receive_len);
        }

        if (BIO_should_retry(bio.get())) return string();

        char error_buf[256];
        ERR_error_string(ERR_get_error(), error_buf);
        string error = receive_len == 0 ?
            "Connection closed by peer" :
            "Failed to read data from BIO socket. Error: " + string(error_buf);
        dbgWarning(D_CONNECTION) << error;
        return genError(HTTPResponse(HTTPStatusCode::HTTP_UNKNOWN, error));
    }

// LCOV_EXCL_START Reason: Fix in a future commit
    Maybe<void>
    encryptProxyConnection()
    {
        dbgFlow(D_CONNECTION) << "Encrypting BIO socket";
        if (ssl_ctx.get() == nullptr) return genError("SSL context does not exist");

        BioUniquePtr<BIO> s_bio = BioUniquePtr<BIO>(BIO_new_ssl(ssl_ctx.get(), 1));
        if (s_bio.get() == nullptr) return genError("Failed to create encrypted BIO socket");

        bio = BioUniquePtr<BIO>(BIO_push(s_bio.release(), bio.release()));
        BIO_get_ssl(bio.get(), &ssl_socket);
        if (!ssl_socket) return genError("Failed to locate SSL pointer");

        SSL_set_hostflags(ssl_socket, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        auto host = key.getHostName().c_str();
        if (!SSL_set1_host(ssl_socket, host)) {
            return genError("Failed to set host name verification. Host: " + string(host));
        }

        I_MainLoop *i_mainloop = Singleton::Consume<I_MainLoop>::by<Messaging>();
        I_TimeGet *i_time = Singleton::Consume<I_TimeGet>::by<Messaging>();
        return performHandshakeAndVerifyCert(i_time, i_mainloop);
    }
// LCOV_EXCL_STOP

    Maybe<HTTPResponse, HTTPResponse>
    sendAndReceiveData(const string &request, bool is_connect)
    {
        dbgFlow(D_CONNECTION) << "Sending and receiving data";
        I_MainLoop *i_mainloop = Singleton::Consume<I_MainLoop>::by<Messaging>();
        while (lock) {
            i_mainloop->yield(true);
        }
        lock = true;
        auto unlock = make_scope_exit([&] () { lock = false; });

        if (should_close_connection) {
            dbgWarning(D_CONNECTION) << close_error.getBody();
            return genError(close_error);
        }

        I_TimeGet *i_time = Singleton::Consume<I_TimeGet>::by<Messaging>();
        auto sending_end_time = i_time->getMonotonicTime() + getConnectionTimeout();
        size_t data_left_to_send = request.length();

        while (data_left_to_send > 0) {
            if (i_time->getMonotonicTime() > sending_end_time) return genError(sending_timeout);
            auto send_size = sendData(request, data_left_to_send);
            if (!send_size.ok()) return send_size.passErr();
            data_left_to_send -= *send_size;
            i_mainloop->yield(*send_size == 0); // We want to force waiting if we failed to send the data
        }

        auto receiving_end_time = i_time->getMonotonicTime() + getConnectionTimeout();
        HTTPResponseParser http_parser;
        dbgTrace(D_CONNECTION) << "Sent the message, now waiting for response";
        while (!http_parser.hasReachedError()) {
            if (i_time->getMonotonicTime() > receiving_end_time) {
                should_close_connection = true;
                return genError(receving_timeout);
            };
            auto receieved = receiveData();
            if (!receieved.ok()) {
                should_close_connection = true;
                return receieved.passErr();
            }
            auto response = http_parser.parseData(*receieved, is_connect);
            if (response.ok()) {
                dbgTrace(D_MESSAGING) << printOut(response.unpack().toString());
                return response.unpack();
            }
            i_mainloop->yield(receieved.unpack().empty());
        }
        return genError(parsing_error);
    }

    static string
    printOut(const string &data)
    {
        string type = getConfigurationWithDefault<string>("chopped", "message", "Data printout type");
        uint length = getConfigurationWithDefault<uint>(10, "message", "Data printout length");
        if (type == "full") return data;
        if (type == "size") return to_string(data.size()) + " bytes";
        if (type == "none") return "";
        string chopped_str = data.substr(0, length) + (data.size() > length ? " ..." : "");
        if (type == "chopped") return chopped_str;


        dbgWarning(D_CONNECTION) << "Unknown data printout option '" << type << "' - going with 'chopped' instead.";
        return chopped_str;
    }

    MessageConnectionKey key;
    Flags<ConnectionFlags> flags;

    MessageProxySettings settings;
    string connect_message;
    string certificate;

    smartBIO::BioUniquePtr<BIO> bio = nullptr;
    smartBIO::BioUniquePtr<SSL_CTX> ssl_ctx = nullptr;
    SSL *ssl_socket = nullptr;

    Maybe<void, chrono::seconds> active = genError<chrono::seconds>(0);
    uint failed_attempts = 0;

    bool lock = false;
    bool should_close_connection = false;
};

Connection::Connection(const MessageConnectionKey &key, const MessageMetadata &metadata)
        :
    pimpl(make_shared<Connection::Impl>(key, metadata))
{}

Connection::~Connection()
{}

Maybe<void>
Connection::setProxySettings(const MessageProxySettings &settings)
{
    pimpl->setProxySettings(settings);

    map<string, string> headers;
    auto i_encrypt = Singleton::Consume<I_Encryptor>::by<Messaging>();
    if (!settings.getProxyAuth().empty()) {
        headers["Proxy-Authorization"] = i_encrypt->base64Encode(settings.getProxyAuth());
    }

    auto req = HTTPRequest::prepareRequest(*this, HTTPMethod::CONNECT, "", headers, "");
    if (!req.ok()) return genError("Failed to create connect request. Error: " + req.getErr());

    pimpl->setConnectMessage(req.unpack().toString());
    return Maybe<void>();
}

void
Connection::setExternalCertificate(const string &certificate)
{
    pimpl->setExternalCertificate(certificate);
}

const MessageProxySettings &
Connection::getProxySettings() const
{
    return pimpl->getProxySettings();
}

const string &
Connection::getExternalCertificate() const
{
    return pimpl->getExternalCertificate();
}

const MessageConnectionKey &
Connection::getConnKey() const
{
    return pimpl->getConnKey();
}

bool
Connection::shouldCloseConnection() const
{
    return pimpl->shouldCloseConnection();
}

bool
Connection::isOverProxy() const
{
    return pimpl->isOverProxy();
}

bool
Connection::isUnsecure() const
{
    return pimpl->isUnsecure();
}

bool
Connection::isSuspended()
{
    return pimpl->isSuspended();
}

Maybe<void>
Connection::establishConnection()
{
    return pimpl->establishConnection();
}

Maybe<HTTPResponse, HTTPResponse>
Connection::sendRequest(const string &request)
{
    return pimpl->sendRequest(request);
}
