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

#include "http_client.h"
#include "curl_client.h"

#include "debug.h"
#include "i_agent_details.h"
#include "i_encryptor.h"
#include "downloader.h"
#include "config.h"
#include "boost/uuid/uuid.hpp"
#include "boost/uuid/uuid_generators.hpp"
#include <boost/asio/deadline_timer.hpp>
#include "boost/uuid/uuid_io.hpp"

#include <string>
#include <iostream>
#include <istream>
#include <ostream>
#include <fstream>
#include <boost/asio.hpp>
#include <boost/bind/bind.hpp>
#include <boost/asio/ssl.hpp>
#include <exception>

using namespace boost::placeholders;
using boost::asio::ip::tcp;
using namespace std;

USE_DEBUG_FLAG(D_COMMUNICATION);
USE_DEBUG_FLAG(D_HTTP_REQUEST);
USE_DEBUG_FLAG(D_ORCHESTRATOR);

// LCOV_EXCL_START Reason: Depends on real download server.
class BadResponseFromServer : public exception
{
public:
    BadResponseFromServer() : message("Bad response returned from server") {}
    BadResponseFromServer(const string &msg) : message(msg) {}
    const char *
    what() const throw()
    {
        return message.c_str();
    }

private:
    string message;
};

class Client
{
public:
    Client(
        ofstream &out_file,
        boost::asio::io_service &io_service,
        boost::asio::ssl::context &context,
        const URLParser &_url,
        const Maybe<string> &_proxy_url,
        const Maybe<uint16_t> &_proxy_port,
        const Maybe<string> &_proxy_auth,
        const string &_token)
            :
        out_file(out_file),
        url(_url),
        proxy_url(_proxy_url),
        proxy_port(_proxy_port),
        proxy_auth(_proxy_auth),
        resolver_(io_service),
        deadline(io_service),
        socket_(io_service),
        ssl_socket(socket_, context),
        token(_token)
    {
    }

    Maybe<void>
    handleConnection()
    {
        ostream request_stream(&request_);
        stringstream http_request;
        http_request << "GET " << url.getQuery() << " HTTP/1.1\r\n";
        string host = url.getBaseURL().unpack();
        string port = url.getPort();
        int port_int;
        try {
            port_int = stoi(port);
        } catch (const exception &err) {
            dbgWarning(D_COMMUNICATION)
                << "Failed to convert port number from string. Port: "
                << port
                << ", Error: "
                << err.what();
            return genError("Failed to parse port to a number. Port: " + port);
        }
        if (port_int != 443) {
            host = host + ":" + port;
        }

        http_request << "Host: " << host << "\r\n";

        if (!token.empty()) {
            http_request << "Authorization: " << "Bearer " << token << "\r\n";
        }
        http_request << "User-Agent: Infinity Next (a7030abf93a4c13)\r\n";
        boost::uuids::uuid correlation_id;
        try {
            correlation_id = uuid_random_gen();
        } catch (const boost::uuids::entropy_error &) {
            dbgWarning(D_COMMUNICATION) << "Failed to generate random correlation id - entropy exception";
        }
        http_request << "X-Trace-Id: " + boost::uuids::to_string(correlation_id) + "\r\n";
        http_request << "Accept: */*\r\n";
        http_request << "Connection: close\r\n\r\n";

        request_stream << http_request.str();

        deadline.expires_from_now(boost::posix_time::minutes(5));
        deadline.async_wait(boost::bind(&Client::checkDeadline, this, _1));

        if (proxy_url.ok()) {
            if (!proxy_port.ok()) {
                dbgWarning(D_COMMUNICATION)
                    << "Failed to connect to proxy due to invalid port value, Error: "
                    << proxy_port.getErr();

                return genError(
                    "Failed to handle connection to server. proxy port is invalid, Error: " +
                    proxy_port.getErr()
                );
            }
            if (port_int == 443) host = host + ":" + port;
            ostream connect_request_stream(&connect_request);
            stringstream proxy_request;
            proxy_request << "CONNECT " << host << " HTTP/1.1\r\n";
            proxy_request << "Host: " << host << "\r\n";
            if (proxy_auth.ok()) {
                I_Encryptor *encryptor = Singleton::Consume<I_Encryptor>::by<Downloader>();
                proxy_request
                    << "Proxy-Authorization: Basic "
                    << encryptor->base64Encode(proxy_auth.unpack())
                    << "\r\n";
            }
            proxy_request << "\r\n";

            dbgTrace(D_HTTP_REQUEST) << "Connecting to proxy: " << endl << proxy_request.str();
            connect_request_stream << proxy_request.str();

            tcp::resolver::query query(proxy_url.unpack(), to_string(proxy_port.unpack()));
            resolver_.async_resolve(
                query,
                boost::bind(
                    &Client::overProxyResolver,
                    this,
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::iterator
                )
            );
        } else {
            tcp::resolver::query query(url.getBaseURL().unpack(), port);
            resolver_.async_resolve(
                query,
                boost::bind(
                    &Client::handleResolve,
                    this,
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::iterator
                )
            );
        }

        dbgTrace(D_HTTP_REQUEST) << "Sending the following HTTP Request: " << endl << http_request.str();
        return Maybe<void>();
    }

private:
    void
    checkDeadline(const boost::system::error_code &err)
    {
        if (err) return;
        if (deadline.expires_at() <= boost::asio::deadline_timer::traits_type::now()) {
            boost::system::error_code ignored_ec = boost::asio::error::operation_aborted;
            socket_.close(ignored_ec);
            deadline.expires_at(boost::posix_time::pos_infin);
            return;
        }
        deadline.async_wait(boost::bind(&Client::checkDeadline, this, _1));
    }

    void
    overProxyResolver(const boost::system::error_code &err, tcp::resolver::iterator endpoint_iterator)
    {
        if (!err) {
            boost::asio::async_connect(socket_, endpoint_iterator,
                boost::bind(&Client::overProxyHandleConnect, this,
                    boost::asio::placeholders::error));
        } else {
            string err_msg = "Failed to connect to proxy. Error: " + err.message();
            throw BadResponseFromServer(err_msg);
        }
    }

    void
    overProxyHandleConnect(const boost::system::error_code &err)
    {
        if (!err) {
            boost::asio::async_write(socket_, connect_request,
                boost::bind(&Client::overProxyHandleWriteRequest, this,
                    boost::asio::placeholders::error));
        } else {
            string err_msg = "Failed to connect to proxy. Error: " + err.message();
            throw BadResponseFromServer(err_msg);
        }
    }

    void
    overProxyHandleWriteRequest(const boost::system::error_code &err)
    {
        if (!err) {
            boost::asio::async_read_until(
                socket_,
                response_,
                "\r\n",
                boost::bind(&Client::overProxyHandleReadStatusLine, this, boost::asio::placeholders::error)
            );
        } else {
            string err_msg = "Failed to write over proxy. Error: " + err.message();
            throw BadResponseFromServer(err_msg);
        }
    }

    void
    overProxyHandleReadStatusLine(const boost::system::error_code &err)
    {
        if (err) {
            string err_msg = "Failed to read status line over proxy. Error: " + err.message();
            throw BadResponseFromServer(err_msg);
        }
        // Check that response is OK.
        istream response_stream(&response_);
        string response_http_version;
        response_stream >> response_http_version;
        unsigned int status_code;
        response_stream >> status_code;
        string status_message;
        getline(response_stream, status_message);
        if (!response_stream || response_http_version.substr(0, 5) != "HTTP/") {
            throw BadResponseFromServer("Invalid response");
            return;
        }

        if (status_code != 200) {
            string err_msg = "Response returned with status code " + status_code;
            throw BadResponseFromServer(err_msg);
        }

        dbgTrace(D_HTTP_REQUEST)
            << "Received HTTP Response over proxied connection with the following data:"
            << endl
            << response_http_version
            << " "
            << status_code
            << " "
            << status_message;

        if (getProfileAgentSettingWithDefault<bool>(false, "agent.config.message.ignoreSslValidation") == false) {
            ssl_socket.set_verify_mode(boost::asio::ssl::verify_peer | boost::asio::ssl::verify_fail_if_no_peer_cert);
            ssl_socket.set_verify_callback(boost::bind(&Client::verifyCertificate, this, _1, _2));
        } else {
            dbgWarning(D_HTTP_REQUEST) << "Ignoring SSL validation";
        }

        ssl_socket.async_handshake(
            boost::asio::ssl::stream_base::client,
            boost::bind(&Client::handleHandshake, this, boost::asio::placeholders::error)
        );
    }

    void
    handleResolve(const boost::system::error_code &err, tcp::resolver::iterator endpoint_iterator)
    {
        if (!err) {
            boost::asio::async_connect(ssl_socket.lowest_layer(), endpoint_iterator,
                boost::bind(&Client::handleConnect, this,
                    boost::asio::placeholders::error));
        } else {
            string message = "Failed to connect. Error: " + err.message();
            throw BadResponseFromServer(message);
        }
    }

    bool
    verifyCertificate(bool preverified, boost::asio::ssl::verify_context &ctx)
    {
        if (!token.empty()) {
            X509_STORE_CTX *cts = ctx.native_handle();

            switch (X509_STORE_CTX_get_error(cts))
            {
                case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
                    dbgWarning(D_ORCHESTRATOR) << "SSL verification error: X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT";
                    break;
                case X509_V_ERR_CERT_NOT_YET_VALID:
                case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
                    dbgWarning(D_ORCHESTRATOR) << "SSL verification error: Certificate not yet valid";
                    break;
                case X509_V_ERR_CERT_HAS_EXPIRED:
                case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
                    dbgWarning(D_ORCHESTRATOR) << "Certificate expired";
                    break;
                case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
                case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
                    dbgDebug(D_ORCHESTRATOR) << "Self signed certificate in chain";
                    if (getConfigurationWithDefault(false, "orchestration", "Self signed certificates acceptable")) {
                        preverified = true;
                    }
                    break;
                default:
                    if (!preverified) {
                        dbgWarning(D_ORCHESTRATOR)
                            << "Certificate verification error number: "
                            << X509_STORE_CTX_get_error(cts);
                    }
                    break;
            }
            return preverified;
        }
        return true;
    }

    void
    handleConnect(const boost::system::error_code &err)
    {
        if (!err) {
            if (getProfileAgentSettingWithDefault<bool>(false, "agent.config.message.ignoreSslValidation") == false) {
                ssl_socket.set_verify_mode(
                    boost::asio::ssl::verify_peer |
                    boost::asio::ssl::verify_fail_if_no_peer_cert
                );
                ssl_socket.set_verify_callback(boost::bind(&Client::verifyCertificate, this, _1, _2));
            } else {
                dbgWarning(D_HTTP_REQUEST) << "Ignoring SSL validation";
            }

            ssl_socket.async_handshake(boost::asio::ssl::stream_base::client,
                boost::bind(&Client::handleHandshake, this,
                    boost::asio::placeholders::error));
        } else {
            string err_message = "Failed to connect. Error: " + err.message();
            throw BadResponseFromServer(err_message);
        }
    }

    void
    handleHandshake(const boost::system::error_code &error)
    {
        if (!error) {
            boost::asio::buffer_cast<const char*>(request_.data());

            boost::asio::async_write(ssl_socket, request_,
                boost::bind(&Client::handleWriteRequest, this,
                    boost::asio::placeholders::error));
        } else {
            string err_message = "Handshake failed. Error: " + error.message();
            throw BadResponseFromServer(err_message);
        }
    }

    void
    handleWriteRequest(const boost::system::error_code &err)
    {
        if (!err) {
            boost::asio::async_read_until(ssl_socket, resp, "\r\n",
                boost::bind(&Client::handleReadStatusLine, this,
                    boost::asio::placeholders::error));
        } else {
            string err_message = "Failed to handle write request. Error: " + err.message();
            throw BadResponseFromServer(err_message);
        }
    }

    void
    handleReadStatusLine(const boost::system::error_code &err)
    {
        if (!err) {
            istream response_stream(&resp);
            string http_version;
            response_stream >> http_version;
            unsigned int status_code;
            response_stream >> status_code;
            string status_message;
            getline(response_stream, status_message);
            dbgTrace(D_HTTP_REQUEST)
                << "Received HTTP Response with the following data:"
                << endl
                << http_version
                << " "
                << status_code;

            if (!response_stream || http_version.substr(0, 5) != "HTTP/") {
                string err_message = "Invalid response";
                throw BadResponseFromServer(err_message);
            }
            if (status_code != 200) {
                string err_message = "HTTPS response returned with status code " + to_string(status_code)
                    + ". URL: " + url.toString();
                throw BadResponseFromServer(err_message);
            }

            boost::asio::async_read_until(ssl_socket, resp, "\r\n\r\n",
                boost::bind(&Client::handleReadHeaders, this,
                    boost::asio::placeholders::error));
        } else {
            dbgWarning(D_COMMUNICATION) << "Failed to read response status. Error:" << err.message();
            string err_message = "Failed to read status. Error: " + err.message();
            throw BadResponseFromServer(err_message);
        }
    }

    void
    handleReadHeaders(const boost::system::error_code &err)
    {
        if (!err) {
            // Process the response headers.
            istream response_stream(&resp);
            string header;
            vector<string> headers;
            while (getline(response_stream, header) && header != "\r") {
                headers.push_back(header);
            }

            dbgTrace(D_HTTP_REQUEST) << "Received Response headers:" << endl << makeSeparatedStr(headers, "\n");
            // Write whatever content we already have to output.
            if (resp.size() > 0)
                out_file << &resp;

            // Start reading remaining data until EOF.
            boost::asio::async_read(ssl_socket, resp,
                boost::asio::transfer_at_least(1),
                boost::bind(&Client::handleReadContent, this,
                    boost::asio::placeholders::error));
        } else {
            dbgWarning(D_COMMUNICATION) << "Failed to read response headers. Error:" << err.message();
            string err_message = "Failed to read headers. Error: " + err.message();
            throw BadResponseFromServer(err_message);
        }
    }

    void
    handleReadContent(const boost::system::error_code &err)
    {
        if (!err) {
            // Write all of the data that has been read so far.
            out_file << &resp;
            // Continue reading remaining data until EOF.
            boost::asio::async_read(
                ssl_socket,
                resp,
                boost::asio::transfer_at_least(1),
                boost::bind(&Client::handleReadContent, this, boost::asio::placeholders::error)
            );
        } else if (err != boost::asio::error::eof && err != boost::asio::ssl::error::stream_truncated) {
            dbgWarning(D_COMMUNICATION) << "Failed to read response body. Error:" << err.message();
            string err_message = "Failed to read content. Error: " + err.message();
            throw BadResponseFromServer(err_message);
        } else if (err == boost::asio::ssl::error::stream_truncated) {
            dbgError(D_COMMUNICATION) << "Had SSL warning during reading response body stage. Error:" << err.message();
            deadline.cancel();
        } else {
            deadline.cancel();
        }
    }

    ofstream &out_file;
    const URLParser &url;
    const Maybe<string> proxy_url;
    const Maybe<uint16_t> proxy_port;
    const Maybe<string> proxy_auth;
    tcp::resolver resolver_;
    boost::asio::deadline_timer deadline;
    boost::asio::ip::tcp::socket socket_;
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket&> ssl_socket;
    boost::asio::streambuf request_;
    boost::asio::streambuf connect_request;
    boost::asio::streambuf response_;
    boost::asio::streambuf resp;
    const string &token;
    boost::uuids::random_generator uuid_random_gen;
};

string
HTTPClient::loadCAChainDir()
{
    string ca_chain_dir;
    auto agent_details = Singleton::Consume<I_AgentDetails>::by<Downloader>();
    auto load_ca_chain_dir = agent_details->getOpenSSLDir();
    if (load_ca_chain_dir.ok()) {
        ca_chain_dir = load_ca_chain_dir.unpack();
    }
    return getConfigurationWithDefault<string>(ca_chain_dir, "message", "Certificate authority directory");
}

Maybe<void>
HTTPClient::getFileSSL(const URLParser &url, ofstream &out_file, const string &token)
{
    try {
        boost::asio::ssl::context ctx(boost::asio::ssl::context::sslv23);
        if (!token.empty()) {
            string cert_file_path = getConfigurationWithDefault<string>(
                getFilesystemPathConfig() + "/certs/fog.pem",
                "message",
                "Certificate chain file path"
            );
            dbgTrace(D_ORCHESTRATOR) << "Http client, cert file path: " << cert_file_path;
            auto trusted_ca_directory = getConfiguration<string>("message", "Trusted CA directory");
            if (trusted_ca_directory.ok() && !trusted_ca_directory.unpack().empty()) {
                ctx.add_verify_path(trusted_ca_directory.unpack());
            } else {
                string cert_file_path = getConfigurationWithDefault<string>(
                    getFilesystemPathConfig() + "/certs/fog.pem",
                    "message",
                    "Certificate chain file path"
                );
                ctx.load_verify_file(cert_file_path);
            }
        }
        boost::asio::io_service io_service;
        auto proxy_config = Singleton::Consume<I_ProxyConfiguration>::by<HTTPClient>();

        Client client(
            out_file,
            io_service,
            ctx,
            url,
            proxy_config->getProxyDomain(ProxyProtocol::HTTPS),
            proxy_config->getProxyPort(ProxyProtocol::HTTPS),
            proxy_config->getProxyCredentials(ProxyProtocol::HTTPS),
            token
        );

        auto connection_result = client.handleConnection();
        if (!connection_result.ok()) {
            return connection_result;
        };

        auto mainloop = Singleton::Consume<I_MainLoop>::by<Downloader>();
        while (!io_service.stopped()) {
            io_service.poll_one();
            mainloop->yield(true);
        }
    } catch (const exception &e) {
        dbgWarning(D_COMMUNICATION) << "Failed to get file over HTTPS. Error:" << string(e.what());
        string error_str = "Failed to get file over HTTPS, exception: " + string(e.what());
        return genError(error_str);
    }

    return Maybe<void>();
}

Maybe<void>
HTTPClient::curlGetFileOverSSL(const URLParser &url, ofstream &out_file, const string &token)
{
    try {
        string cert_file_path;
        if (!token.empty())
        {
            cert_file_path = getConfigurationWithDefault<string>(
                getFilesystemPathConfig() + "/certs/fog.pem",
                "message",
                "Certificate chain file path"
            );
        }

        auto proxy_config = Singleton::Consume<I_ProxyConfiguration>::by<HTTPClient>();

        HttpsCurl ssl_curl_client(
            url,
            out_file,
            token,
            proxy_config->getProxyDomain(ProxyProtocol::HTTPS),
            proxy_config->getProxyPort(ProxyProtocol::HTTPS),
            proxy_config->getProxyCredentials(ProxyProtocol::HTTPS),
            cert_file_path);

        ssl_curl_client.setCurlOpts();
        bool connection_ok = ssl_curl_client.connect();
        if (!connection_ok)
        {
            stringstream url_s;
            url_s << url;
            string err_msg = string("Failed to get file over HTTPS. URL: ") + url_s.str();
            return genError(err_msg);
        }

    } catch (const exception &e) {
        dbgWarning(D_COMMUNICATION) << "Failed to get file over HTTPS. Error:" << string(e.what());
        string error_str = "Failed to get file over HTTPS, exception: " + string(e.what());
        return genError(error_str);
    }

    return Maybe<void>();
}

// LCOV_EXCL_STOP
