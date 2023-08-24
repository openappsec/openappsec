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
#include "downloader.h"
#include "debug.h"
#include "i_encryptor.h"
#include "url_parser.h"
#include "config.h"
#include "i_environment.h"
#include "orchestration_comp.h"

#include <fstream>
#include <string>
#include <iostream>
#include <chrono>
#include <boost/asio/ip/tcp.hpp>

using boost::asio::ip::tcp;
using namespace std;

USE_DEBUG_FLAG(D_ORCHESTRATOR);
USE_DEBUG_FLAG(D_HTTP_REQUEST);

// LCOV_EXCL_START Reason: Depends on real download server.
class ClientConnection
{
public:
    ClientConnection(
        const URLParser &_url,
        const Maybe<string> &_proxy_url,
        const Maybe<uint16_t> &_proxy_port,
        const Maybe<string> &_proxy_auth,
        const string &_token)
            :
        url(_url),
        proxy_url(_proxy_url),
        proxy_port(_proxy_port),
        proxy_auth(_proxy_auth),
        token(_token)
    {
    }

    Maybe<void>
    handleConnect()
    {
        if (!url.getBaseURL().ok()) {
            return genError("Failed to handle connection. Error: " + url.getBaseURL().getErr());
        }
        string server_name = url.getBaseURL().unpack();
        string port = url.getPort();
        string query = url.getQuery();
        string host = server_name;
        try {
            if (stoi(port) != 80) {
                host = host + ":" + port;
            }
        } catch (const exception &err) {
            return genError("Failed to parse port to a number. Port: " + port );
        }

        chrono::duration<unsigned int, ratio<1>> sleep_time(60);
        io_stream.expires_from_now(sleep_time);

        if (proxy_url.ok()) {
            if (!proxy_port.ok()) {
                return genError(
                    "Failed to handle connection to server. proxy domain is defined with invalid port, Error: " +
                    proxy_port.getErr()
                );
            }
            io_stream.connect(proxy_url.unpack(), to_string(proxy_port.unpack()));
        } else {
            io_stream.connect(server_name, port);
        }

        if (!io_stream) {
            return genError("Failed to handle connection to server. Error: " + io_stream.error().message());
        }

        string request_url = query;
        if (proxy_url.ok()) {
            request_url = host + query;
        }

        stringstream http_request;
        http_request << "GET http://" << request_url << " HTTP/1.1\r\n";
        http_request << "Host: " << host << "\r\n";
        if (!token.empty()) {
            http_request << "Authorization: " << "Bearer " << token << "\r\n";
        }
        http_request << "User-Agent: Infinity Next (a7030abf93a4c13)\r\n";

        auto i_trace_env = Singleton::Consume<I_Environment>::by<OrchestrationComp>();
        http_request << i_trace_env->getCurrentHeaders();
        http_request << "Accept: */*\r\n";

        if (proxy_url.ok()) {
            http_request << "Accept-Encoding: identity";
            http_request << "Connection: close\r\n";
            http_request << "Proxy-Connection: Keep-Alive\r\n";

            if (proxy_auth.ok()) {
                I_Encryptor *encryptor = Singleton::Consume<I_Encryptor>::by<Downloader>();
                http_request << "Proxy-Authorization: Basic " + encryptor->base64Encode(proxy_auth.unpack()) + "\r\n";
            }
            http_request << "\r\n";
        } else {
            http_request << "Connection: close\r\n\r\n";
        }

        dbgTrace(D_HTTP_REQUEST) << "Sending the following HTTP Request: " << endl << http_request.str();
        io_stream << http_request.str();
        return Maybe<void>();
    }

    Maybe<void>
    handleResponse(ofstream &out_file)
    {
        string response_http_version;
        io_stream >> response_http_version;
        unsigned int status_code;
        io_stream >> status_code;
        string status_message;
        getline(io_stream, status_message);

        if (!io_stream || response_http_version.substr(0, 5) != "HTTP/")  {
            return genError("Invalid response");
        }

        if (status_code != 200) {
            return genError("HTTP response returned with status code " + status_code);
        }

        string header;
        vector<string> headers;
        while (getline(io_stream, header) && header != "\r") {
            headers.push_back(header);
        }

        out_file << io_stream.rdbuf();

        dbgTrace(D_HTTP_REQUEST)
            << "Received HTTP Response with the following data (downloaded file will not be printed):"
            << endl
            << response_http_version
            << " "
            << status_code
            << " "
            << status_message
            << endl
            << makeSeparatedStr(headers, "\n");


        return Maybe<void>();
    }

private:
    const URLParser url;
    const Maybe<string> proxy_url;
    const Maybe<uint16_t> proxy_port;
    const Maybe<string> proxy_auth;
    const string &token;
    boost::asio::ip::tcp::iostream io_stream;
};

Maybe<void>
HTTPClient::getFile(const URLParser &url, ofstream &out_file, bool auth_required)
{
    auto proxy_config = Singleton::Consume<I_ProxyConfiguration>::by<HTTPClient>();
    auto load_env_proxy = proxy_config->loadProxy();
    if (!load_env_proxy.ok()) return load_env_proxy;

    string token = "";
    if (auth_required) {
        token = Singleton::Consume<I_AgentDetails>::by<HTTPClient>()->getAccessToken();
    }

    if (url.isOverSSL()) {
        auto get_file_over_ssl_res = getFileSSL(url, out_file, token);
        if (!get_file_over_ssl_res.ok())
        {
            //CURL fallback
            dbgWarning(D_ORCHESTRATOR) << "Failed to get file over SSL. Trying via CURL (SSL).";
            return curlGetFileOverSSL(url, out_file, token);
        }
        return get_file_over_ssl_res;
    }
    auto get_file_http_res = getFileHttp(url, out_file, token);
    if (!get_file_http_res.ok())
    {
        //CURL fallback
        dbgWarning(D_ORCHESTRATOR) << "Failed to get file over HTTP. Trying via CURL (HTTP).";
        return curlGetFileOverHttp(url, out_file, token);
    }

    return get_file_http_res;
}

Maybe<void>
HTTPClient::curlGetFileOverHttp(const URLParser &url, ofstream &out_file, const string &token)
{
    try {
        auto proxy_config = Singleton::Consume<I_ProxyConfiguration>::by<HTTPClient>();

        HttpCurl http_curl_client(
            url,
            out_file,
            token,
            proxy_config->getProxyDomain(ProxyProtocol::HTTPS),
            proxy_config->getProxyPort(ProxyProtocol::HTTPS),
            proxy_config->getProxyCredentials(ProxyProtocol::HTTPS));

        http_curl_client.setCurlOpts();
        bool connection_ok = http_curl_client.connect();
        if (!connection_ok)
        {
            stringstream url_s;
            url_s << url;
            string err_msg = string("Failed to get file over HTTP. URL: ") + url_s.str();
            return genError(err_msg);
        }

        // As this class is a temporal solution catch all exception types is enabled.
    } catch (const exception &e) {
        string err_msg = "Failed to get file over HTTP. Exception: " + string(e.what());
        return genError(err_msg);
    }

    return Maybe<void>();
}

Maybe<void>
HTTPClient::getFileHttp(const URLParser &url, ofstream &out_file, const string &token)
{
    try {
        auto proxy_config = Singleton::Consume<I_ProxyConfiguration>::by<HTTPClient>();
        ClientConnection client_connection(
            url,
            proxy_config->getProxyDomain(ProxyProtocol::HTTP),
            proxy_config->getProxyPort(ProxyProtocol::HTTP),
            proxy_config->getProxyCredentials(ProxyProtocol::HTTP),
            token
        );
        auto handle_connect_res = client_connection.handleConnect();
        if (!handle_connect_res.ok()) return handle_connect_res;

        return client_connection.handleResponse(out_file);

    // As this class is a temporal solution catch all exception types is enabled.
    } catch (const exception &e) {
        string err_msg = "Failed to get file over HTTP. Exception: " + string(e.what());
        return genError(err_msg);
    }

    return Maybe<void>();
}
// LCOV_EXCL_STOP
