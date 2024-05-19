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

#include "http_request.h"

#include <sstream>
#include <string>

#include "messaging.h"

using namespace std;

USE_DEBUG_FLAG(D_MESSAGING);

void
HTTPRequest::insertHeader(const string &header_key, const string &header_val)
{
    headers[header_key] = header_val;
}

bool
HTTPRequest::setConnectionHeaders(const Connection &conn)
{
    string host = conn.getConnKey().getHostName();
    string uri_prefix = conn.isOverProxy() ? "http://" + host : "";

    switch (method) {
        case HTTPMethod::GET: {
            method_statement = "GET " + uri_prefix + uri + " HTTP/1.1";
            break;
        }
        case HTTPMethod::POST: {
            method_statement = "POST " + uri_prefix + uri + " HTTP/1.1";
            break;
        }
        case HTTPMethod::PATCH: {
            method_statement = "PATCH " + uri_prefix + uri + " HTTP/1.1";
            break;
        }
        case HTTPMethod::PUT: {
            method_statement = "PUT " + uri_prefix + uri + " HTTP/1.1";
            break;
        }
        case HTTPMethod::CONNECT: {
            host = host + ":" + to_string(conn.getConnKey().getPort());
            method_statement = "CONNECT " + host + " HTTP/1.1";
            break;
        }
        default: {
            return false;
        }
    }

    if (headers.find("Host") == headers.end()) {
        insertHeader("Host", host);
    }
    insertHeader("Content-Length", to_string(body.size()));
    insertHeader("Content-type", "application/json");
    insertHeader("Accept-Encoding", "identity");
    if (headers.find("Connection") == headers.end()) {
        insertHeader("Connection", "keep-alive");
    }
    return true;
}

Maybe<HTTPRequest>
HTTPRequest::prepareRequest(
    const Connection &conn,
    HTTPMethod method,
    const string &uri,
    const map<string, string> &headers,
    const string &body
)
{
    HTTPRequest req(method, uri, headers, body);

    bool dont_add_access_token = false;
    if (headers.find("Host") != headers.end()) {
        dont_add_access_token = true;
        dbgTrace(D_MESSAGING) << "Request is not for FOG";
    }
    string agent_registration_query = R"("authenticationMethod": "token")";
    if (method == HTTPMethod::CONNECT || body.find(agent_registration_query) != string::npos) {
        dont_add_access_token = true;
        dbgTrace(D_MESSAGING) << "Request is for agent authentication";
    }
    auto res = req.addAccessToken(conn, dont_add_access_token);
    if (!res.ok()) return res.passErr();

    if (!req.setConnectionHeaders(conn)) return genError("Failed to identify the HTTP method");

    if (conn.isOverProxy()) {
        auto res = req.addProxyAuthorization(conn);
        if (!res.ok()) return res.passErr();
    }

    return req;
}

string
HTTPRequest::toString() const
{
    stringstream res;
    res << method_statement << "\r\n";
    for (const auto &header : headers) {
        res << header.first << ": " << header.second << "\r\n";
    }
    res << "\r\n" << body;
    return res.str();
}

Maybe<void>
HTTPRequest::addAccessToken(const Connection &conn, bool dont_add_access_token)
{
    if (headers.find("Authorization") != headers.end() || dont_add_access_token) return Maybe<void>();

    if (!conn.getExternalCertificate().empty()) {
        insertHeader("Authorization", conn.getExternalCertificate());
        return Maybe<void>();
    }

    string access_token = Singleton::Consume<I_AgentDetails>::by<Messaging>()->getAccessToken();
    if (access_token.empty()) return genError("Access token is missing.");
    insertHeader("Authorization", "Bearer " + access_token);
    return Maybe<void>();
}

Maybe<void>
HTTPRequest::addProxyAuthorization(const Connection &conn)
{
    insertHeader("Accept", "*/*");
    insertHeader("Proxy-Connection", "Keep-Alive");

    if (!conn.isUnsecure()) return Maybe<void>();

    MessageProxySettings proxy_settings = conn.getProxySettings();
    if (proxy_settings.getProxyAuth().empty()) {
        dbgTrace(D_MESSAGING) << "No proxy authentication was set";
        return Maybe<void>();
    }

    I_Encryptor *encryptor = Singleton::Consume<I_Encryptor>::by<Messaging>();
    insertHeader("Proxy-Authorization", "Basic " + encryptor->base64Encode(proxy_settings.getProxyAuth()));
    return Maybe<void>();
}
