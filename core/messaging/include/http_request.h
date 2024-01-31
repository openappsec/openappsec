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

#ifndef __HTTP_REQUEST_H__
#define __HTTP_REQUEST_H__

#include <map>
#include <string>

#include "connection.h"
#include "i_agent_details.h"
#include "i_encryptor.h"
#include "i_messaging.h"

class HTTPRequest
{
public:
    static Maybe<HTTPRequest> prepareRequest(
        const Connection &conn,
        HTTPMethod method,
        const std::string &uri,
        const std::map<std::string, std::string> &headers,
        const std::string &body
    );

    Maybe<void> setConnectionHeaders(const Connection &conn, bool is_access_token_needed);

    bool
    isConnect() const
    {
        return method == HTTPMethod::CONNECT;
    }

    std::string toString() const;

private:
    HTTPRequest(
        HTTPMethod _method,
        const std::string &_uri,
        const std::map<std::string, std::string> &_headers,
        const std::string &_body
    ) :
        body(_body), uri(_uri), headers(_headers), method(_method)
    {}

    bool setConnectionHeaders(const Connection &conn);
    void insertHeader(const std::string &header_key, const std::string &header_val);
    Maybe<void> addAccessToken(const Connection &conn, bool is_registration);
    Maybe<void> addProxyAuthorization(const Connection &conn);

    std::string body;
    std::string uri;
    std::string method_statement;
    std::map<std::string, std::string> headers;
    HTTPMethod method;
};

#endif // __HTTP_REQUEST_H__
