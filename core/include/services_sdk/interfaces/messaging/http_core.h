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

#ifndef __HTTP_CORE_H__
#define __HTTP_CORE_H__

#include <string>
#include <unordered_map>

#include "maybe_res.h"
#include "cereal/archives/json.hpp"
#include "cereal/types/string.hpp"

enum class HTTPStatusCode
{
    // 10X - Information responses. Not supported yet.
    // 20x - Successful responses.
    HTTP_OK = 200,
    HTTP_NO_CONTENT = 204,
    HTTP_MULTI_STATUS = 207,
    // 30x - Redirection messages. Not supported yet.
    // 4xx - Client error responses.
    HTTP_BAD_REQUEST = 400,
    HTTP_UNAUTHORIZED = 401,
    HTTP_FORBIDDEN = 403,
    HTTP_NOT_FOUND = 404,
    HTTP_METHOD_NOT_ALLOWED = 405,
    HTTP_PROXY_AUTHENTICATION_REQUIRED = 407,
    HTTP_REQUEST_TIME_OUT = 408,
    HTTP_PAYLOAD_TOO_LARGE = 413,
    // 5xx - Server error responses.
    HTTP_INTERNAL_SERVER_ERROR = 500,
    HTTP_NOT_IMPLEMENTED = 501,
    HTTP_BAD_GATEWAY = 502,
    HTTP_SERVICE_UNABAILABLE = 503,
    HTTP_GATEWAY_TIMEOUT = 504,
    HTTP_VERSION_NOT_SUPPORTED = 505,
    HTTP_VARIANT_ALSO_NEGOTIATES = 506,
    HTTP_INSUFFICIENT_STORAGE = 507,
    HTTP_LOOP_DETECTED = 508,
    HTTP_NOT_EXTENDED = 510,
    HTTP_NETWORK_AUTHENTICATION_REQUIRED = 511,
    // Not supported status code.
    HTTP_UNKNOWN
};

class HTTPResponse
{
public:
    HTTPResponse(const HTTPStatusCode status_code, const std::string &&body);

    Maybe<std::string> getResponse() const;

    HTTPStatusCode getStatusCode() const { return status_code; }
    std::string getBody() const { return body; }

    class BadRequestResponse
    {
    public:
        void serialize(cereal::JSONInputArchive &ar);

        std::string getMsg() const          { return message; }
        std::string getID() const           { return message_id; }

    private:
        std::string message;
        std::string message_id;
    };

private:
    HTTPStatusCode status_code;
    std::string body;
};

class HTTPHeaders
{
public:
    HTTPHeaders() = default;
    static Maybe<HTTPHeaders> createHTTPHeader(const std::string &http_data);

    void insertHeader(const std::string &header_key, const std::string &header_val);
    void insertHeader(const std::string &header);
    void insertHeaders(const std::string &headers);
    Maybe<std::string> getHeaderVal(const std::string &header_key);
    std::string toString() const;

private:
    HTTPHeaders(const std::string &http_data);

    std::unordered_map<std::string, std::string> headers;
};

#endif // __HTTP_CORE_H__
