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

#ifndef __MESSAGING_ENUMS_H__
#define __MESSAGING_ENUMS_H__

enum class MessageCategory
{
    GENERIC,
    LOG,
    DEBUG,
    METRIC,
    INTELLIGENCE,

    COUNT
};

enum class MessageConnectionConfig
{
    UNSECURE_CONN,
    ONE_TIME_CONN,
    IGNORE_SSL_VALIDATION,
    ONE_TIME_FOG_CONN, // used for learning mechanism - one time connection sent by dedicated thread

    COUNT
};

enum class HTTPMethod
{
    GET,
    POST,
    PATCH,
    CONNECT,
    PUT,

    COUNT
};

enum class HTTPStatusCode
{
    // 10X - Information responses. Not supported yet.
    // 20x - Successful responses.
    NO_HTTP_RESPONSE = 0,
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
    HTTP_TOO_MANY_REQUESTS = 429,
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
    HTTP_UNKNOWN = -1,
    HTTP_SUSPEND = -2
};

enum class BioConnectionStatus
{
    SUCCESS,
    SHOULD_RETRY,
    SHOULD_NOT_RETRY,

    COUNT
};

#endif // __MESSAGING_ENUMS_H__
