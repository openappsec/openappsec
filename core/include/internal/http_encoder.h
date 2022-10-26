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

#ifndef __HTTP_ENCODER_H__
#define __HTTP_ENCODER_H__

#include <string>

#include "messaging/http_core.h"

class HTTPRequest
{
public:
    HTTPRequest() = default;
    HTTPRequest(const std::string &_method_statement);
    HTTPRequest(const std::string &_method_statement, const std::string &_host, const bool to_proxy);

    HTTPRequest & insertHeader(const std::string &header_key, const std::string &header_val);
    HTTPRequest & insertHeader(const std::string &header);
    HTTPRequest & insertHeaders(const std::string &rec_headers);
    HTTPRequest & insertBody(const std::string &body);

    std::string toString() const;

private:
    std::string method_statement;
    HTTPHeaders headers;
    std::string body;
};

class ConnectRequest: public HTTPRequest
{
public:
    ConnectRequest(const std::string &_host, const std::string &_port);
};

class PostRequest: public HTTPRequest
{
public:
    PostRequest(const std::string &_post_path, const std::string &_host, bool to_proxy);
};

class PutRequest : public HTTPRequest
{
public:
    PutRequest(const std::string &_put_path, const std::string &_host, bool to_proxy);
};

class GetRequest: public HTTPRequest
{
public:
    GetRequest(const std::string &_get_path, const std::string &_host, bool to_proxy);
};

class PatchRequest: public HTTPRequest
{
public:
    PatchRequest(const std::string &_patch_path, const std::string &_host, bool to_proxy);
};

class HTTPEncoder
{
public:
    HTTPEncoder(const std::string &_host, const std::string &_port);

    HTTPRequest & Connect();
    HTTPRequest & Post(const std::string &post_path);
    HTTPRequest & Put(const std::string &put_path);
    HTTPRequest & Patch(const std::string &patch_path);
    HTTPRequest & Get(const std::string &get_path);

    HTTPEncoder & isOverProxy();
    HTTPEncoder & isOverSSL();

    std::string build() const { return request.toString(); }

private:
    HTTPRequest request;
    std::string host;
    std::string port;
    bool over_ssl   = false;
    bool over_proxy = false;
};

#endif //  __HTTP_ENCODER_H__
