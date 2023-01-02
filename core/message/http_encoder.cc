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

#include "http_encoder.h"
#include "debug.h"

using namespace std;

USE_DEBUG_FLAG(D_COMMUNICATION);

HTTPRequest::HTTPRequest(const string &_method_statement, const string &_host, const bool to_proxy)
        :
    method_statement(_method_statement)
{
    if (to_proxy) {
        insertHeader("Accept: */*");
        insertHeader("Proxy-Connection: Keep-Alive");
    }
    insertHeader("Host", _host);
}

HTTPRequest::HTTPRequest(const string &_method_statement)
        :
    method_statement(_method_statement)
{
}

HTTPRequest &
HTTPRequest::insertHeader(const string &header_key, const string &header_val)
{
    headers.insertHeader(header_key, header_val);
    return *this;
}

HTTPRequest &
HTTPRequest::insertHeader(const string &header)
{
    try {
        headers.insertHeader(header);
    } catch(const std::exception& e) {
        dbgWarning(D_COMMUNICATION) << "Failed to insert header. Header: " << header;
    }

    return *this;
}

HTTPRequest &
HTTPRequest::insertHeaders(const string &rec_headers)
{
    try {
        headers.insertHeaders(rec_headers);
    } catch(const std::exception& e) {
        dbgWarning(D_COMMUNICATION) << "Failed to insert headers. Headers: " << rec_headers;
    }

    return *this;
}

HTTPRequest &
HTTPRequest::insertBody(const string &reqest_body)
{
    body = reqest_body;
    return *this;
}

string
HTTPRequest::toString() const
{
    string ret = method_statement + "\r\n";
    ret += headers.toString();
    ret += body;
    return ret;
}

ConnectRequest::ConnectRequest(const string &_host, const string &_port)
        :
    HTTPRequest("CONNECT " + _host + ":" + _port + " HTTP/1.1")
{
    insertHeader("Host", _host + ":" + _port);
}

PostRequest::PostRequest(const string &_post_path, const string &_host, bool to_proxy)
        :
    HTTPRequest("POST " + (to_proxy ? "http://" +  _host: "") + _post_path + " HTTP/1.1", _host, to_proxy)
{
}

PutRequest::PutRequest(const string &_put_path, const string &_host, bool to_proxy)
        :
    HTTPRequest("PUT " + (to_proxy ? "http://" + _host : "") + _put_path + " HTTP/1.1", _host, to_proxy)
{
}

GetRequest::GetRequest(const string &_get_path, const string &_host, bool to_proxy)
        :
    HTTPRequest("GET " + (to_proxy ? "http://" +  _host: "") + _get_path + " HTTP/1.1", _host, to_proxy)
{
}

PatchRequest::PatchRequest(const string &_patch_path, const string &_host, bool to_proxy)
        :
    HTTPRequest("PATCH " + (to_proxy ? "http://" +  _host: "") + _patch_path + " HTTP/1.1", _host, to_proxy)
{
}

HTTPEncoder::HTTPEncoder::HTTPEncoder(const string &_host, const string &_port)
        :
    host(_host),
    port(_port)
{
}

HTTPRequest &
HTTPEncoder::Connect()
{
    request = ConnectRequest(host, port);
    request.insertHeader("Proxy-Connection: Keep-Alive");
    return request;
}

HTTPRequest &
HTTPEncoder::Post(const string &_post_path)
{
    request = PostRequest(_post_path, host, over_proxy && !over_ssl);
    return request;
}

HTTPRequest &
HTTPEncoder::Put(const string &_put_path)
{
    request = PutRequest(_put_path, host, over_proxy && !over_ssl);
    return request;
}

HTTPRequest &
HTTPEncoder::Patch(const string &_patch_path)
{
    request = PatchRequest(_patch_path, host, over_proxy && !over_ssl);
    return request;
}

HTTPRequest &
HTTPEncoder::Get(const string &_get_path)
{
    request = GetRequest(_get_path, host, over_proxy && !over_ssl);
    return request;
}

HTTPEncoder &
HTTPEncoder::isOverProxy()
{
    over_proxy = true;
    return *this;
}

HTTPEncoder &
HTTPEncoder::isOverSSL()
{
    over_ssl = true;
    return *this;
};
