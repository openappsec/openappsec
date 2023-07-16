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

#ifndef __HTTP_TRANSACTION_DATA_H__
#define __HTTP_TRANSACTION_DATA_H__

#include <iostream>
#include <string>
#include <list>
#include <string>
#include <vector>

#include "connkey.h"
#include "buffer.h"
#include "enum_range.h"
#include "maybe_res.h"
#include "http_transaction_common.h"
#include "compression_utils.h"

class HttpTransactionData
{
public:
    HttpTransactionData();

    HttpTransactionData (
        std::string http_proto,
        std::string method,
        std::string host_name,
        IPAddr listening_ip,
        uint16_t listening_port,
        std::string uri,
        IPAddr client_ip,
        uint16_t client_port
    );

    HttpTransactionData (
        std::string http_proto,
        std::string method,
        std::string host_name,
        std::string parsed_host,
        IPAddr listening_ip,
        uint16_t listening_port,
        std::string uri,
        std::string parsed_uri,
        IPAddr client_ip,
        uint16_t client_port
    );

// LCOV_EXCL_START - sync functions, can only be tested once the sync module exists
    template <class Archive>
    void
    save(Archive &ar) const
    {
        ar(
            http_proto,
            method,
            host_name,
            parsed_host,
            listening_ip,
            listening_port,
            uri,
            parsed_uri,
            client_ip,
            client_port,
            response_content_encoding
        );
    }

    template <class Archive>
    void
    load(Archive &ar)
    {
        ar(
            http_proto,
            method,
            host_name,
            parsed_host,
            listening_ip,
            listening_port,
            uri,
            parsed_uri,
            client_ip,
            client_port,
            response_content_encoding
        );
    }
// LCOV_EXCL_STOP

    static Maybe<HttpTransactionData> createTransactionData(const Buffer &transaction_raw_data);

    const IPAddr & getSourceIP() const { return client_ip; }
    uint16_t getSourcePort() const { return client_port; }
    const IPAddr & getListeningIP() const { return listening_ip; }
    uint16_t getListeningPort() const { return listening_port; }
    const std::string & getDestinationHost() const { return host_name; }
    const std::string & getParsedHost() const { return parsed_host; }
    const std::string & getHttpProtocol() const { return http_proto; }
    const std::string & getURI() const { return uri; }
    const std::string & getParsedURI() const { return parsed_uri; }
    const std::string & getHttpMethod() const { return method; }

    void print(std::ostream &out_stream) const;

    CompressionType getResponseContentEncoding() const { return response_content_encoding; }
    bool isRequest() const { return is_request; }

    void setDirection(bool _is_request) { is_request = _is_request; }

    void
    setResponseContentEncoding(const CompressionType _response_content_encoding)
    {
        response_content_encoding = _response_content_encoding;
    }

    static const std::string http_proto_ctx;
    static const std::string method_ctx;
    static const std::string host_name_ctx;
    static const std::string listening_port_ctx;
    static const std::string listening_ip_ctx;
    static const std::string uri_ctx;
    static const std::string uri_path_decoded;
    static const std::string uri_query_decoded;
    static const std::string client_ip_ctx;
    static const std::string client_port_ctx;
    static const std::string req_headers;
    static const std::string req_body;
    static const std::string source_identifier;
    static const std::string proxy_ip_ctx;

    static const CompressionType default_response_content_encoding;

private:
    std::string http_proto;
    std::string method = "GET";
    std::string host_name;
    std::string parsed_host;
    IPAddr listening_ip;
    uint16_t listening_port;
    std::string uri;
    std::string parsed_uri;
    IPAddr client_ip;
    uint16_t client_port;
    bool is_request;
    CompressionType response_content_encoding;
};

#endif // __HTTP_TRANSACTION_DATA_H__
