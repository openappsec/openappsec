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

#include "http_transaction_data.h"

#include <sys/time.h>
#include <sstream>
#include <boost/algorithm/string.hpp>

#include "enum_array.h"
#include "buffer.h"
#include "nginx_attachment_common.h"

using namespace std;

USE_DEBUG_FLAG(D_NGINX_ATTACHMENT);

enum class ETransactionData {
    HTTP_PROTO,
    METHOD,
    HOST_NAME,
    LISTENING_IP,
    LISTENING_PORT,
    URI,
    CLIENT_IP,
    CLIENT_PORT,

    COUNT
};

const string HttpTransactionData::http_proto_ctx     = "transaction_http_proto";
const string HttpTransactionData::method_ctx         = "transaction_method";
const string HttpTransactionData::host_name_ctx      = "transaction_host_name";
const string HttpTransactionData::listening_ip_ctx   = "transaction_listening_ip";
const string HttpTransactionData::listening_port_ctx = "transaction_listening_port";
const string HttpTransactionData::uri_ctx            = "transaction_uri";
const string HttpTransactionData::uri_path_decoded   = "transaction_uri_path_decoded";
const string HttpTransactionData::uri_query_decoded  = "transaction_uri_query_decoded";
const string HttpTransactionData::client_ip_ctx      = "transaction_client_ip";
const string HttpTransactionData::client_port_ctx    = "transaction_client_port";
const string HttpTransactionData::req_headers        = "transaction_request_headers";
const string HttpTransactionData::req_body           = "transaction_request_body";
const string HttpTransactionData::source_identifier  = "sourceIdentifiers";
const string HttpTransactionData::proxy_ip_ctx       = "proxy_ip";

const CompressionType HttpTransactionData::default_response_content_encoding = CompressionType::NO_COMPRESSION;

Maybe<uint16_t>
deserializeUintParam(const Buffer &data, uint &cur_pos)
{
    //  Int value is encoded in binary form
    auto value = data.getTypePtr<uint16_t>(cur_pos);

    if (!value.ok()) {
        return genError("Failed to get Uint param " + value.getErr());
    }

    cur_pos += sizeof(uint16_t);
    dbgTrace(D_NGINX_ATTACHMENT) << "Successfully parsed the number parameter. Value: " << *(value.unpack());

    return *(value.unpack());
}

Maybe<string>
deserializeStrParam(const Buffer &data, uint &cur_pos)
{
    //String is encoded by 16-bit uint representing length followed by const c-type string data bytes
    Maybe<uint16_t> str_size = deserializeUintParam(data, cur_pos);
    if (!str_size.ok()) return genError("Could Not parse string size value: " + str_size.getErr());

    dbgTrace(D_NGINX_ATTACHMENT)
        << "Deserializing string parameter. Current position: "
        << cur_pos
        << ", String size: "
        << *str_size;

    string res = "";
    if (*str_size > 0) {
        auto value = data.getPtr(cur_pos, *str_size);
        if (!value.ok()) {
            return genError("Failed to get String param " + value.getErr());
        }

        const u_char *ptr = value.unpack();
        res = string(reinterpret_cast<const char *>(ptr), *str_size);
    }
    dbgTrace(D_NGINX_ATTACHMENT)
        << "Successfully parsed string parameter. Result: "
        << res
        << ", Length: "
        << to_string(*str_size);

    cur_pos += *str_size;

    return move(res);
}

Maybe<IPAddr>
deserializeIpAddrParam(const Buffer &data, uint &cur_pos)
{
    Maybe<string> str_value = deserializeStrParam(data, cur_pos);
    if (!str_value.ok()) return str_value.passErr();

    Maybe<IPAddr> ip = IPAddr::createIPAddr(str_value.unpackMove());
    if (!ip.ok()) return genError("Could not parse IP Address: " + ip.getErr());

    return move(ip.unpackMove());
}

Maybe<HttpTransactionData>
HttpTransactionData::createTransactionData(const Buffer &transaction_raw_data)
{
    // Deserialize TransactionData from binary blob sent from attachment
    uint cur_pos = 0;

    dbgTrace(D_NGINX_ATTACHMENT)
        << "Parsing buffer "
        << dumpHex(transaction_raw_data)
        << " of size "
        << transaction_raw_data.size();

    Maybe<string> http_protocol = deserializeStrParam(transaction_raw_data, cur_pos);
    if (!http_protocol.ok()) {
        return genError("Could not deserialize HTTP protocol: " + http_protocol.getErr());
    } else {
        dbgTrace(D_NGINX_ATTACHMENT) << "Successfully deserialized HTTP protocol: " << http_protocol.unpack();
    }

    Maybe<string> http_method = deserializeStrParam(transaction_raw_data, cur_pos);
    if (!http_method.ok()) {
        return genError("Could not deserialize HTTP method: " + http_method.getErr());
    } else {
        dbgTrace(D_NGINX_ATTACHMENT) << "Successfully deserialized HTTP method: " << http_method.unpack();
    }

    Maybe<string> host_name = deserializeStrParam(transaction_raw_data, cur_pos);
    if (!host_name.ok()) {
        return genError("Could not deserialize host name: " + host_name.getErr());
    } else {
        dbgTrace(D_NGINX_ATTACHMENT) << "Successfully deserialized host name: " << host_name.unpack();
    }

    Maybe<IPAddr> listening_addr = deserializeIpAddrParam(transaction_raw_data, cur_pos);
    if (!listening_addr.ok()) {
        return genError("Could not deserialize listening address: " + listening_addr.getErr());
    } else {
        dbgTrace(D_NGINX_ATTACHMENT) << "Successfully deserialized listening address: " << listening_addr.unpack();
    }

    Maybe<uint32_t> listening_port = deserializeUintParam(transaction_raw_data, cur_pos);
    if (!listening_port.ok()) {
        return genError("Could not deserialize listening port: " + listening_port.getErr());
    } else {
        dbgTrace(D_NGINX_ATTACHMENT) << "Successfully deserialized listening port: " << listening_port.unpack();
    }

    Maybe<string> uri = deserializeStrParam(transaction_raw_data, cur_pos);
    if (!uri.ok()) {
        return genError("Could not deserialize URI: " + uri.getErr());
    } else {
        dbgTrace(D_NGINX_ATTACHMENT) << "Successfully deserialized URI: " << uri.unpack();
    }

    Maybe<IPAddr> client_addr = deserializeIpAddrParam(transaction_raw_data, cur_pos);
    if (!client_addr.ok()) {
        return genError("Could not deserialize client address: " + client_addr.getErr());
    } else {
        dbgTrace(D_NGINX_ATTACHMENT) << "Successfully deserialized client address: " << client_addr.unpack();
    }

    Maybe<uint32_t> client_port = deserializeUintParam(transaction_raw_data, cur_pos);
    if (!client_port.ok()) {
        return genError("Could not deserialize client port: " + client_port.getErr());
    } else {
        dbgTrace(D_NGINX_ATTACHMENT) << "Successfully deserialized client port: " << client_port.unpack();
    }

    if (cur_pos == transaction_raw_data.size()) {
        dbgDebug(D_NGINX_ATTACHMENT)
            << "No extra data to read from buffer. This agent is working with an old "
            << "attachment version that does not contain the parsed host and parsed uri elements.";

        HttpTransactionData transaction(
            http_protocol.unpackMove(),
            http_method.unpackMove(),
            host_name.unpackMove(),
            listening_addr.unpackMove(),
            listening_port.unpackMove(),
            uri.unpackMove(),
            client_addr.unpackMove(),
            client_port.unpackMove()
        );

        return transaction;
    }

    Maybe<string> ngx_parsed_host = deserializeStrParam(transaction_raw_data, cur_pos);
    if (!ngx_parsed_host.ok()) {
        return genError("Could not deserialize nginx host: " + ngx_parsed_host.getErr());
    } else {
        dbgTrace(D_NGINX_ATTACHMENT) << "Successfully deserialized nginx_host: " << ngx_parsed_host.unpack();
    }

    Maybe<string> ngx_parsed_uri = deserializeStrParam(transaction_raw_data, cur_pos);
    if (!ngx_parsed_uri.ok()) {
        return genError("Could not deserialize parsed URI: " + ngx_parsed_uri.getErr());
    } else {
        dbgTrace(D_NGINX_ATTACHMENT) << "Successfully deserialized parsed URI: " << ngx_parsed_uri.unpack();
    }

    // Fail if after parsing exact number of items, we didn't exactly consume whole buffer
    if (cur_pos != transaction_raw_data.size()) {
        dbgWarning(D_NGINX_ATTACHMENT) << "Nothing to deserialize, but raw data still remain";
        return genError("Finished deserialization and raw data still exist - Probably corrupted buffer.");
    }

    HttpTransactionData transaction(
        http_protocol.unpackMove(),
        http_method.unpackMove(),
        host_name.unpackMove(),
        ngx_parsed_host.unpackMove(),
        listening_addr.unpackMove(),
        listening_port.unpackMove(),
        uri.unpackMove(),
        ngx_parsed_uri.unpackMove(),
        client_addr.unpackMove(),
        client_port.unpackMove()
    );

    return transaction;
}

HttpTransactionData::HttpTransactionData (
    string _http_proto,
    string _method,
    string _host_name,
    IPAddr _listening_ip,
    uint16_t _listening_port,
    string _uri,
    IPAddr _client_ip,
    uint16_t _client_port
)
        :
    HttpTransactionData::HttpTransactionData(
        _http_proto,
        _method,
        _host_name,
        _host_name,
        _listening_ip,
        _listening_port,
        _uri,
        _uri,
        _client_ip,
        _client_port
    )
{
}

HttpTransactionData::HttpTransactionData (
    string _http_proto,
    string _method,
    string _host_name,
    string _parsed_host,
    IPAddr _listening_ip,
    uint16_t _listening_port,
    string _uri,
    string _parsed_uri,
    IPAddr _client_ip,
    uint16_t _client_port
)
        :
    http_proto(move(_http_proto)),
    method(move(_method)),
    host_name(move(_host_name)),
    parsed_host(move(_parsed_host)),
    listening_ip(move(_listening_ip)),
    listening_port(move(_listening_port)),
    uri(move(_uri)),
    parsed_uri(move(_parsed_uri)),
    client_ip(move(_client_ip)),
    client_port(move(_client_port)),
    is_request(true),
    response_content_encoding(default_response_content_encoding)
{
}

HttpTransactionData::HttpTransactionData()
        :
    HttpTransactionData::HttpTransactionData(
        "",
        "GET",
        "",
        "",
        IPAddr(),
        -1,
        "",
        "",
        IPAddr(),
        -1
    )
{}

void
HttpTransactionData::print(ostream &out_stream) const
{
    out_stream << http_proto << " " << method << endl;
    out_stream << "From: " << client_ip << ":" << client_port << endl;
    out_stream << "To: "
        << host_name
        << uri
        << " (listening on "
        << listening_ip
        << ":"
        << listening_port
        << ")"
        << endl;
}
