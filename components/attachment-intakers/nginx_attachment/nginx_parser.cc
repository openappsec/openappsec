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

#include "nginx_parser.h"

#include "config.h"
#include <algorithm>
#include "connkey.h"
#include "compression_utils.h"
#include "nginx_attachment.h"
#include "nginx_attachment_opaque.h"
#include "user_identifiers_config.h"
#include "debug.h"

using namespace std;

USE_DEBUG_FLAG(D_NGINX_ATTACHMENT_PARSER);

Buffer NginxParser::tenant_header_key = Buffer();
static const Buffer proxy_ip_header_key("X-Forwarded-For", 15, Buffer::MemoryType::STATIC);
static const Buffer source_ip("sourceip", 8, Buffer::MemoryType::STATIC);

map<Buffer, CompressionType> NginxParser::content_encodings = {
    {Buffer("identity"), CompressionType::NO_COMPRESSION},
    {Buffer("gzip"), CompressionType::GZIP},
    {Buffer("deflate"), CompressionType::ZLIB}
};

Maybe<HttpTransactionData>
NginxParser::parseStartTrasaction(const Buffer &data)
{
    return HttpTransactionData::createTransactionData(data);
}

Maybe<ResponseCode>
NginxParser::parseResponseCode(const Buffer &data)
{
    if (data.size() < sizeof(uint16_t)) {
        dbgWarning(D_NGINX_ATTACHMENT_PARSER) << "Failed to get response code";
        return genError("Response code size is lower than uint16_t");
    }

    return reinterpret_cast<const uint16_t *>(data.data())[0];
}

Maybe<uint64_t>
NginxParser::parseContentLength(const Buffer &data)
{
    if (data.size() < sizeof(uint64_t)) {
        dbgWarning(D_NGINX_ATTACHMENT_PARSER)
            << "Failed to get content length";
        return genError("Content length size is lower than uint64");
    }
    return **data.getTypePtr<uint64_t>(0);
}

Maybe<Buffer>
genHeaderPart(const Buffer &raw_data, uint16_t &cur_pos)
{
    if (cur_pos >= raw_data.size()) return genError("Current header data possession is after header part end");

    auto value = raw_data.getTypePtr<uint16_t>(cur_pos);

    if (!value.ok()) {
        return genError("Failed to get header part size: " + value.getErr());
    }

    uint16_t part_len = *(value.unpack());
    cur_pos += sizeof(uint16_t);
    if (cur_pos + part_len > raw_data.size()) return genError("Header data extends beyond current buffer");

    const u_char *part_data = raw_data.data();
    Buffer header_part(part_data + cur_pos, part_len, Buffer::MemoryType::VOLATILE);

    cur_pos += part_len;

    return header_part;
}

Maybe<vector<HttpHeader>>
genHeaders(const Buffer &raw_data)
{
    dbgFlow(D_NGINX_ATTACHMENT_PARSER) << "Generating headers";

    uint16_t cur_pos = 0;
    auto is_last_header_data = raw_data.getTypePtr<uint8_t>(cur_pos);
    if (!is_last_header_data.ok()) {
        return genError("Failed to get 'is last header' value: " + is_last_header_data.getErr());
    }

    bool is_last_header = *(is_last_header_data.unpack()) == 1;
    dbgTrace(D_NGINX_ATTACHMENT_PARSER)
        << "Current header bulk "
        << (is_last_header ? "contains " : "does not contain ")
        << "last header";

    cur_pos += sizeof(uint8_t);
    auto part_count = raw_data.getTypePtr<uint8_t>(cur_pos);
    if (!part_count.ok()) {
        return genError("Failed to get part count value: " + part_count.getErr());
    }
    dbgTrace(D_NGINX_ATTACHMENT_PARSER) << "Current header bulk index: " << to_string(*(part_count.unpack()));

    static const string key_val_desc[] = {"key", "value"};
    Maybe<Buffer> header[2] = {Buffer(), Buffer()};
    vector<HttpHeader> headers;

    cur_pos += sizeof(uint8_t);
    uint8_t cur_part = *(part_count.unpack());
    while (cur_pos < raw_data.size()) {
        for (int i = 0 ; i < 2 ; i ++) {
            dbgTrace(D_NGINX_ATTACHMENT_PARSER)
                << "Generating"
                << (is_last_header ? " last " : " ")
                << "header's "
                << key_val_desc[i];

            header[i] = genHeaderPart(raw_data, cur_pos);
            if (!header[i].ok()) {
                return genError("Failed to generate header's " + key_val_desc[i] + ":" + header[i].getErr());
            }

            dbgTrace(D_NGINX_ATTACHMENT_PARSER)
                << "Successfully generated header part. Header part type:"
                << key_val_desc[i]
                << ", data: '"
                << dumpHex(header[i].unpack())
                << "', size: "
                << header[i].unpack().size();
        }

        // is_last_header in bulk relates only to the last header in the bulk.
        headers.emplace_back(
            header[0].unpack(),
            header[1].unpack(),
            cur_part,
            cur_pos >= raw_data.size() && is_last_header
        );

        dbgTrace(D_NGINX_ATTACHMENT_PARSER) << "end pos: " << cur_pos;
        cur_part++;
    }
    return headers;
}

static vector<string>
getActivetenantAndProfile(const string &str, const string &deli = ",")
{
    vector<string> elems;
    elems.reserve(2);

    int start = 0;
    int end = str.find(deli);
    while (end != -1) {
        elems.push_back(str.substr(start, end - start));
        start = end + deli.size();
        end = str.find(deli, start);
    }

    elems.push_back(str.substr(start, end - start));

    if (elems.size() == 1) {
        elems.push_back("");
    }

    return elems;
}

Maybe<vector<HttpHeader>>
NginxParser::parseRequestHeaders(const Buffer &data)
{
    auto parsed_headers = genHeaders(data);
    if (!parsed_headers.ok()) return parsed_headers.passErr();

    auto i_transaction_table = Singleton::Consume<I_TableSpecific<SessionID>>::by<NginxAttachment>();

    for (const HttpHeader &header : *parsed_headers) {
        auto source_identifiers = getConfigurationWithDefault<UsersAllIdentifiersConfig>(
            UsersAllIdentifiersConfig(),
            "rulebase",
            "usersIdentifiers"
        );
        source_identifiers.parseRequestHeaders(header);

        NginxAttachmentOpaque &opaque = i_transaction_table->getState<NginxAttachmentOpaque>();
        opaque.addToSavedData(
            HttpTransactionData::req_headers,
            static_cast<string>(header.getKey()) + ": " + static_cast<string>(header.getValue()) + "\r\n"
        );

        if (NginxParser::tenant_header_key == header.getKey()) {
            dbgDebug(D_NGINX_ATTACHMENT_PARSER)
                << "Identified active tenant header. Key: "
                << dumpHex(header.getKey())
                << ", Value: "
                << dumpHex(header.getValue());

            auto active_tenant_and_profile = getActivetenantAndProfile(header.getValue());
            opaque.setSessionTenantAndProfile(active_tenant_and_profile[0], active_tenant_and_profile[1]);
        } else if (proxy_ip_header_key == header.getKey()) {
            source_identifiers.setXFFValuesToOpaqueCtx(header, UsersAllIdentifiersConfig::ExtractType::PROXYIP);
        }
    }

    return parsed_headers;
}

Maybe<vector<HttpHeader>>
NginxParser::parseResponseHeaders(const Buffer &data)
{
    return genHeaders(data);
}

Maybe<Buffer>
decompressBuffer(CompressionStream *compression_stream, const Buffer &compressed_buffer)
{
    if (compressed_buffer.size() == 0) return Buffer();

    auto compression_result = decompressData(compression_stream, compressed_buffer.size(), compressed_buffer.data());
    if (!compression_result.ok) return genError("Failed to decompress data");

    if (compression_result.output == nullptr) return Buffer();;

    Buffer decompressed_buffer(
        compression_result.output,
        compression_result.num_output_bytes,
        Buffer::MemoryType::OWNED
    );
    free(compression_result.output);

    return decompressed_buffer;
}

Maybe<Buffer>
parseCompressedHttpBodyData(CompressionStream *compression_stream, const Buffer &body_raw_data)
{
    if (compression_stream == nullptr) return genError("Cannot decompress body without compression stream");

    Maybe<Buffer> decompressed_buffer_maybe = decompressBuffer(compression_stream, body_raw_data);
    if (!decompressed_buffer_maybe.ok()) {
        return genError("Failed to decompress buffer. Error: " + decompressed_buffer_maybe.getErr());
    }

    return decompressed_buffer_maybe.unpack();
}

Maybe<HttpBody>
genBody(const Buffer &raw_response_body, CompressionStream *compression_stream = nullptr)
{
    uint offset = 0;
    auto is_last_part_maybe = raw_response_body.getTypePtr<uint8_t>(offset);
    if (!is_last_part_maybe.ok()) {
        return genError("Failed to get 'is last part' value: " + is_last_part_maybe.getErr());
    }
    bool is_last_part = *is_last_part_maybe.unpack();

    offset += sizeof(uint8_t);
    auto part_count_maybe = raw_response_body.getTypePtr<uint8_t>(offset);
    if (!part_count_maybe.ok()) {
        return genError("Failed to get part count value: " + part_count_maybe.getErr());
    }
    uint8_t body_chunk_index = *part_count_maybe.unpack();

    offset += sizeof(uint8_t);
    Buffer body_raw_data(
        raw_response_body.data() + offset,
        raw_response_body.size() - offset,
        Buffer::MemoryType::VOLATILE
    );

    if (compression_stream == nullptr) {
        dbgTrace(D_NGINX_ATTACHMENT_PARSER) << "Successfully generated body chunk from non compressed buffer";
        return HttpBody(body_raw_data, is_last_part, body_chunk_index);
    }

    Maybe<Buffer> body_data_maybe = parseCompressedHttpBodyData(compression_stream, body_raw_data);
    if (!body_data_maybe.ok()) {
        dbgWarning(D_NGINX_ATTACHMENT_PARSER)
            << "Failed to decompress body chunk. Chunk index: "
            <<  to_string(body_chunk_index)
            << ", raw input size: "
            << body_raw_data.size();
        return genError("Failed to parse HTTP body data: " + body_data_maybe.getErr());
    }

    dbgTrace(D_NGINX_ATTACHMENT_PARSER)
        << "Successfully generated decompressed body chunk. Compressed original size: "
        << body_raw_data.size();

    return HttpBody(body_data_maybe.unpack(), is_last_part, body_chunk_index);
}

Maybe<HttpBody>
NginxParser::parseRequestBody(const Buffer &data)
{
    Maybe<HttpBody> body = genBody(data);
    if (!body.ok()) return genError("Failed to generate body from buffer: " + body.getErr());

    dbgTrace(D_NGINX_ATTACHMENT_PARSER)
        << "Successfully generated request body chunk. Chunk index: "
        <<  to_string(body.unpack().getBodyChunkIndex())
        << ", is last chunk: "
        << (body.unpack().isLastChunk() ? "true" : "false")
        << ", size: "
        <<  body.unpack().getData().size()
        << ", value: "
        << dumpHex(body.unpack().getData());

    auto i_transaction_table = Singleton::Consume<I_TableSpecific<SessionID>>::by<NginxAttachment>();
    auto &state = i_transaction_table->getState<NginxAttachmentOpaque>();
    state.setSavedData(HttpTransactionData::req_body, (*body).getData());

    return body;
}

Maybe<HttpBody>
NginxParser::parseResponseBody(const Buffer &raw_response_body, CompressionStream *compression_stream)
{
    Maybe<HttpBody> body = genBody(raw_response_body, compression_stream);
    if (!body.ok()) return genError("Failed to generate body from buffer: " + body.getErr());

    dbgTrace(D_NGINX_ATTACHMENT_PARSER)
        << "Successfully generated response body chunk. Chunk index: "
        <<  to_string(body.unpack().getBodyChunkIndex())
        << ", is last chunk: "
        << (body.unpack().isLastChunk() ? "true" : "false")
        << ", size: "
        <<  body.unpack().getData().size()
        << ", value: "
        << dumpHex(body.unpack().getData());;

    return body;
}

Maybe<CompressionType>
NginxParser::parseContentEncoding(const vector<HttpHeader> &headers)
{
    static const Buffer content_encoding_header_key("Content-Encoding");

    auto it = find_if(
        headers.begin(),
        headers.end(),
        [&] (const HttpHeader &http_header) { return http_header.getKey() == content_encoding_header_key; }
    );
    if (it == headers.end()) {
        dbgTrace(D_NGINX_ATTACHMENT_PARSER)
            << "Headers do not contain \"Content-Encoding\" header: "
            << "body is expected to be plain-text";

        return CompressionType::NO_COMPRESSION;
    }

    dbgTrace(D_NGINX_ATTACHMENT_PARSER)
        << "Found header with key \"Content-Encoding\". Value: "
        << dumpHex((*it).getValue());
    auto content_encoding_maybe = convertToContentEncoding((*it).getValue());
    if (!content_encoding_maybe.ok()) {
        return genError(
            "Failed to parse value of \"Content-Encoding\" header: " +
            content_encoding_maybe.getErr()
        );
    }
    dbgTrace(D_NGINX_ATTACHMENT_PARSER) << "Successfully parsed value of \"Content-Encoding\" header";

    return content_encoding_maybe.unpack();
}

Maybe<CompressionType>
NginxParser::convertToContentEncoding(const Buffer &content_encoding_header_value)
{
    if (content_encoding_header_value.contains(',')) {
        return genError("Multiple content encodings for a specific HTTP request/response body are not supported");
    }

    if (content_encodings.find(content_encoding_header_value) == content_encodings.end()) {
        return genError(
            "Unsupported or undefined \"Content-Encoding\" value: " +
            static_cast<string>(content_encoding_header_value)
        );
    }
    return content_encodings[content_encoding_header_value];
}
