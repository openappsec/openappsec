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

#ifndef __NGINX_PARSER_H__
#define __NGINX_PARSER_H__

#include <vector>

#include "compression_utils.h"
#include "nginx_attachment_common.h"
#include "http_transaction_common.h"
#include "http_inspection_events.h"
#include "i_encryptor.h"

class NginxParser : Singleton::Consume<I_Encryptor>
{
public:
    static Maybe<HttpTransactionData> parseStartTrasaction(const Buffer &data);
    static Maybe<ResponseCode> parseResponseCode(const Buffer &data);
    static Maybe<uint64_t> parseContentLength(const Buffer &data);
    static Maybe<std::vector<HttpHeader>> parseRequestHeaders(const Buffer &data);
    static Maybe<std::vector<HttpHeader>> parseResponseHeaders(const Buffer &data);
    static Maybe<HttpBody> parseRequestBody(const Buffer &data);
    static Maybe<HttpBody> parseResponseBody(const Buffer &raw_response_body, CompressionStream *compression_stream);
    static Maybe<CompressionType> parseContentEncoding(const std::vector<HttpHeader> &headers);

    static Buffer tenant_header_key;

private:
    static Maybe<CompressionType> convertToContentEncoding(const Buffer &content_encoding_header_value);

    static std::map<Buffer, CompressionType> content_encodings;
};

#endif // __NGINX_PARSER_H__
