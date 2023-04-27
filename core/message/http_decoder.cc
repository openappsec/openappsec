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

#include "http_decoder.h"

using namespace std;

USE_DEBUG_FLAG(D_COMMUNICATION);

const map<HTTPStatusCode, string> errorCodeMapper = {
    { HTTPStatusCode::HTTP_OK,                              "OK" },
    { HTTPStatusCode::HTTP_NO_CONTENT,                      "No Content" },
    { HTTPStatusCode::HTTP_MULTI_STATUS,                    "Multi Status" },
    { HTTPStatusCode::HTTP_BAD_REQUEST,                     "Bad Request" },
    { HTTPStatusCode::HTTP_UNAUTHORIZED,                    "Unauthorized" },
    { HTTPStatusCode::HTTP_FORBIDDEN,                       "Forbidden" },
    { HTTPStatusCode::HTTP_NOT_FOUND,                       "Not Found" },
    { HTTPStatusCode::HTTP_METHOD_NOT_ALLOWED,              "Method Not Allowed" },
    { HTTPStatusCode::HTTP_PROXY_AUTHENTICATION_REQUIRED,   "Proxy Authentication Required"},
    { HTTPStatusCode::HTTP_REQUEST_TIME_OUT,                "Request Timeout" },
    { HTTPStatusCode::HTTP_PAYLOAD_TOO_LARGE,               "Payload Too Large" },
    { HTTPStatusCode::HTTP_INTERNAL_SERVER_ERROR,           "Internal Server Error" },
    { HTTPStatusCode::HTTP_NOT_IMPLEMENTED,                 "Not Implemented" },
    { HTTPStatusCode::HTTP_BAD_GATEWAY,                     "Bad Gateway" },
    { HTTPStatusCode::HTTP_SERVICE_UNABAILABLE,             "Service Unavailable" },
    { HTTPStatusCode::HTTP_GATEWAY_TIMEOUT,                 "Gateway Timeout" },
    { HTTPStatusCode::HTTP_UNKNOWN,                         "Not supported." }
};

ostream &
operator<<(ostream &os, const HTTPResponse::BadRequestResponse &response)
{
    return os
        << "[Message]: "      << response.getMsg() << " "
        << "[Message-ID]: "   << response.getID();
}

void
HTTPResponse::BadRequestResponse::serialize(cereal::JSONInputArchive &ar)
{
    ar(cereal::make_nvp("message",      message));
    ar(cereal::make_nvp("messageId",    message_id));
}

HTTPDecoder::HTTPDecoder(I_Messaging::Method _method)
        :
    method(_method),
    status_code(genError("Not received")),
    headers(genError("Not received")),
    response(),
    body()
{
}

Maybe<HTTPResponse>
HTTPDecoder::decodeBytes(const string &data)
{
    connection_is_closed = data.empty();
    response += data;
    if (!status_code.ok()) status_code = parseStatusLine();
    if (!status_code.ok()) genError("Failed to parse the status line");
    if (!headers.ok()) headers = handleHeaders();

    if (handleBody()) return HTTPResponse(status_code.unpack(), move(body));

    return genError("Response not ready!");
}

Maybe<HTTPHeaders>
HTTPDecoder::handleHeaders()
{
    auto end_of_headers = response.find("\r\n\r\n");
    if (end_of_headers == string::npos) return genError("Headers data not found.");
    end_of_headers += 4;

    auto headers = response.substr(0, end_of_headers);
    response = response.substr(end_of_headers);

    return HTTPHeaders::createHTTPHeader(headers);
}

bool
HTTPDecoder::handleBody()
{
    if (!status_code.ok()) return false;

    if (status_code.unpack() == HTTPStatusCode::HTTP_OK) {
        if (method == I_Messaging::Method::CONNECT) return true;
    }

    if (!headers.ok()) return false;

    body_size += response.size();
    if (status_code.unpack() == HTTPStatusCode::HTTP_NO_CONTENT) {
        if (body_size != 0) {
            dbgDebug(D_COMMUNICATION) << "Invalid body.";
            return false;
        }
        return true;
    }

    auto unpacked_headers = headers.unpack();
    auto content_length = unpacked_headers.getHeaderVal("content-length");
    if (content_length.ok()) {
        size_t body_length;
        try{
            body_length = stoi(content_length.unpack());
        } catch (const exception& err) {
            dbgDebug(D_COMMUNICATION)
                << "Failed to convert body length to a number. Body length: "
                << content_length.unpack();
            return false;
        }
        body += response;
        response.clear();
        return body_size == body_length;
    }

    auto maybe_transfer_encoding = unpacked_headers.getHeaderVal("transfer-encoding");
    if (maybe_transfer_encoding.ok()) {
        auto transfer_encoding_type = maybe_transfer_encoding.unpack();
        if (transfer_encoding_type == "chunked") return getChunkedResponse();
    }

    auto connection_header = unpacked_headers.getHeaderVal("connection");
    if (connection_header.ok()) {
        if (connection_header.unpack() == "close"  && connection_is_closed) {
            return true;
        }
    }
    dbgDebug(D_COMMUNICATION) << "Transfer-Encoding method isn't supported.";
    return false;
}

bool
HTTPDecoder::getChunkedResponse()
{
    if(!isLegalChunkedResponse(response)) return false;

    string line;
    string res = response;
    string chunk_body = "";
    string CRLF = "\r\n";
    size_t chunk_size = 0;

    for (auto end_of_line = res.find(CRLF); end_of_line != string::npos; end_of_line = res.find(CRLF)) {
        line = res.substr(0, end_of_line);
        try {
            chunk_size = stoi(line, nullptr, 16);
        } catch (const exception& err) {
            dbgDebug(D_COMMUNICATION) << "Failed to convert chunk length to a number. Line: " << line;
            return false;
        }

        if (end_of_line + 2 + chunk_size > res.length()) {
            dbgDebug(D_COMMUNICATION) << "Invalid chunked data structure - chunk-size is bigger than chunk-data";
            return false;
        }
        chunk_body = res.substr(end_of_line + 2, chunk_size);
        res = res.substr(end_of_line + 2 + chunk_size);

        if (res.find(CRLF) != 0) {
            dbgDebug(D_COMMUNICATION) << "Invalid chunked data structure - chunk-data missing final CRLF sequence";
            return false;
        }
        res = res.substr(2);
        body += chunk_body;
    }

    if (chunk_size != 0) {
        dbgDebug(D_COMMUNICATION) << "Invalid chunked data structure - last-chunk of the body is not sized 0";
        return false;
    }
    return true;
}

bool
HTTPDecoder::isLegalChunkedResponse(const string &res)
{
    auto end_of_data = res.find("0\r\n\r\n");
    return end_of_data != string::npos && res.length() == end_of_data + 5;
}

Maybe<HTTPStatusCode>
HTTPDecoder::parseStatusLine()
{
    auto end_of_first_line = response.find("\r\n");
    if (end_of_first_line == string::npos) return genError("No Status Line was received.");
    auto status = response.substr(0, end_of_first_line);
    // Removing the status
    response = response.substr(end_of_first_line + 2);
    // Also status text can be supported at the future.
    if (status.find("HTTP/1.") != string::npos) {
        int status_num;
        try {
            status_num = stoi(status.substr(9, 3));
        } catch (const exception& err) {
            return genError("Failed to convert status code to a number. Status code: " + status.substr(9, 3));
        }
        switch (status_num)
        {
            case 200: {
                return HTTPStatusCode::HTTP_OK;
            }
            case 204: {
                return HTTPStatusCode::HTTP_NO_CONTENT;
            }
            case 207: {
                return HTTPStatusCode::HTTP_MULTI_STATUS;
            }
            case 400: {
                return HTTPStatusCode::HTTP_BAD_REQUEST;
            }
            case 401: {
                return HTTPStatusCode::HTTP_UNAUTHORIZED;
            }
            case 403: {
                return HTTPStatusCode::HTTP_FORBIDDEN;
            }
            case 404: {
                return HTTPStatusCode::HTTP_NOT_FOUND;
            }
            case 405: {
                return HTTPStatusCode::HTTP_METHOD_NOT_ALLOWED;
            }
            case 408: {
                return HTTPStatusCode::HTTP_REQUEST_TIME_OUT;
            }
            case 413: {
                return HTTPStatusCode::HTTP_PAYLOAD_TOO_LARGE;
            }
            case 500: {
                return HTTPStatusCode::HTTP_INTERNAL_SERVER_ERROR;
            }
            case 501: {
                return HTTPStatusCode::HTTP_NOT_IMPLEMENTED;
            }
            case 502: {
                return HTTPStatusCode::HTTP_BAD_GATEWAY;
            }
            case 503: {
                return HTTPStatusCode::HTTP_SERVICE_UNABAILABLE;
            }
            case 504: {
                return HTTPStatusCode::HTTP_GATEWAY_TIMEOUT;
            }
            default: {
                dbgWarning(D_COMMUNICATION) << "Unknown HTTP status code: " << status_num;
                return HTTPStatusCode::HTTP_UNKNOWN;
            }
        }
    }
    return genError("Status code not found.");
}

HTTPResponse::HTTPResponse(const HTTPStatusCode _status_code, const string &&_body)
        :
    status_code(_status_code),
    body(move(_body))
{
}

Maybe<string>
HTTPResponse::getResponse() const
{
    if (status_code == HTTPStatusCode::HTTP_OK || status_code == HTTPStatusCode::HTTP_NO_CONTENT) return body;

    try {
        stringstream in;
        in << body;
        cereal::JSONInputArchive in_ar(in);
        BadRequestResponse response_details;
        response_details.serialize(in_ar);
        dbgWarning(D_COMMUNICATION) << "Response details: " << response_details;
    } catch (...) {}

    string status_code_str = to_string(static_cast<int>(status_code));
    auto status_code_message = errorCodeMapper.find(status_code);
    if(status_code_message == errorCodeMapper.end()) {
        dbgWarning(D_COMMUNICATION) << "Failed to parse HTTP status code message. Status code: " << status_code_str;
        return genError(string("Request failed, Status code: ") + status_code_str);
    }
    return genError(string("Request failed, Error: ") + status_code_str + " " + status_code_message->second);
}
