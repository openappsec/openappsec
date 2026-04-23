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

#include "response_parser.h"

#include <algorithm>
#include <string>
#include <vector>

using namespace std;

USE_DEBUG_FLAG(D_MESSAGING);

static const string CRLF = "\r\n";

static const map<HTTPStatusCode, string> status_code_to_string = {
    {HTTPStatusCode::NO_HTTP_RESPONSE,                      "0 - NO_HTTP_RESPONSE"                      },
    { HTTPStatusCode::HTTP_OK,                              "200 - HTTP_OK"                             },
    { HTTPStatusCode::HTTP_NO_CONTENT,                      "204 - HTTP_NO_CONTENT"                     },
    { HTTPStatusCode::HTTP_MULTI_STATUS,                    "207 - HTTP_MULTI_STATUS"                   },
    { HTTPStatusCode::HTTP_BAD_REQUEST,                     "400 - HTTP_BAD_REQUEST"                    },
    { HTTPStatusCode::HTTP_UNAUTHORIZED,                    "401 - HTTP_UNAUTHORIZED"                   },
    { HTTPStatusCode::HTTP_FORBIDDEN,                       "403 - HTTP_FORBIDDEN"                      },
    { HTTPStatusCode::HTTP_NOT_FOUND,                       "404 - HTTP_NOT_FOUND"                      },
    { HTTPStatusCode::HTTP_METHOD_NOT_ALLOWED,              "405 - HTTP_METHOD_NOT_ALLOWED"             },
    { HTTPStatusCode::HTTP_PROXY_AUTHENTICATION_REQUIRED,   "407 - HTTP_PROXY_AUTHENTICATION_REQUIRED"  },
    { HTTPStatusCode::HTTP_REQUEST_TIME_OUT,                "408 - HTTP_REQUEST_TIME_OUT"               },
    { HTTPStatusCode::HTTP_PAYLOAD_TOO_LARGE,               "413 - HTTP_PAYLOAD_TOO_LARGE"              },
    { HTTPStatusCode::HTTP_TOO_MANY_REQUESTS,               "429 - HTTP_TOO_MANY_REQUESTS"              },
    { HTTPStatusCode::HTTP_INTERNAL_SERVER_ERROR,           "500 - HTTP_INTERNAL_SERVER_ERROR"          },
    { HTTPStatusCode::HTTP_NOT_IMPLEMENTED,                 "501 - HTTP_NOT_IMPLEMENTED"                },
    { HTTPStatusCode::HTTP_BAD_GATEWAY,                     "502 - HTTP_BAD_GATEWAY"                    },
    { HTTPStatusCode::HTTP_SERVICE_UNABAILABLE,             "503 - HTTP_SERVICE_UNABAILABLE"            },
    { HTTPStatusCode::HTTP_GATEWAY_TIMEOUT,                 "504 - HTTP_GATEWAY_TIMEOUT"                },
    { HTTPStatusCode::HTTP_VERSION_NOT_SUPPORTED,           "505 - HTTP_VERSION_NOT_SUPPORTED"          },
    { HTTPStatusCode::HTTP_VARIANT_ALSO_NEGOTIATES,         "506 - HTTP_VARIANT_ALSO_NEGOTIATES"        },
    { HTTPStatusCode::HTTP_INSUFFICIENT_STORAGE,            "507 - HTTP_INSUFFICIENT_STORAGE"           },
    { HTTPStatusCode::HTTP_LOOP_DETECTED,                   "508 - HTTP_LOOP_DETECTED"                  },
    { HTTPStatusCode::HTTP_NOT_EXTENDED,                    "510 - HTTP_NOT_EXTENDED"                   },
    { HTTPStatusCode::HTTP_NETWORK_AUTHENTICATION_REQUIRED, "511 - HTTP_NETWORK_AUTHENTICATION_REQUIRED"},
    { HTTPStatusCode::HTTP_UNKNOWN,                         "-1 - HTTP_UNKNOWN"                         },
    { HTTPStatusCode::HTTP_SUSPEND,                         "-2 - HTTP_SUSPEND"                         }
};

static const map<int, HTTPStatusCode> num_to_status_code = {
    {200,  HTTPStatusCode::HTTP_OK                             },
    { 204, HTTPStatusCode::HTTP_NO_CONTENT                     },
    { 207, HTTPStatusCode::HTTP_MULTI_STATUS                   },
    { 400, HTTPStatusCode::HTTP_BAD_REQUEST                    },
    { 401, HTTPStatusCode::HTTP_UNAUTHORIZED                   },
    { 403, HTTPStatusCode::HTTP_FORBIDDEN                      },
    { 404, HTTPStatusCode::HTTP_NOT_FOUND                      },
    { 405, HTTPStatusCode::HTTP_METHOD_NOT_ALLOWED             },
    { 407, HTTPStatusCode::HTTP_PROXY_AUTHENTICATION_REQUIRED  },
    { 408, HTTPStatusCode::HTTP_REQUEST_TIME_OUT               },
    { 413, HTTPStatusCode::HTTP_PAYLOAD_TOO_LARGE              },
    { 429, HTTPStatusCode::HTTP_TOO_MANY_REQUESTS              },
    { 500, HTTPStatusCode::HTTP_INTERNAL_SERVER_ERROR          },
    { 501, HTTPStatusCode::HTTP_NOT_IMPLEMENTED                },
    { 502, HTTPStatusCode::HTTP_BAD_GATEWAY                    },
    { 503, HTTPStatusCode::HTTP_SERVICE_UNABAILABLE            },
    { 504, HTTPStatusCode::HTTP_GATEWAY_TIMEOUT                },
    { 505, HTTPStatusCode::HTTP_VERSION_NOT_SUPPORTED          },
    { 506, HTTPStatusCode::HTTP_VARIANT_ALSO_NEGOTIATES        },
    { 507, HTTPStatusCode::HTTP_INSUFFICIENT_STORAGE           },
    { 508, HTTPStatusCode::HTTP_LOOP_DETECTED                  },
    { 510, HTTPStatusCode::HTTP_NOT_EXTENDED                   },
    { 511, HTTPStatusCode::HTTP_NETWORK_AUTHENTICATION_REQUIRED}
};

const string &
HTTPResponse::getBody() const
{
    return body;
}

HTTPStatusCode
HTTPResponse::getHTTPStatusCode() const
{
    return status_code;
}

string
HTTPResponse::toString() const
{
    auto code = status_code_to_string.find(status_code);
    if (code == status_code_to_string.end()) {
        dbgAssertOpt(code != status_code_to_string.end())
            << AlertInfo(AlertTeam::CORE, "messaging i/s")
            << "Unknown status code "
            << int(status_code);
        return "[Status-code]: 500 - HTTP_INTERNAL_SERVER_ERROR, [Body]: " + (body.empty() ? "{}" : body);
    }

    return "[Status-code]: " + code->second + ", [Body]: " + (body.empty() ? "{}" : body);
}

Maybe<string>
HTTPResponse::getHeaderVal(const string &header_key)
{
    auto header = headers.find(header_key);
    if (header == headers.end()) {
        return genError("Header \'" + header_key + "\' not found.");
    }
    return header->second;
}

Maybe<HTTPResponse>
HTTPResponseParser::parseData(const string &data, bool is_connect)
{
    if (data.empty()) return genError("Data is empty");
    raw_response += data;

    if (!status_code.ok()) {
        if (!parseStatusLine()) return genError("Failed to parse the status line. Error: " + status_code.getErr());
    }

    if (!headers.ok()) {
        if (!handleHeaders()) return genError("Failed to parse the headers. Error: " + headers.getErr());
    }

    if (!handleBody(is_connect)) return genError("Response not ready!");

    return HTTPResponse(status_code.unpack(), body, headers.unpack());
}

static string
strip(const string &str)
{
    string res;
    for (auto ch : str) {
        if (!isspace(ch)) res += tolower(ch);
    }
    return res;
}

bool
HTTPResponseParser::handleHeaders()
{
    stringstream ss(raw_response);
    unordered_map<string, string> header_map;

    while (true) {
        string header;
        getline(ss, header);

        if (header.empty()) {
            headers = genError("Headers not complete");
            return false;
        }

        if (header == "\r") {
            headers = header_map;
            ss.sync();
            raw_response = raw_response.substr(ss.tellg());
            return true;
        }

        auto colon_index = header.find_first_of(":");
        if (colon_index == string::npos) {
            // The only case where not finding a colon isn't an error is if we run out of data
            error = !ss.str().empty();
            headers = genError(error ? "Invalid headers: " + header : "Did not reach end of headers");
            return false;
        }

        auto header_key = header.substr(0, colon_index);
        auto header_val = header.substr(colon_index + 2);
        header_map[strip(header_key)] = strip(header_val);
    }
}

Maybe<string>
HTTPResponseParser::getHeaderVal(const string &header_key)
{
    auto headers_map = headers.unpack();
    auto header = headers_map.find(header_key);
    if (header == headers_map.end()) {
        return genError("Header \'" + header_key + "\' not found.");
    }
    return header->second;
}

bool
HTTPResponseParser::handleBody(bool is_connect)
{
    if (*status_code == HTTPStatusCode::HTTP_OK && is_connect) return true;

    if (*status_code == HTTPStatusCode::HTTP_NO_CONTENT) return raw_response.empty();

    auto content_length = getHeaderVal("content-length");
    if (content_length.ok()) {
        size_t body_length;
        try {
            body_length = stoi(content_length.unpack());
        } catch (const exception &err) {
            return false;
        }

        body += raw_response;
        raw_response.clear();
        return body.size() == body_length;
    }

    auto transfer_encoding = getHeaderVal("transfer-encoding");
    if (transfer_encoding.ok() && *transfer_encoding == "chunked") return getChunkedResponse();

    dbgError(D_MESSAGING) << "Response has neither content-lenght nor chunked encoded";
    return false;
}

bool
HTTPResponseParser::getChunkedResponse()
{
    if (!isLegalChunkedResponse(raw_response)) return false;

    size_t chunk_size = 0;

    for (auto line_end = raw_response.find(CRLF); line_end != string::npos; line_end = raw_response.find(CRLF)) {
        string line = raw_response.substr(0, line_end);
        try {
            chunk_size = stoi(line, nullptr, 16);
        } catch (const exception &) {
            dbgWarning(D_MESSAGING) << "Failed to convert chunk length to a number. Line: " << line;
            return false;
        }

        if (line_end + 2 + chunk_size > raw_response.length()) {
            dbgWarning(D_MESSAGING) << "Invalid chunked data structure - chunk-size is bigger than chunk-data";
            return false;
        }
        string chunk_body = raw_response.substr(line_end + 2, chunk_size);
        raw_response = raw_response.substr(line_end + 2 + chunk_size);

        if (raw_response.find(CRLF) != 0) {
            dbgWarning(D_MESSAGING) << "Invalid chunked data structure - chunk-data missing final CRLF sequence";
            return false;
        }
        raw_response = raw_response.substr(2);

        body += chunk_body;
    }

    if (chunk_size != 0) {
        dbgDebug(D_MESSAGING) << "Invalid chunked data structure - last-chunk of the body is not sized 0";
        return false;
    }
    return true;
}

bool
HTTPResponseParser::isLegalChunkedResponse(const string &res)
{
    auto end_of_data = res.find("0\r\n\r\n");
    return end_of_data != string::npos && res.length() == end_of_data + 5;
}

bool
HTTPResponseParser::parseStatusLine()
{
    auto end_of_first_line = raw_response.find(CRLF);
    if (end_of_first_line == string::npos) {
        status_code = genError("No Status Line was received.");
        return false;
    }

    auto status_line = raw_response.substr(0, end_of_first_line);
    raw_response = raw_response.substr(end_of_first_line + 2);

    // Also status text can be supported at the future.
    if (status_line.find("HTTP/1.") == string::npos) {
        status_code = genError("Status code not found.");
        error = true;
        return false;
    }

    int status_num;
    try {
        status_num = stoi(status_line.substr(9, 3));
    } catch (const exception &err) {
        status_code = genError("Failed to convert status code to a number. Status code: " + status_line.substr(9, 3));
        error = true;
        return false;
    }

    auto status = num_to_status_code.find(status_num);
    if (status != num_to_status_code.end()) {
        status_code = status->second;
    } else {
        dbgWarning(D_MESSAGING) << "Unknown HTTP status code: " << status_num;
        status_code = HTTPStatusCode::HTTP_UNKNOWN;
    }
    return true;
}
