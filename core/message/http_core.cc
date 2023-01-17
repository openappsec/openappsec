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

#include "messaging/http_core.h"

#include <algorithm>
#include <iostream>

using namespace std;

USE_DEBUG_FLAG(D_HTTP_REQUEST);

HTTPHeaders::HTTPHeaders(const string &http_data)
{
    static const string end_of_headers = "\r\n\r\n";
    if (http_data.find(end_of_headers) == string::npos) throw invalid_argument("Invalid headers");

    insertHeaders(http_data);
}

void
HTTPHeaders::insertHeader(const string &_header_key, const string &_header_val)
{
    string header_key = _header_key;
    string header_val = _header_val;
    // Removing \n from end of the value.
    if (header_val.back() == '\n') header_val.pop_back();
    // Removing \r from end of the value.
    if (header_val.back() == '\r') header_val.pop_back();
    // Transforming all the keys to lower case.
    // RFC 2616 - "Hypertext Transfer Protocol -- HTTP/1.1", Section 4.2, "Message Headers":
    // Each header field consists of a name followed by a colon (":") and the field value.
    // Field names are case-insensitive.
    transform(header_key.begin(), header_key.end(), header_key.begin(), ::tolower);
    dbgTrace(D_HTTP_REQUEST) << "Added HTTP header :'" << header_key << ": " << header_val << "'";
    headers[header_key] = move(header_val);
}

void
HTTPHeaders::insertHeader(const string &header)
{
    if (header.empty()) return;

    auto colon_index = header.find_first_of(":");

    if (colon_index == string::npos) throw invalid_argument(header + " is invalid headers");

    auto header_key = header.substr(0, colon_index);
    // Including characters of colon and space.
    auto header_val = header.substr(colon_index + 2);
    insertHeader(header_key, header_val);
}

void
HTTPHeaders::insertHeaders(const string &headers)
{
    string header;
    stringstream ss(headers);
    while (getline(ss, header) && header != "\r") { insertHeader(header); }
}

Maybe<string>
HTTPHeaders::getHeaderVal(const string &header_key)
{
    auto header = headers.find(header_key);
    if (header == headers.end()) return genError("Header not found.");
    return header->second;
}

string
HTTPHeaders::toString() const
{
    string headers_as_string;
    for_each(
        headers.begin(),
        headers.end(),
        [&headers_as_string] (const pair<string, string> &header)
        {
            headers_as_string += header.first + ": " + header.second + "\r\n";
        }
    );
    return headers_as_string + "\r\n";
}


Maybe<HTTPHeaders>
HTTPHeaders::createHTTPHeader(const string &http_data)
{
    try {
        return move(HTTPHeaders(http_data));
    } catch(const std::exception& e) {
        return genError(e.what());
    }
    dbgAssert(false) << "Failed to create HTTP headers";
    // To justify the compiler
    return HTTPHeaders();
}
