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

#include "url_parser.h"

#include <sstream>

#include "singleton.h"
#include "common.h"
#include "maybe_res.h"

using namespace std;

USE_DEBUG_FLAG(D_ORCHESTRATOR);

ostream &
operator<<(ostream &os, const URLParser &url)
{
    return os << url.toString();
}

ostream &
operator<<(ostream &os, const URLProtocol &protocol)
{
    switch(protocol) {
        case URLProtocol::HTTP: {
            return os << "http://";
        }
        case URLProtocol::HTTPS: {
            return os << "https://";
        }
        case URLProtocol::LOCAL_FILE: {
            return os << "file://";
        }
        default: {
            dbgAssert(false) << "Unsupported protocol " << static_cast<unsigned int>(protocol);
            return os;
        }
    }
}

URLParser::URLParser(const string &url)
{
    parseURL(url);
}

Maybe<string>
URLParser::getBaseURL() const
{
    if (base_url.empty()) return genError("Error: URL not found");
    return base_url;
}

void
URLParser::parseURL(const string &url)
{
    string url_builder;
    protocol = parseProtocol(url);
    switch(protocol) {
        case URLProtocol::HTTP: {
            dbgDebug(D_ORCHESTRATOR) << "Protocol of " << url << " is HTTP";
            port = "80";
            over_ssl = false;
            url_builder = url.substr(7);
            break;
        }
        case URLProtocol::HTTPS: {
            dbgDebug(D_ORCHESTRATOR) << "Protocol of " << url << " is HTTPS";
            if (url.find("https://") != string::npos) {
                url_builder = url.substr(8);
            } else {
                url_builder = url;
            }
            port = "443";
            over_ssl = true;
            break;
        }
        case URLProtocol::LOCAL_FILE: {
            dbgDebug(D_ORCHESTRATOR) << "Protocol of " << url << " is local file.";
            base_url = url.substr(7);
            return;
        }
        default: {
            dbgAssert(false) << "URL protocol is not supported. Protocol: " << static_cast<unsigned int>(protocol);
            return;
        }
    }

    size_t link_extension_position = url_builder.find_first_of("/");
    if (link_extension_position != string::npos) {
        query = url_builder.substr(link_extension_position);
        url_builder = url_builder.substr(0, link_extension_position);
    }

    size_t port_position = url_builder.find_last_of(":");
    string link = url_builder;
    if (port_position != string::npos) {
        link = url_builder.substr(0, port_position);
        port = url_builder.substr(port_position + 1);
    }

    if (!link.empty()) base_url = link;
    if (!query.empty() && query.back() == '/') query.pop_back();
}

URLProtocol
URLParser::parseProtocol(const string &url) const
{
    if (url.find("http://") != string::npos) {
        return URLProtocol::HTTP;
    } else if (url.find("https://") != string::npos) {
        return URLProtocol::HTTPS;
    } else if (url.find("file://") != string::npos){
        return URLProtocol::LOCAL_FILE;
    }

    dbgWarning(D_ORCHESTRATOR)
        << "No supported protocol in URL, HTTPS default value is used. URL: " << url;
    return URLProtocol::HTTPS;
}

void
URLParser::setQuery(const string &new_query)
{
    query = new_query;
}

string
URLParser::toString() const
{
    stringstream s_build;
    s_build << protocol << base_url << query << ":" << port;
    return s_build.str();
}
