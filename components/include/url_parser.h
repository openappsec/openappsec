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

#ifndef __URL_PARSER_H__
#define __URL_PARSER_H__

#include "orchestration_tools.h"

#include <string>
#include <ostream>

enum class URLProtocol
{
    HTTP,
    HTTPS,
    LOCAL_FILE
};

class URLParser
{
public:
    URLParser(const std::string &url);

    Maybe<std::string> getBaseURL() const;
    bool isOverSSL() const { return over_ssl; }
    std::string getPort() const { return port; }
    std::string getQuery() const { return query; }
    URLProtocol getProtocol() const { return protocol; }
    std::string toString() const;
    void setQuery(const std::string &new_query);

private:
    void parseURL(const std::string &url);
    URLProtocol parseProtocol(const std::string &url) const;

    bool over_ssl;
    std::string base_url;
    std::string port;
    std::string query;
    URLProtocol protocol;
};

std::ostream & operator<<(std::ostream &os, const URLParser &url);
std::ostream & operator<<(std::ostream &os, const URLProtocol &protocol);

#endif // __URL_PARSER_H__
