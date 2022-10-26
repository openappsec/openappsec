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

#ifndef __USER_IDENTIFIERS_CONFIG_H__
#define __USER_IDENTIFIERS_CONFIG_H__

#include <vector>
#include <string>

#include "http_inspection_events.h"
#include "cereal/archives/json.hpp"

class UsersAllIdentifiersConfig
{
public:
    enum class ExtractType { SOURCEIDENTIFIER, PROXYIP};

    UsersAllIdentifiersConfig();
    void load(cereal::JSONInputArchive &ar);
    void parseRequestHeaders(const HttpHeader &header) const;
    std::vector<std::string> getHeaderValuesFromConfig(const std::string &header_key) const;
    void setXFFValuesToOpaqueCtx(const HttpHeader &header, ExtractType type) const;

private:
    class UsersIdentifiersConfig
    {
    public:
        UsersIdentifiersConfig();
        UsersIdentifiersConfig(const std::string &identifier);
        bool operator==(const UsersIdentifiersConfig &other) const;
        void load(cereal::JSONInputArchive &ar);
        bool isEqualSourceIdentifier(const std::string &other) const;
        const std::string & getSourceIdentifier() const { return source_identifier; }
        const std::vector<std::string> & getIdentifierValues() const { return identifier_values; }

    private:
        std::string source_identifier;
        std::vector<std::string> identifier_values;
    };

    bool isHigherPriority(const std::string &current_identifier, const std::string &header_key) const;
    void setIdentifierTopaqueCtx(const HttpHeader &header) const;
    void setCookieValuesToOpaqueCtx(const HttpHeader &header) const;
    void setJWTValuesToOpaqueCtx(const HttpHeader &header) const;
    void setCustomHeaderToOpaqueCtx(const HttpHeader &header) const;
    Maybe<std::string> parseCookieElement(
        const std::string::const_iterator &start,
        const std::string::const_iterator &end,
        const std::string &key) const;
    Buffer extractKeyValueFromCookie(const std::string &cookie_value, const std::string &key) const;
    Maybe<std::string> parseXForwardedFor(const std::string &str) const;

    std::vector<UsersIdentifiersConfig> user_identifiers;
};

#endif // __USER_IDENTIFIERS_CONFIG_H__
