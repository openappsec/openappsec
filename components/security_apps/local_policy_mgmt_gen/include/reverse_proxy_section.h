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

#ifndef __REVERSE_PROXY_SECTION_H__
#define __REVERSE_PROXY_SECTION_H__

#include <cereal/archives/json.hpp>
#include <unordered_map>

#include "agent_core_utilities.h"
#include "i_shell_cmd.h"

class ParsedRule;

class RPMSettings
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const std::string & getName() const;
    std::string applySettings(const std::string &server_content) const;

private:
    std::string name;
    std::string host_hdr = "$host";
    std::string dns_resolver = "127.0.0.11";
};

class ReverseProxyBuilder
{
public:
    static void init();

    static Maybe<void> addNginxServerLocation(
        std::string location,
        const std::string &host,
        const ParsedRule &rule,
        const RPMSettings &rp_settings);

    static Maybe<void> createNewNginxServer(
        const std::string &host,
        const ParsedRule &rule,
        const RPMSettings &rp_settings);

    static std::string replaceTemplate(
        const std::string &content,
        const boost::regex &nginx_directive_template,
        const std::string &value);

    static Maybe<void> reloadNginx();

private:
    static Maybe<void> createSSLNginxServer(const std::string &host, const RPMSettings &rp_settings);
    static Maybe<void> createHTTPNginxServer(const std::string &host, const RPMSettings &rp_settings);

    static Maybe<std::string> getTemplateContent(const std::string &nginx_template_name);
};
#endif // __REVERSE_PROXY_SECTION_H__
