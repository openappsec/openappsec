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

#ifndef __ASSETS_CONFIG_H__
#define __ASSETS_CONFIG_H__

#include <vector>
#include <string>
#include <arpa/inet.h>

#include "generic_rulebase_context.h"
#include "c_common/ip_common.h"
#include "connkey.h"

class RuleAsset
{
public:
    class AssetUrl
    {
    public:
        void
        load(cereal::JSONInputArchive &archive_in);
        const std::string & getProtocol() const { return protocol; }
        const std::string & getIp() const { return ip; }
        const std::string & getPort() const { return port; }

        uint8_t getParsedProtocol() const { return parsed_proto; }
        const IpAddress & getParsedIp() const { return parsed_ip; }
        uint16_t getParsedPort() const { return parsed_port; }
        bool isAnyIp() const { return is_any_ip; }
        bool isAnyPort() const { return is_any_port; }
        bool isAnyProto() const { return is_any_proto; }

    private:
        static IpAddress ConvertToIpAddress(const IPAddr &addr);

        std::string protocol;
        std::string ip;
        std::string port;
        IpAddress parsed_ip;
        uint16_t parsed_port;
        uint8_t parsed_proto;
        bool is_any_ip;
        bool is_any_port;
        bool is_any_proto;
    };

    void load(cereal::JSONInputArchive &archive_in);

    const GenericConfigId & getId() const { return asset_id; }
    const std::string & getName() const { return asset_name; }
    const std::vector<AssetUrl> & getUrls() const { return asset_urls; }
    
private:
    GenericConfigId asset_id;
    std::string asset_name;
    std::vector<AssetUrl> asset_urls;
};

class Assets
{
public:
    static void preload();

    void load(cereal::JSONInputArchive &archive_in)
    {
        try {
            cereal::load(archive_in, assets);
        }catch (const cereal::Exception &) {
        }
    }

    static const Assets empty_assets_config;

    const std::vector<RuleAsset> & getAssets() const { return assets; }

private:
    std::vector<RuleAsset> assets;
};

#endif //__ASSETS_CONFIG_H__
