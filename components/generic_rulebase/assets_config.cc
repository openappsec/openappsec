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

#include "generic_rulebase/assets_config.h"

#include <string>
#include <algorithm>
#include <unordered_map>

#include "generic_rulebase/generic_rulebase_utils.h"
#include "config.h"
#include "debug.h"
#include "ip_utilities.h"

USE_DEBUG_FLAG(D_RULEBASE_CONFIG);

using namespace std;

void
RuleAsset::load(cereal::JSONInputArchive &archive_in)
{
    archive_in(cereal::make_nvp("assetId", asset_id));
    archive_in(cereal::make_nvp("assetName", asset_name));
    archive_in(cereal::make_nvp("assetUrls", asset_urls));

    dbgWarning(D_RULEBASE_CONFIG) << "Adding asset with UID: " << asset_id;
}

void
RuleAsset::AssetUrl::load(cereal::JSONInputArchive &archive_in)
{
    archive_in(cereal::make_nvp("protocol", protocol));
    transform(protocol.begin(), protocol.end(), protocol.begin(), [](unsigned char c) { return tolower(c); });

    archive_in(cereal::make_nvp("ip", ip));
    archive_in(cereal::make_nvp("port", port));

    int value;
    if (protocol == "*") {
        is_any_proto = true;
    } else {
        is_any_proto = false;
        try {
            value = 0;
            if(protocol == "udp") value = IPPROTO_UDP;
            if(protocol == "tcp") value = IPPROTO_TCP;
            if(protocol == "dccp") value = IPPROTO_DCCP;
            if(protocol == "sctp") value = IPPROTO_SCTP;
            if(protocol == "icmp") value = IPPROTO_ICMP;
            if(protocol == "icmpv6") value = IPPROTO_ICMP;

            if (value > static_cast<int>(UINT8_MAX) || value < 0) {
                dbgWarning(D_RULEBASE_CONFIG)
                    << "provided value is not a legal IP protocol number. Value: "
                    << protocol;
            } else {
                parsed_proto = value;
            }
        } catch (...) {
            dbgWarning(D_RULEBASE_CONFIG) << "provided value is not a legal IP protocol. Value: " << protocol;
        }
    }

    if (port == "*") {
        is_any_port = true;
    } else {
        is_any_port = false;
        try {
            value = stoi(port);
            if (value > static_cast<int>(UINT16_MAX) || value < 0) {
                dbgWarning(D_RULEBASE_CONFIG) << "provided value is not a legal port number. Value: " << port;
            } else {
                parsed_port = value;
            }
        } catch (...) {
            dbgWarning(D_RULEBASE_CONFIG) << "provided value is not a legal port. Value: " << port;
        }
    }

    if (ip == "*") {
        is_any_ip = true;
    } else {
        is_any_ip = false;
        auto ip_addr = IPAddr::createIPAddr(ip);
        if (!ip_addr.ok()) {
            dbgWarning(D_RULEBASE_CONFIG) << "Could not create IP address. Error: " << ip_addr.getErr();
        } else {
            parsed_ip = ConvertToIpAddress(ip_addr.unpackMove());
        }
    }
}

IpAddress
RuleAsset::AssetUrl::ConvertToIpAddress(const IPAddr &addr)
{
    IpAddress address;
    switch (addr.getType()) {
        case IPType::UNINITIALIZED: {
            address.addr4_t = {0};
            address.ip_type = IP_VERSION_ANY;
            break;
        }
        case IPType::V4: {
            address.addr4_t = addr.getIPv4();
            address.ip_type = IP_VERSION_4;
            break;
        }
        case IPType::V6: {
            address.addr6_t = addr.getIPv6();
            address.ip_type = IP_VERSION_6;
            break;
        }
        default:
            address.addr4_t = {0};
            address.ip_type = IP_VERSION_ANY;
            dbgWarning(D_RULEBASE_CONFIG) << "Unsupported IP type: " << static_cast<int>(addr.getType());
    }
    return address;
}

const Assets Assets::empty_assets_config = Assets();

void
Assets::preload()
{
    registerExpectedSetting<Assets>("rulebase", "usedAssets");
}
