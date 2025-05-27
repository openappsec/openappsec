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

#include "CidrMatch.h"
#include <string.h>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <iostream>
#include <errno.h>
#include "log_generator.h"
#include <stdexcept>

static in_addr applyMaskV4(const in_addr& addr, uint8_t prefixLength) {
    in_addr maskedAddr;
    if (prefixLength == 0) {
        maskedAddr.s_addr = 0;
    } else {
        uint32_t mask = htonl(~((1 << (32 - prefixLength)) - 1));  // Create mask
        maskedAddr.s_addr = addr.s_addr & mask;  // Apply mask
    }
    return maskedAddr;
}

// Function to apply a network mask to an IPv6 address
static in6_addr applyMaskV6(const in6_addr& addr, uint8_t prefixLength) {
    in6_addr maskedAddr = addr;
    int fullBytes = prefixLength / 8;
    int remainingBits = prefixLength % 8;
    uint8_t partialByte = maskedAddr.s6_addr[fullBytes];

    // Mask full bytes
    for (int i = fullBytes; i < 16; ++i) {
        maskedAddr.s6_addr[i] = 0;
    }

    // Mask remaining bits
    if (remainingBits > 0) {
        uint8_t mask = ~((1 << (8 - remainingBits)) - 1);
        maskedAddr.s6_addr[fullBytes] = partialByte & mask;
    }

    return maskedAddr;
}

// Helper function to convert an IPv4 address to string
static std::string ipv4ToString(const in_addr& ipv4) {
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ipv4, str, INET_ADDRSTRLEN);
    return std::string(str);
}

// Helper function to convert an IPv6 address to string
static std::string ipv6ToString(const in6_addr& ipv6) {
    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ipv6, str, INET6_ADDRSTRLEN);
    return std::string(str);
}

USE_DEBUG_FLAG(D_WAAP);
namespace Waap {
namespace Util {

bool CIDRData::operator==(const CIDRData &other) const {
    bool cidrsMatching = isIPV6 ? (memcmp(ipCIDRV6.s6_addr, other.ipCIDRV6.s6_addr, sizeof(ipCIDRV6.s6_addr)) == 0) :
        (ipCIDRV4.s_addr == other.ipCIDRV4.s_addr);
    return cidrString == other.cidrString &&
        cidrsMatching &&
        networkBits == other.networkBits &&
        isIPV6 == other.isIPV6;
}

bool CIDRData::operator<(const CIDRData &other) const {
    if (isIPV6) {
        if (!other.isIPV6) return false;
        return memcmp(ipCIDRV6.s6_addr, other.ipCIDRV6.s6_addr, sizeof(ipCIDRV6.s6_addr)) < 0;
    }
    if (other.isIPV6) return true;
    return ntohl(ipCIDRV4.s_addr) < ntohl(other.ipCIDRV4.s_addr);
}

bool cidr4_match(const in_addr &addr, const in_addr &net, uint8_t bits) {
    if (bits == 0) {
        // C99 6.5.7 (3): u32 << 32 is undefined behaviour
        return true;
    }
    return !((addr.s_addr ^ net.s_addr) & htonl(0xFFFFFFFFu << (32 - bits)));
}

bool cidr6_match(const in6_addr &address, const in6_addr &network, uint8_t bits) {
#ifdef __linux__
    const uint32_t *a = address.s6_addr32;
    const uint32_t *n = network.s6_addr32;
#else
    const uint32_t *a = address.__u6_addr.__u6_addr32;
    const uint32_t *n = network.__u6_addr.__u6_addr32;
#endif
    int bits_whole, bits_incomplete;
    bits_whole = bits >> 5;         // number of whole u32
    bits_incomplete = bits & 0x1F;  // number of bits in incomplete u32
    if (bits_whole) {
        if (memcmp(a, n, bits_whole << 2)) {
        return false;
        }
    }
    if (bits_incomplete) {
        uint32_t mask = htonl((0xFFFFFFFFu) << (32 - bits_incomplete));
        if ((a[bits_whole] ^ n[bits_whole]) & mask) {
        return false;
        }
    }
    return true;
}

bool isCIDR(const std::string& strCIDR, CIDRData& cidr)
{
    size_t processedBits = 0;

    size_t pos = strCIDR.find_last_of('/');
    
    // get ip from targetCidr
    std::string strPrefix = pos != std::string::npos ? strCIDR.substr(0, pos) : strCIDR;
    // get subnet mask from targetCidr or calculate it based on ipv4 / ipv6
    std::string strSuffix = (pos != std::string::npos && (pos + 1) <= strCIDR.size()) ? strCIDR.substr(pos + 1) :
        (strCIDR.find(':') == std::string::npos) ? "32" : "128";

    int bits = -1;
    try
    {
        bits = std::stoi(strSuffix, &processedBits);
        cidr.networkBits = (uint8_t)bits;
        // convert int to uint8_t
    }
    catch (const std::invalid_argument & e)
    {
        dbgDebug(D_WAAP) << "Failed to convert CIDR number of bits from string to int (Invalid arguments)."
            << strCIDR;
        return false;
    }
    catch (const std::out_of_range & e)
    {
        dbgDebug(D_WAAP) << "Failed to convert CIDR number of bits from string to int (out of range)."
            << strCIDR;;
        return false;
    }

    // check if CIDR is valid
    if (processedBits != strSuffix.length() || bits > 128 || bits < 0) {
        dbgDebug(D_WAAP) << "Failed to convert CIDR number of bits from string to int (out of range)."
            << strCIDR;
        return false;
    }

    memset(&cidr.ipCIDRV4, 0, sizeof(struct in_addr));
    memset(&cidr.ipCIDRV6, 0, sizeof(struct in6_addr));

    if (inet_pton(AF_INET, strPrefix.c_str(), &cidr.ipCIDRV4) == 1 && bits <= 32) {
        cidr.ipCIDRV4 = applyMaskV4(cidr.ipCIDRV4, bits);
        cidr.isIPV6 = false;
    }
    else if (inet_pton(AF_INET6, strPrefix.c_str(), &cidr.ipCIDRV6) == 1 && bits <= 128) {
        cidr.ipCIDRV6 = applyMaskV6(cidr.ipCIDRV6, bits);
        cidr.isIPV6 = true;
    }
    else
    {
        return false;
    }

    cidr.cidrString = strCIDR;

    return true;
}

bool cidrMatch(const std::string& sourceip, const std::string& targetCidr) {
    CIDRData cidrData;

    // check if target is valid input.
    if (!isCIDR(targetCidr, cidrData))
    {
        return false;
    }

    return cidrMatch(sourceip, cidrData);
}

bool cidrMatch(const std::string & sourceip, const CIDRData & cidr){
    struct in_addr source_inaddr;
    struct in6_addr source_inaddr6;

    // check from which type the target ip and check if ip belongs to is mask ip
    //convert sourceip to ip v4 or v6.
    if(!cidr.isIPV6 && inet_pton(AF_INET, sourceip.c_str(), &source_inaddr) == 1) {
        return cidr4_match(source_inaddr, cidr.ipCIDRV4, cidr.networkBits);
    }
    else if (cidr.isIPV6 && inet_pton(AF_INET6, sourceip.c_str(), &source_inaddr6) == 1) {
        return cidr6_match(source_inaddr6, cidr.ipCIDRV6, cidr.networkBits);
    }
    
    dbgDebug(D_WAAP) << "Source IP address does not match any of the CIDR definitions.";
    return false;
}

bool doesFirstCidrContainSecond(const CIDRData &first, const CIDRData &second) {
    if (first.isIPV6 != second.isIPV6) return false;  // IPv4 and IPv6 cannot overlap
    if (first.networkBits >= second.networkBits) return false;

    if (!first.isIPV6) {
        // IPv4 containment check
        in_addr smallerNetwork = applyMaskV4(second.ipCIDRV4, first.networkBits);
        return (first.ipCIDRV4.s_addr == smallerNetwork.s_addr);
    }
    // IPv6 containment check
    in6_addr smallerNetwork = applyMaskV6(second.ipCIDRV6, first.networkBits);

    for (int i = 0; i < 16; ++i) {
        if (first.ipCIDRV6.s6_addr[i] != smallerNetwork.s6_addr[i]) {
            return false;
        }
    }
    return true;
}

std::string cidrsToString(const std::vector<CIDRData>& cidrs) {
    std::stringstream ss;
    bool is_first = true;
    ss << "[";
    for (const auto& cidr : cidrs) {
        if (!is_first) ss << ", ";
        if (cidr.isIPV6) {
            ss << ipv6ToString(cidr.ipCIDRV6) << "/" << static_cast<int>(cidr.networkBits);
        } else {
            ss << ipv4ToString(cidr.ipCIDRV4) << "/" << static_cast<int>(cidr.networkBits);
        }
        is_first = false;
    }
    ss << "]";
    return ss.str();
}

}
}
