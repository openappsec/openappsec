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

#include "ip_utilities.h"

#include "connkey.h"

using namespace std;

// LCOV_EXCL_START Reason: temporary until we add relevant UT until 07/10
bool
operator<(const IpAddress &this_ip_addr, const IpAddress &other_ip_addr)
{
    if (this_ip_addr.ip_type < other_ip_addr.ip_type) return true;
    if (this_ip_addr.ip_type == IP_VERSION_4) return this_ip_addr.addr4_t.s_addr < other_ip_addr.addr4_t.s_addr;
    return memcmp(&this_ip_addr.addr6_t, &other_ip_addr.addr6_t, sizeof(struct in6_addr)) < 0;
}

bool
operator==(const IpAddress &this_ip_addr, const IpAddress &other_ip_addr)
{
    if (this_ip_addr.ip_type != other_ip_addr.ip_type) return false;
    if (this_ip_addr.ip_type == IP_VERSION_4) return this_ip_addr.addr4_t.s_addr == other_ip_addr.addr4_t.s_addr;
    return memcmp(&this_ip_addr.addr6_t, &other_ip_addr.addr6_t, sizeof(struct in6_addr)) == 0;
}
// LCOV_EXCL_STOP

Maybe<pair<string, int>>
extractAddressAndMaskSize(const string &cidr)
{
    size_t delimiter_pos = cidr.find("/");
    if (delimiter_pos == string::npos) return genError("provided value is not in CIDR notation: " + cidr);
    string address = cidr.substr(0, delimiter_pos);
    string mask_size = cidr.substr(delimiter_pos + 1, cidr.size() - delimiter_pos - 1);
    try {
        return make_pair(address, stoi(mask_size));
    } catch(...) {
        return genError("failed to cast provided value to integer: " + mask_size);
    }
    return genError("failed to parse provided string as a CIDR: " + cidr);
}

template<typename Integer>
pair<Integer, Integer>
applyMaskOnAddress(const vector<Integer> &oct, Integer mask)
{
    Integer start = (oct[0] | oct[1] | oct[2] | oct[3]) & mask;
    Integer end = (oct[0] | oct[1] | oct[2] | oct[3]) | (~mask);
    return make_pair(start, end);
}

Maybe<pair<string, string>>
createRangeFromCidrV4(const pair<string, int> &cidr_values)
{
    string address = cidr_values.first;
    int mask_size = cidr_values.second;
    vector<uint32_t> oct;
    for (int i=3; i>=0; i--) {
        size_t delimiter_pos = address.find(".");
        string oct_str = address.substr(0, delimiter_pos);
        try {
            oct.push_back(static_cast<uint32_t>(stoul(oct_str)) << (i * 8));
        } catch (...) {
            return genError("failed to cast provided value to integer: " + oct_str);
        }
        if ((i == 0) != (delimiter_pos == string::npos)) {
            return genError("provided value is not in a correct ipv4 structure: " + makeSeparatedStr(oct, "."));
        }
        address.erase(0, delimiter_pos + 1);
    }

    unsigned int mask = 0xffffffff;
    mask <<= (32 - mask_size);

    unsigned int start, end;
    tie(start, end) = applyMaskOnAddress<unsigned int>(oct, mask);

    auto construct_address = [](unsigned int value)
    {
        stringstream address_stream;
        for (int i = 3; i >= 0; i--) {
            address_stream << ((value >> (i * 8)) & 0xff) << (i > 0 ? "." : "");
        }
        return address_stream.str();
    };

    return make_pair<string, string>(construct_address(start), construct_address(end));
}

// LCOV_EXCL_START Reason: it is tested, but for some reason coverage doesn't catch it
Maybe<pair<string, string>>
createRangeFromCidrV6(const pair<string, int> &cidr_values)
{
    string address = cidr_values.first;
    int mask_size = cidr_values.second;
    // fill compressed zeros
    struct in6_addr v6;
    if (inet_pton(AF_INET6, address.c_str(), &v6) == -1) {
        return genError("faild to convert provided value to ipv6: " + address);
    };
    struct in6_addr *addr = &v6;
    vector<unsigned int> oct_from_str;
    for (int i=0; i<15; i+=2){
        char hex[8];
        unsigned int num;
        sprintf(hex, "%02x%02x", static_cast<int>(addr->s6_addr[i]), static_cast<int>(addr->s6_addr[i+1]));
        sscanf(hex, "%x", &num);
        oct_from_str.push_back(num);
    }

    uint64_t mask = 0xffffffffffffffff;
    function<string(uint64_t, bool)> construct_address;
    int oct_offset;

    if (mask_size > 64) {
        oct_offset = 7;
        mask <<= (128 - mask_size);
        construct_address = [oct_from_str](uint64_t value, bool is_start)
        {
            (void)is_start;
            stringstream address_stream;
            for (int i = 0; i < 4; i++) {
                address_stream << hex << oct_from_str[i] << ":";
            }
            for (int i = 3; i >= 0; i--) {
                address_stream << hex << (unsigned int)((value >> (i * 16)) & 0xffff) << (i > 0 ? ":" : "");
            }
            return address_stream.str();
        };
    } else {
        oct_offset = 3;
        mask <<= (64 - mask_size);
        construct_address = [](uint64_t value, bool is_start)
        {
            stringstream address_stream;
            for (int i = 3; i >= 0; i--) {
                address_stream << hex << (unsigned int)((value >> (i * 16)) & 0xffff) << ":";
            }
            address_stream << (is_start ? "0:0:0:0" : "ffff:ffff:ffff:ffff");
            return address_stream.str();
        };
    }

    uint64_t start, end;
    vector<uint64_t> oct;
    for (int i = 3; i >= 0; i--) {
        oct.push_back(static_cast<uint64_t>(oct_from_str[oct_offset - i]) << (i * 16));
    }
    tie(start, end) = applyMaskOnAddress<uint64_t>(oct, mask);
    return make_pair<string, string>(
        construct_address(start, true),
        construct_address(end, false)
    );
}
// LCOV_EXCL_STOP

namespace IPUtilities {
Maybe<map<IpAddress, string>>
getInterfaceIPs()
{
    struct ifaddrs *if_addr_list = nullptr;
    if (getifaddrs(&if_addr_list) == -1) {
        return genError(string("Failed to get interface IP's. Error: ") + strerror(errno));
    }

    map<IpAddress, string> interface_ips;
    for (struct ifaddrs *if_addr = if_addr_list; if_addr != nullptr; if_addr = if_addr->ifa_next) {
        if (if_addr->ifa_addr == nullptr) continue;
        if (if_addr->ifa_addr->sa_family != AF_INET && if_addr->ifa_addr->sa_family != AF_INET6) continue;

        char address_buffer[INET6_ADDRSTRLEN] = { '\0' };
        if (if_addr->ifa_addr->sa_family == AF_INET) {
            struct in_addr addr = reinterpret_cast<struct sockaddr_in *>(if_addr->ifa_addr)->sin_addr;
            inet_ntop(AF_INET, &addr, address_buffer, INET_ADDRSTRLEN);
            string address_string(address_buffer);
            if (address_string.find("127.0.0.1") != string::npos) continue;

            IpAddress ip_addr;
            ip_addr.ip_type = IP_VERSION_4;
            memcpy(&ip_addr.ip.ipv4, &addr, sizeof(ip_addr.ip.ipv4));
            interface_ips.emplace(ip_addr, address_string);
        } else {
            struct in6_addr addr = reinterpret_cast<struct sockaddr_in6 *>(if_addr->ifa_addr)->sin6_addr;
            inet_ntop(AF_INET6, &addr, address_buffer, INET6_ADDRSTRLEN);
            string address_string(address_buffer);
            if (address_string.find("::1") != string::npos) continue;

            IpAddress ip_addr;
            ip_addr.ip_type = IP_VERSION_6;
            memcpy(&ip_addr.ip.ipv6, &addr, sizeof(ip_addr.ip.ipv6));
            interface_ips.emplace(ip_addr, address_string);
        }
    }

    if (if_addr_list != nullptr) freeifaddrs(if_addr_list);

    return interface_ips;
}

Maybe<pair<string, string>>
createRangeFromCidr(const string &cidr)
{
    auto cidr_values = extractAddressAndMaskSize(cidr);
    if (!cidr_values.ok()) return genError("Failed to create range from Cidr: " + cidr_values.getErr());
    return cidr.find(".") != string::npos
        ? createRangeFromCidrV4(cidr_values.unpack())
        : createRangeFromCidrV6(cidr_values.unpack());
}

bool
isIpAddrInRange(const IPRange &rule_ip_range, const IpAddress &ip_addr)
{
    IpAddress min_ip = rule_ip_range.start;
    IpAddress max_ip = rule_ip_range.end;

    if (ip_addr.ip_type == IP_VERSION_4) {
        if (max_ip.ip_type != IP_VERSION_4) return 0;
        return
            memcmp(&ip_addr.ip.ipv4, &min_ip.ip.ipv4, sizeof(struct in_addr)) >= 0 &&
            memcmp(&ip_addr.ip.ipv4, &max_ip.ip.ipv4, sizeof(struct in_addr)) <= 0;
    }
    if (ip_addr.ip_type == IP_VERSION_6) {
        if (max_ip.ip_type != IP_VERSION_6) return 0;
        return
            memcmp(&ip_addr.ip.ipv6, &min_ip.ip.ipv6, sizeof(struct in6_addr)) >= 0 &&
            memcmp(&ip_addr.ip.ipv6, &max_ip.ip.ipv6, sizeof(struct in6_addr)) <= 0;
    }
    return 0;
}

string
IpAddrToString(const IpAddress &address)
{
    if (address.ip_type == IP_VERSION_6) {
        char ip_str[INET6_ADDRSTRLEN];
        struct sockaddr_in6 sa6;

        sa6.sin6_family = AF_INET6;
        sa6.sin6_addr = address.ip.ipv6;

        inet_ntop(AF_INET6, &(sa6.sin6_addr), ip_str, INET6_ADDRSTRLEN);
        return move(string(ip_str));
    }

    char ip_str[INET_ADDRSTRLEN];
    struct sockaddr_in sa;

    sa.sin_family = AF_INET;
    sa.sin_addr = address.ip.ipv4;

    inet_ntop(AF_INET, &(sa.sin_addr), ip_str, INET_ADDRSTRLEN);
    return move(string(ip_str));
}

IpAddress
createIpFromString(const string &ip_string)
{
    IpAddress res_address = {0, IP_VERSION_ANY};
    if (ip_string == "any") return res_address;
    auto  maybe_ip_addr = IPAddr::createIPAddr(ip_string);
    if (!maybe_ip_addr.ok()) {
        return res_address;
    }
    IPAddr ip_addr = maybe_ip_addr.unpack();
    res_address.ip_type = static_cast<IpVersion>(ip_addr.getType());
    if (ip_addr.getType() == IPType::V4) {
        res_address.addr4_t = ip_addr.getIPv4();
    } else {
        res_address.addr6_t = ip_addr.getIPv6();
    }
    return res_address;
}

IpAddress
ConvertToIpAddress(const IPAddr &addr) {
    IpAddress address;
    switch (addr.getType()) {
        case IPType::UNINITIALIZED: {
            address.addr4_t = {0};
            address.ip_type = IP_VERSION_ANY;
            break;
        }
        case IPType::V4: {
            address.addr4_t = addr.getIPv4(); // reference to a local variable ?
            address.ip_type = IP_VERSION_4;
            break;
        }
        case IPType::V6: {
            address.addr6_t = addr.getIPv6();
            address.ip_type = IP_VERSION_6;
            break;
        }
        default:
            dbgAssert(false) << "Unsupported IP type";
    }
    return address;
}

IpAttrFromString::operator Maybe<IpAddress>()
{
    auto ip_addr = IPAddr::createIPAddr(data);
    if (!ip_addr.ok()) return genError("Could not create IP address. Error: " + ip_addr.getErr());
    return ConvertToIpAddress(ip_addr.unpackMove());
}

IpAttrFromString::operator Maybe<IpProto>()
{
    int value;
    try {
        value = stoi(data);
    } catch (...) {
        return genError("provided value is not a legal number. Value: " + data);
    }

    if (value > static_cast<int>(UINT8_MAX) || value < 0) {
        return genError("provided value is not a legal ip protocol number. Value: " + data);
    }

    return static_cast<IpProto>(value);
}

IpAttrFromString::operator Maybe<Port>()
{
    int value;
    try {
        value = stoi(data);
    } catch (...) {
        return genError("provided value is not a legal number. Value: " + data);
    }

    if (value > static_cast<int>(UINT16_MAX) || value < 0) {
        return genError("provided value is not a legal port number. Value: " + data);
    }

    return static_cast<Port>(value);
}
}
