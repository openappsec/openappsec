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

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "connkey.h"
#include "debug.h"
#include "config.h"
#include "hash_combine.h"
#include "enum_range.h"
#include "cereal/types/memory.hpp"

using namespace std;

CEREAL_CLASS_VERSION(IPAddr, 0);
CEREAL_CLASS_VERSION(ConnKey, 0);

USE_DEBUG_FLAG(D_CONFIG);

static bool
protoHasPorts(IPProto proto)
{
    return (proto==IPPROTO_TCP) || (proto==IPPROTO_UDP);
}

ostream &
operator<<(ostream &os, const IPType &t)
{
    switch (t) {
        case IPType::V4: {
            return os << "IPv4";
        }
        case IPType::V6: {
            return os << "IPv6";
        }
        case IPType::UNINITIALIZED: {
            break;
        }
    }
    return os << "Invalid(" << static_cast<uint>(t) << ")";
}

// Format an IP address. Use a pair, becuase it depends on the type (v4/v6)
ostream &
IPAddr::print(ostream &os) const
{
    char buf[INET6_ADDRSTRLEN];
    const char *formatted_addr;

    switch (type) {
        case IPType::V4: {
            formatted_addr = inet_ntop(AF_INET, &v4, buf, sizeof(buf));
            dbgAssert(formatted_addr == buf) << "Failed to convert an IPv4 address";
            break;
        }
        case IPType::V6: {
            formatted_addr = inet_ntop(AF_INET6, &v6, buf, sizeof(buf));
            dbgAssert(formatted_addr == buf) << "Failed to convert an IPv6 address";
            break;
        }
        case IPType::UNINITIALIZED: {
            formatted_addr = "Uninitialized IP address";
            break;
        }
        default: {
            formatted_addr = "?";
            break;
        }
    }

    return os << formatted_addr;
}

// Format a port numbers. Use a pair, becuase it depends on the protocl (only TCP/UDP have ports).
static ostream &
operator<<(ostream &os, pair<IPProto, PortNumber> pp)
{
    if (protoHasPorts(get<0>(pp))) {
        os << "|" << get<1>(pp);
    }
    return os;
}

ostream &
ConnKey::print(ostream &os) const
{
    if (src.type == IPType::UNINITIALIZED) return os << "<Uninitialized connection>";

    return os << "<" <<
        src << make_pair(src.proto, src.port) <<
        " -> " <<
        dst << make_pair(dst.proto, dst.port) <<
        " " << static_cast<uint>(src.proto) << ">";  // Cast needed to print as a number.
}

void
ConnKey::reverse()
{
    swap(src, dst);
}

size_t
ConnKey::hash() const
{
    dbgAssert(src.type != IPType::UNINITIALIZED) << "ConnKey::hash was called on an uninitialized object";
    size_t seed = 0;  // XXX: random seed for security?
    hashCombine(seed, static_cast<u_char>(src.type));
    hashCombine(seed, src.proto);
    hashCombine(seed, src);
    hashCombine(seed, dst);
    hashCombine(seed, src.port);
    hashCombine(seed, dst.port);
    return seed;
}

size_t
IPAddr::hash() const
{
    size_t seed = 0;
    hashCombine(seed, v6.s6_addr32[0]);
    hashCombine(seed, v6.s6_addr32[1]);
    hashCombine(seed, v6.s6_addr32[2]);
    hashCombine(seed, v6.s6_addr32[3]);
    return seed;
}

bool
IPAddr::isInRange(const IPAddr &left, const IPAddr &right) const
{
    return (*this >= left) && (*this <= right);
}

Maybe<IPAddr>
IPAddr::createIPAddr(const string &ip_text)
{
    if (ip_text.find(':') == string::npos) {
        struct in_addr v4;
        if(inet_pton(AF_INET, ip_text.c_str(), &v4)!=0){
            return IPAddr(v4);
        }
    } else {  // Found ':' - it's IPv6
        struct in6_addr v6;
        if(inet_pton(AF_INET6, ip_text.c_str(), &v6)!=0){
            return IPAddr(v6);
        }
    }
    return genError("String \'"+ ip_text +"\' is not a valid IPv4/IPv6 address");
}

bool IPAddr::isValidIPAddr(const string &ip_text) { return createIPAddr(ip_text).ok(); }

const string ConnKey::network_key = "NetworkKey";

template<typename Num>
Maybe<Num>
fromStringToNumeric(const string &value_str, const string &name, const int max_val)
{
    if (value_str.find_first_not_of("0123456789") != string::npos) {
        dbgError(D_CONFIG) << name << " contains non digit chars. Value: " << value_str;
        return genError(name + " contains non digit chars. Value: " + value_str);
    }
    try {
        int value;
        value = stoi(value_str);
        if (value > max_val) {
            dbgError(D_CONFIG) << "Invalid " << name << ". Value: " << value_str;
            return genError("Invalid " + name + ". Value: " + value_str);
        }
        return static_cast<Num>(value);
    } catch (const invalid_argument &e) {
        dbgError(D_CONFIG) << name << " received is invalid. Error: " << e.what();
        return genError(name + " received is invalid. Error: " + e.what());
    }
    return genError("Error in creating numeric value of " + name);
}

bool
ConnKeyUtil::fromString(const string &proto_str, IPProto &proto)
{
    Maybe<IPProto> ip_protocol = fromStringToNumeric<IPProto>(proto_str, "Ip protocol", 255);
    if (ip_protocol.ok()) {
        proto = ip_protocol.unpack();
        return true;
    }
    return false;
}

bool
ConnKeyUtil::fromString(const string &port_str, PortNumber &port)
{
    Maybe<PortNumber> port_num = fromStringToNumeric<PortNumber>(port_str, "Port", 65535);
    if (port_num.ok()) {
        port = port_num.unpack();
        return true;
    }
    return false;
}

bool
ConnKeyUtil::fromString(const string &ip_str, IPAddr &ip_address)
{
    Maybe<IPAddr> ip_addr = IPAddr::createIPAddr(ip_str);
    if (!ip_addr.ok()) {
        dbgError(D_CONFIG) << "Ip address received is invalid: " << ip_addr.getErr();
        return false;
    }
    ip_address = ip_addr.unpack();
    return true;
}
