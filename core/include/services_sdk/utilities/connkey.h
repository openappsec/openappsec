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

#ifndef __CONNKEY_H__
#define __CONNKEY_H__

#include <netinet/in.h>
#include <tuple>
#include <string.h>
#include "debug.h"
#include "maybe_res.h"

#include "cereal/archives/json.hpp"

enum class IPType : uint8_t
{
    UNINITIALIZED = 0,
    V4 = 4,
    V6 = 6,
};

std::ostream & operator<<(std::ostream &os, const IPType &t);

using PortNumber = uint16_t; // Host order
using IPProto = uint8_t;     // XXX: Printed as a char, which is bad. Maybe make it a class?

template<class Archive>
void
serialize(Archive &archive, struct in6_addr &addr, uint32_t)
{
    archive(
        addr.s6_addr[0],
        addr.s6_addr[1],
        addr.s6_addr[2],
        addr.s6_addr[3],
        addr.s6_addr[4],
        addr.s6_addr[5],
        addr.s6_addr[6],
        addr.s6_addr[7],
        addr.s6_addr[8],
        addr.s6_addr[9],
        addr.s6_addr[10],
        addr.s6_addr[11],
        addr.s6_addr[12],
        addr.s6_addr[13],
        addr.s6_addr[14],
        addr.s6_addr[15]
    );
}

class IPAddr
{
public:
    explicit IPAddr() : type(IPType::UNINITIALIZED) {}

    explicit IPAddr(const struct in_addr &_v4)
        : type(IPType::V4)
    {
        v6 = IN6ADDR_ANY_INIT; // Make sure unused bits are 0
        v4 = _v4;
    }

    explicit IPAddr(const struct in6_addr &_v6)
        : type(IPType::V6)
    {
        v6 = _v6;
    }

    size_t hash() const;

    IPType getType() const { return type; }

    // Unsafe get functions!
    const struct in_addr & getIPv4() const { return v4; }
    const struct in6_addr & getIPv6() const { return v6; }

    bool
    operator==(const IPAddr &other) const
    {
        dbgAssert(type!=IPType::UNINITIALIZED && other.type!=IPType::UNINITIALIZED)
            << "Called on an uninitialized IPType object";
        // Always compairing as if IPv6, in case of Ipv4 the rest of the address is zeroed out.
        int ip_len = (other.type == IPType::V4) ? sizeof(v4.s_addr) : sizeof(v6.s6_addr);
        return (type == other.type) && (memcmp(v6.s6_addr, other.v6.s6_addr, ip_len) == 0);
    }

    bool
    operator>(const IPAddr &other) const
    {
        int ip_len = (other.type == IPType::V4) ? sizeof(v4.s_addr) : sizeof(v6.s6_addr);
        return (type == other.type) && (memcmp(v6.s6_addr, other.v6.s6_addr, ip_len) > 0);
    }

    bool
    operator<(const IPAddr &other) const
    {
        return !(*this >= other);
    }

    bool
    operator>=(const IPAddr &other) const
    {
        return (*this > other) || (*this == other);
    }

    bool
    operator<=(const IPAddr &other) const
    {
        return !(*this > other);
    }

    Maybe<std::string> calculateSubnetStart(int subnet_value);

    Maybe<std::string> calculateSubnetEnd(int subnet_value);

    // Checks if the IP address is in the range [left, right] inclusive.
    // All IPAddrs must be of the same kind, or the result is false.
    bool isInRange(const IPAddr &left, const IPAddr &right) const;

    std::ostream & print(std::ostream &os) const;

    static bool isValidIPAddr(const std::string &ip_text);

    //factory function to create and validate  ipV4/ipV6 from string
    static Maybe<IPAddr> createIPAddr(const std::string &ip_text);

    template<class Archive>
    void
    serialize(Archive &ar, uint32_t)
    {
        ar(v6, type, proto, port);
    }

private:
    union {
        struct in_addr v4;
        struct in6_addr v6;
    };
    IPType type;

    friend class ConnKey;
    friend class PendingKey;
    // Additional fields to be used by ConnKey class and placed here to save space, IPAddr class should ignore them.
    IPProto proto;
    PortNumber port;

    Maybe<std::string> calculateSubnetStartV4(int subnet_value);

    Maybe<std::string> calculateSubnetEndV4(int subnet_value);

    Maybe<std::string> calculateSubnetStartV6(int subnet_value);

    Maybe<std::string> calculateSubnetEndV6(int subnet_value);
};

namespace ConnKeyUtil {

bool fromString(const std::string &proto_str, IPProto &proto);

bool fromString(const std::string &port_str, PortNumber &port);

bool fromString(const std::string &ip_str, IPAddr &ip_address);
};

template <typename RangeType>
class CustomRange
{
public:
    CustomRange(const RangeType &_start, const RangeType &_end) : start(_start), end(_end) {}

    bool contains(const RangeType &elem) const { return elem >= start && elem <= end; }

    static Maybe<CustomRange<RangeType>>
    createRange(const std::string &maybe_range)
    {
        std::string start_range;
        std::string end_range;
        size_t delimiter_position;

        if ((delimiter_position = maybe_range.find("-")) != std::string::npos) {
            // If it's a range.
            start_range = maybe_range.substr(0, delimiter_position);
            end_range = maybe_range.substr(delimiter_position + 1);
            if (end_range.empty()) {
                end_range = start_range;
            }
        } else if ((delimiter_position = maybe_range.find("/")) != std::string::npos) {
            // If it's a subnet.
            IPAddr ip;
            ConnKeyUtil::fromString((maybe_range.substr(0, delimiter_position)), ip);
            std::string subnet = maybe_range.substr(delimiter_position + 1);
            int subnet_value = std::stoi(subnet);
            start_range = ip.calculateSubnetStart(subnet_value).unpack();
            end_range = ip.calculateSubnetEnd(subnet_value).unpack();
        } else {
            // If it's a single IP.
            start_range = maybe_range;
            end_range = maybe_range;
        }
        RangeType _start;
        if (!ConnKeyUtil::fromString(start_range, _start)) {
            return genError("Error in start value of custom range, value: " + start_range);
        }

        RangeType _end;
        if (!ConnKeyUtil::fromString(end_range, _end)) {
            return genError("Error in end value of custom range, value: " + end_range);
        }

        if (_start > _end) {
            return genError("Error in creating custom range, invalid range: " + maybe_range);
        }

        return CustomRange(_start, _end);
    }

private:
    RangeType start;
    RangeType end;
};

// Specialization of std::hash<> for IPAddr
namespace std
{

template <>
struct hash<IPAddr>
{
    size_t operator()(const IPAddr &ip) const { return ip.hash(); }
};

} // namespace std

static inline std::ostream & operator<<(std::ostream &os, const IPAddr &addr) { return addr.print(os); }

class ConnKey
{
public:
    explicit ConnKey() {}
    explicit ConnKey(
        const IPAddr &_src,
        PortNumber sport,
        const IPAddr &_dst,
        PortNumber dport,
        IPProto proto)
            :
        src(_src),
        dst(_dst)
    {
        src.port = sport;
        dst.port = dport;
        src.proto = proto;
        dst.proto = proto;
    }

    static void preload();
    static void init();
    static void fini() {}

    static std::string getName() { return "ConnKey"; }

    bool
    operator==(const ConnKey &other) const
    {
        auto my_tuple = std::tie(src, src.port, dst, dst.port, src.proto);
        auto other_tuple = std::tie(other.src, other.src.port, other.dst, other.dst.port, other.src.proto);
        return my_tuple == other_tuple;
    }

    bool
    operator!=(const ConnKey &other) const
    {
        return !(*this == other);
    }

    const IPAddr & getSrc() const { return src; }
    PortNumber getSPort() const { return src.port; }
    const IPAddr & getDst() const { return dst; }
    PortNumber getDPort() const { return dst.port; }
    IPProto getProto() const { return src.proto; }
    std::string
    getProtocolAsString() const
    {
        switch(src.proto) {
            case 1:
                return "ICMP";
            case 6:
                return "TCP";
            case 17:
                return "UDP";
            default:
                int int_proto = src.proto;
                return std::to_string(int_proto);
        }
    }

    IPType
    getType() const
    {
        dbgAssert(src.type == dst.type) << "Mismatch in connection types (Src and Dst types are not identical)";
        return src.type;
    }

    size_t hash() const;
    void reverse();        // XXX: I actually want a reversing copy constructor.
    std::ostream & print(std::ostream &os) const;

// LCOV_EXCL_START Reason: coverage upgrade
    template<class Archive>
    void
    serialize(Archive &ar, uint32_t)
    {
        ar(src, dst);
    }
// LCOV_EXCL_STOP

    static const std::string network_key;

private:
    IPAddr src, dst;
};

// Specialization of std::hash<> for ConnKey
namespace std
{

template <>
struct hash<ConnKey>
{
    size_t operator()(const ConnKey &k) const { return k.hash(); }
};

} // namespace std

static inline std::ostream & operator<<(std::ostream &os, const ConnKey &k) { return k.print(os); }

#endif // __CONNKEY_H__
