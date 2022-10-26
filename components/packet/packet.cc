#include "packet.h"
#include "debug.h"
#include "byteorder.h"
#include "c_common/network_defs.h"
#include "config.h"

#include <cstddef>
#include <limits>
#include <vector>
#include <stdlib.h>
#include <string.h>
#include <iostream>

using namespace std;

USE_DEBUG_FLAG(D_PACKET);

ostream &
operator<<(ostream &os, const PktErr &err)
{
    switch (err) {
        case PktErr::UNINITIALIZED: {
            return os << "Uninitialized packet";
        }
        case PktErr::NON_ETHERNET_FRAME: {
            return os << "Layer 2 frame length does not match the Ethernet frame length";
        }
        case PktErr::MAC_LEN_TOO_BIG: {
            return os << "Layer 2 frame length is greater than the packet length";
        }
        case PktErr::NON_IP_PACKET: {
            return os << "Ethernet frame contains a non-IP packet";
        }
        case PktErr::UNKNOWN_L3_PROTOCOL: {
            return os << "Unknown Layer 3 protocol type";
        }
        case PktErr::IP_SIZE_MISMATCH: {
            return os << "Wrong IP header size";
        }
        case PktErr::IP_VERSION_MISMATCH: {
            return os << "IP header version differs from the IP version defined by the Ethernet frame";
        }
        case PktErr::IP_HEADER_TOO_SMALL: {
            return os << "Reported IP header length is shorter than the allowed minimum";
        }
        case PktErr::PKT_TOO_SHORT_FOR_IP_HEADER: {
            return os << "Packet is too short for the IP header";
        }
        case PktErr::PKT_TOO_SHORT_FOR_IP_EXTENSION_HEADER: {
            return os << "Packet is too short for the IP extension header";
        }
        case PktErr::PKT_TOO_SHORT_FOR_IP_EXTENSION_HEADER_BODY: {
            return os << "Packet is too short for the IP extension body";
        }
        case PktErr::UNKNOWN_IPV6_EXTENSION_HEADER: {
            return os << "Unknown IPv6 extension";
        }
        case PktErr::PKT_TOO_SHORT_FOR_L4_HEADER: {
            return os << "IP content is too short to hold a Layer 4 header";
        }
        case PktErr::PKT_TOO_SHORT_FOR_TCP_OPTIONS: {
            return os << "IP content is too short to hold all the TCP Options";
        }
        case PktErr::TCP_HEADER_TOO_SMALL: {
            return os << "Reported TCP header length is shorter than the allowed minimum";
        }
        case PktErr::PKT_TOO_SHORT_FOR_ICMP_ERROR_DATA: {
            return os << "ICMP data is too short to hold all ICMP error information";
        }
        case PktErr::ICMP_VERSION_MISMATCH: {
            return os << "ICMP version does not match the IP version";
        }
    };

    return os << "Unknown error: " << static_cast<uint>(err);
}

// This is common for (almost) all extension headers.
// All headers that ipv6_is_proto_extension returns true for them must have this layout
struct IPv6ExtBasic
{
    u_char next_type;
};

// This is common for some extension headers
struct IPv6ExtGeneric
{
    u_char next_type;
    u_char ext_hdr_len; // Not in bytes! Sometimes *4, sometimes *8...
};

static const uint basic_ext_len = 8;
static const uint format_multiplier_four = 4;
static const uint format_multiplier_eight = 8;
static const char ipv4_chr = 0x40;
static const char ipv6_chr = 0x60;
static const char ipversion_mask = 0x60;

static bool
isIPv6ProtoExtension(u_char proto)
{
    // ESP and None are not considered as ext headers, as their first 4 bytes are not of type IPv6ExtBasic
    switch (proto) {
        case IPPROTO_HOPOPTS:   //      0 IPv6 hop-by-hop options - RFC2460
        case IPPROTO_ROUTING:   //     43 IPv6 routing header - RFC2460
        case IPPROTO_FRAGMENT:  //     44 IPv6 fragmentation header - RFC2460
//      case IPPROTO_ESP:       //     50 IPv6 encapsulation security payload header - RFC4303
        case IPPROTO_AH:        //     51 IPv6 authentication header - RFC4302
//      case IPPROTO_NONE:      //     59 IPv6 no next header - RFC2460
        case IPPROTO_DSTOPTS:   //     60 IPv6 destination options - RFC2460
        case IPPROTO_MH: {     //    135 IPv6 mobility header - RFC3775
            return true;
        }
    }
    return false;
}

Maybe<ConnKey, PktErr>
Packet::parseFromL4(const IPAddr &src, const IPAddr &dst, IPProto proto)
{
    // Here so we got the l3 headers on both IPv4 and IPv6.
    if (is_fragment) return ConnKey(src, 0, dst, 0, proto);
    // Add ports
    PortNumber sport, dport;
    switch (proto) {
        case IPPROTO_TCP: {
            auto maybe_tcp = l3_payload.getTypePtr<struct TcpHdr>(0);
            if (!maybe_tcp.ok()) {
                dbgTrace(D_PACKET)
                    << "TCP packet is too short ("
                    << l3_payload.size()
                    << ") to contain a basic TCP header";
                return genError(PktErr::PKT_TOO_SHORT_FOR_L4_HEADER);
            }
            auto tcp = maybe_tcp.unpack();
            auto l4_hdr_len = tcp->doff * sizeof(int32_t);

            if (l4_hdr_len < sizeof(struct TcpHdr)) {
                dbgTrace(D_PACKET) <<
                    "TCP header length is smaller than the minimum: " << l4_hdr_len << " < " << sizeof(struct tcphdr);
                return genError(PktErr::TCP_HEADER_TOO_SMALL);
            }
            if (l4_hdr_len > l3_payload.size()) {
                dbgTrace(D_PACKET) <<
                    "TCP packet is too short (" << l3_payload.size() << ") for a TCP header (" << l4_hdr_len << ")";
                return genError(PktErr::PKT_TOO_SHORT_FOR_TCP_OPTIONS);
            }

            l4_header = l3_payload.getSubBuffer(0, l4_hdr_len);
            l4_payload = l3_payload.getSubBuffer(l4_hdr_len, l3_payload.size());
            sport = ntohs(tcp->source);
            dport = ntohs(tcp->dest);
            break;
        }
        case IPPROTO_UDP: {
            auto maybe_udp = l3_payload.getTypePtr<struct UdpHdr>(0);
            if (!maybe_udp.ok()) {
                dbgTrace(D_PACKET)
                    << "UDP packet is too short ("
                    << l3_payload.size()
                    << ") to contain a basic UDP header";
                return genError(PktErr::PKT_TOO_SHORT_FOR_L4_HEADER);
            }
            auto udp = maybe_udp.unpack();
            auto l4_hdr_len = sizeof(struct UdpHdr);

            l4_header = l3_payload.getSubBuffer(0, l4_hdr_len);
            l4_payload = l3_payload.getSubBuffer(l4_hdr_len, l3_payload.size());
            sport = ntohs(udp->source);
            dport = ntohs(udp->dest);
            break;
        }
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6: {
            auto icmp_hdr_len = getIcmpHdrLen(proto, src.getType());
            if (!icmp_hdr_len.ok()) return icmp_hdr_len.passErr();
            auto l4_hdr_len = icmp_hdr_len.unpack();
            if (l4_hdr_len > l3_payload.size()) {
                dbgTrace(D_PACKET)
                    << "ICMPv6 packet is too short ("
                    << l3_payload.size()
                    << ") to contain an ICMP header ("
                    << l4_hdr_len
                    << ")";
                return genError(PktErr::PKT_TOO_SHORT_FOR_L4_HEADER);
            }
            l4_header = l3_payload.getSubBuffer(0, l4_hdr_len);
            l4_payload = l3_payload.getSubBuffer(l4_hdr_len, l3_payload.size());
            tie(sport, dport) = getICMPPorts(proto);
            break;
        }
        case IPPROTO_GRE: {
            auto maybe_gre = l3_payload.getTypePtr<struct GreHdr>(0);
            if (!maybe_gre.ok()) {
                dbgTrace(D_PACKET)
                    << "GRE packet is too short ("
                    << l3_payload.size()
                    << ") to contain a basic GRE header";
                return genError(PktErr::PKT_TOO_SHORT_FOR_L4_HEADER);
            }
            auto l4_hdr_len = sizeof(struct GreHdr);

            l4_header = l3_payload.getSubBuffer(0, l4_hdr_len);
            l4_payload = l3_payload.getSubBuffer(l4_hdr_len, l3_payload.size());
            sport = 0;
            dport = 0;
            break;
        }
        case IPPROTO_SCTP: {
            auto maybe_sctp = l3_payload.getTypePtr<struct SctpHdr>(0);
            if (!maybe_sctp.ok()) {
                dbgTrace(D_PACKET)
                    << "SCTP packet is too short ("
                    << l3_payload.size()
                    << ") to contain a basic SCTP header";
                return genError(PktErr::PKT_TOO_SHORT_FOR_L4_HEADER);
            }
            auto sctp = maybe_sctp.unpack();
            auto l4_hdr_len = sizeof(struct SctpHdr);

            l4_header = l3_payload.getSubBuffer(0, l4_hdr_len);
            l4_payload = l3_payload.getSubBuffer(l4_hdr_len, l3_payload.size());
            sport = ntohs(sctp->sport);
            dport = ntohs(sctp->dport);
            break;
        }
        case IPPROTO_DCCP: {
            auto maybe_dccp = l3_payload.getTypePtr<struct DccpHdr>(0);
            if (!maybe_dccp.ok()) {
                dbgTrace(D_PACKET)
                    << "DCCP packet is too short ("
                    << l3_payload.size()
                    << ") to contain a basic DCCP header";
                return genError(PktErr::PKT_TOO_SHORT_FOR_L4_HEADER);
            }
            auto dccp = maybe_dccp.unpack();
            auto l4_hdr_len = sizeof(struct DccpHdr);

            l4_header = l3_payload.getSubBuffer(0, l4_hdr_len);
            l4_payload = l3_payload.getSubBuffer(l4_hdr_len, l3_payload.size());
            sport = ntohs(dccp->dccph_sport);
            dport = ntohs(dccp->dccph_dport);
            break;
        }
        // other protocols
        default: {
            l4_payload = l3_payload;
            sport = 0;
            dport = 0;
            break;
        }
    }

    return ConnKey(src, sport, dst, dport, proto);
}

tuple<PortNumber, PortNumber>
Packet::getICMPPortsV6()
{
    auto icmp_hdr = l4_header.getTypePtr<struct icmp6_hdr>(0).unpack();
    PortNumber sport = 0;
    PortNumber dport = 0;
    switch(icmp_hdr->icmp6_type) {
        case ICMP6_ECHO_REQUEST:
            sport = ntohs(icmp_hdr->icmp6_id);
            if (!getConfigurationWithDefault<bool>(false, "Allow simultaneous ping")) {
                dport = ntohs(icmp_hdr->icmp6_seq);
            }
            break;
        case ICMP6_ECHO_REPLY:
            if (!getConfigurationWithDefault<bool>(false, "Allow simultaneous ping")) {
                sport = ntohs(icmp_hdr->icmp6_seq);
            }
            dport = ntohs(icmp_hdr->icmp6_id);
            break;
        case ICMP6_DST_UNREACH:
        case ICMP6_PACKET_TOO_BIG:
        case ICMP6_TIME_EXCEEDED:
        case ICMP6_PARAM_PROB:
        case ND_REDIRECT:
            sport = icmp_hdr->icmp6_code;
            dport = icmp_hdr->icmp6_type;
            break;
    }
    return make_tuple(sport, dport);
}

tuple<PortNumber, PortNumber>
Packet::getICMPPortsV4()
{
    auto icmp_hdr = l4_header.getTypePtr<struct icmphdr>(0).unpack();
    PortNumber sport = 0;
    PortNumber dport = 0;
    switch(icmp_hdr->type) {
        case ICMP_ECHO:
        case ICMP_TSTAMP:
        case ICMP_IREQ:
        case ICMP_MASKREQ:
            sport = ntohs(icmp_hdr->un.echo.id);
            if (!getConfigurationWithDefault<bool>(false, "Allow simultaneous ping")) {
                dport = ntohs(icmp_hdr->un.echo.sequence);
            }
            break;
        case ICMP_ECHOREPLY:
        case ICMP_TSTAMPREPLY:
        case ICMP_IREQREPLY:
        case ICMP_MASKREPLY:
            if (!getConfigurationWithDefault<bool>(false, "Allow simultaneous ping")) {
                sport = ntohs(icmp_hdr->un.echo.sequence);
            }
            dport = ntohs(icmp_hdr->un.echo.id);
            break;
        case ICMP_UNREACH:
        case ICMP_SOURCEQUENCH:
        case ICMP_TIMXCEED:
        case ICMP_PARAMPROB:
        case ICMP_REDIRECT:
            sport = icmp_hdr->code;
            dport = icmp_hdr->type;
            break;
    }
    return make_tuple(sport, dport);
}

tuple<PortNumber, PortNumber>
Packet::getICMPPorts(IPProto proto)
{
    return proto == IPPROTO_ICMP ? getICMPPortsV4() : getICMPPortsV6();
}

Maybe<uint, PktErr>
Packet::getIcmpHdrLen(IPProto proto, IPType ip_type)
{
    if (proto == IPPROTO_ICMP && ip_type == IPType::V4) {
        return sizeof(struct icmphdr);
    } else if (proto == IPPROTO_ICMPV6 && ip_type == IPType::V6) {
        return sizeof(struct icmp6_hdr);
    }
    return genError(PktErr::ICMP_VERSION_MISMATCH);
}

Maybe<int, PktErr>
Packet::getIPv6GenericExtLen(uint offset_to_ext_hdr, uint length_multiplier)
{
    auto maybe_header = l3.getTypePtr<IPv6ExtGeneric>(offset_to_ext_hdr);
    if (!maybe_header.ok()) {
        dbgTrace(D_PACKET) <<
            "Not enough room for an IPv6 Extension header basic data (" << offset_to_ext_hdr << " + " <<
            sizeof(IPv6ExtGeneric) << " > " << l3.size() << ")";
        return genError(PktErr::PKT_TOO_SHORT_FOR_IP_EXTENSION_HEADER);
    }
    auto header = maybe_header.unpack();

    return basic_ext_len + (header->ext_hdr_len * length_multiplier);
}

Maybe<int, PktErr>
Packet::getIPv6ExtLen(uint offset_to_ext_hdr, IPProto ext_hdr_type)
{
    switch (ext_hdr_type) {
        case IPPROTO_FRAGMENT: {
            // The length of Fragmentation and ESP headers is always 8 bytes. They don't have a length field.
            return basic_ext_len;
        }
        case IPPROTO_AH: {
            // In AH header the length field specifies the header's length in units of 4 bytes
            return getIPv6GenericExtLen(offset_to_ext_hdr, format_multiplier_four);
        }
        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_DSTOPTS:
        case IPPROTO_MH: {
            // For these headers, the length field specifies the header's length in units of 8 bytes
            return getIPv6GenericExtLen(offset_to_ext_hdr, format_multiplier_eight);
        }
    }
    dbgWarning(D_PACKET) << "Unknown IPv6 Extension header type" << static_cast<uint>(ext_hdr_type);
    return genError(PktErr::UNKNOWN_IPV6_EXTENSION_HEADER);
}

Maybe<IPProto, PktErr>
Packet::getIPv6Proto(IPProto proto)
{
    uint offset_to_ext_hdr = sizeof(struct ip6_hdr);

    while (isIPv6ProtoExtension(proto)) {
        auto res = getIPv6ExtLen(offset_to_ext_hdr, proto);
        if (!res.ok()) return res.passErr();
        auto ext_len = *res;

        if (offset_to_ext_hdr + ext_len > l3.size()) {
            dbgTrace(D_PACKET) <<
                "IPv6 Extension header " << static_cast<uint>(proto) << " body is too long" <<
                " - Body length=" << ext_len << ", offset=" << offset_to_ext_hdr << ", L3 data length=" << l3.size();
            return genError(PktErr::PKT_TOO_SHORT_FOR_IP_EXTENSION_HEADER_BODY);
        }

        if (proto == IPPROTO_FRAGMENT) {
            dbgTrace(D_PACKET) << "Fragmented IPv6 packet";
            is_fragment = true;
        }

        auto header = l3.getTypePtr<IPv6ExtBasic>(offset_to_ext_hdr).unpack();
        proto = header->next_type;
        offset_to_ext_hdr += ext_len;
    }

    l3_header = l3.getSubBuffer(0, offset_to_ext_hdr);
    l3_payload = l3.getSubBuffer(offset_to_ext_hdr, l3.size());
    return proto;
}

Maybe<ConnKey, PktErr>
Packet::parseFromL3v6()
{
    auto maybe_ip6 = l2_payload.getTypePtr<struct ip6_hdr>(0);
    if (!maybe_ip6.ok()) {
        dbgTrace(D_PACKET)
            << "IPv6 packet is too short for an IPv6 header: "
            << l2_payload.size()
            << " < "
            << sizeof(struct ip);
        return genError(PktErr::PKT_TOO_SHORT_FOR_IP_HEADER);
    }
    auto ip6 = maybe_ip6.unpack();

    uint ip_version = (ip6->ip6_vfc) >> 4;
    if (ip_version != 6) {
        dbgTrace(D_PACKET) << "Bad IPv6 version " << ip_version;
        return genError(PktErr::IP_VERSION_MISMATCH);
    }

    auto l3_len_reported_by_header = sizeof(struct ip6_hdr) + ntohs(ip6->ip6_plen);
    if (l3_len_reported_by_header > l2_payload.size()) {
        dbgTrace(D_PACKET) <<
            "IP header reports a total of " << l3_len_reported_by_header <<
            " bytes, but the packet length is only " << l2_payload.size() << " bytes";
        return genError(PktErr::IP_SIZE_MISMATCH);
    }

    l3 = l2_payload.getSubBuffer(0, l3_len_reported_by_header); // Remove padding

    auto proto = getIPv6Proto(ip6->ip6_nxt);
    if (!proto.ok()) return genError(proto.getErr());

    return parseFromL4(IPAddr(ip6->ip6_src), IPAddr(ip6->ip6_dst), proto.unpack());
}

Maybe<ConnKey, PktErr>
Packet::parseFromL3v4()
{
    auto maybe_ip4 = l2_payload.getTypePtr<struct ip>(0);
    if (!maybe_ip4.ok()) {
        dbgTrace(D_PACKET)
            << "IPv4 packet is too short for an IPv4 header: "
            << l2_payload.size()
            << "<"
            << sizeof(struct ip);
        return genError(PktErr::PKT_TOO_SHORT_FOR_IP_HEADER);
    }
    auto ip4 = maybe_ip4.unpack();

    uint ip_version = ip4->ip_v;
    if (ip_version != 4) {
        dbgTrace(D_PACKET) << "Bad IPv4 version " << ip_version << " length: " << ntohs(ip4->ip_len);
        return genError(PktErr::IP_VERSION_MISMATCH);
    }

    auto l3_len_reported_by_header = ntohs(ip4->ip_len);
    if (l3_len_reported_by_header < sizeof(struct ip)) {
        dbgTrace(D_PACKET) <<
            "IPv4 payload length is smaller than the IPv4 header: " <<
            l3_len_reported_by_header << " < " << sizeof(struct ip);
        return genError(PktErr::IP_SIZE_MISMATCH);
    }
    if (l3_len_reported_by_header > l2_payload.size()) {
        dbgTrace(D_PACKET) <<
            "IP header reports a total of "  << l3_len_reported_by_header <<
            " bytes, but the packet length is only " << l2_payload.size() << " bytes";
        return genError(PktErr::IP_SIZE_MISMATCH);
    }

    auto l3_hdr_len = ip4->ip_hl * sizeof(int);
    if (l3_hdr_len < sizeof(struct ip)) {
        dbgTrace(D_PACKET)
            << "The reported IPv4 header length is smaller than the allowed minimum: "
            << l3_hdr_len
            << " < "
            <<  sizeof(struct ip);
        return genError(PktErr::IP_HEADER_TOO_SMALL);
    }
    if (l3_hdr_len > l2_payload.size()) {
        dbgTrace(D_PACKET)
            << "IPv4 header is too big for the IPv4 packet: "
            << l3_hdr_len
            << " > "
            << l2_payload.size();
        return genError(PktErr::PKT_TOO_SHORT_FOR_IP_HEADER);
    }

    auto frag_offset = ntohs(ip4->ip_off);
    if ((frag_offset & IP_OFFMASK) || (frag_offset & IP_MF)) {
        dbgTrace(D_PACKET) << "Fragmented IPv4 packet";
        is_fragment = true;
    }

    l3 = l2_payload.getSubBuffer(0, l3_len_reported_by_header); // Remove padding
    l3_header = l3.getSubBuffer(0, l3_hdr_len);
    l3_payload = l3.getSubBuffer(l3_hdr_len, l3.size());

    return parseFromL4(IPAddr(ip4->ip_src), IPAddr(ip4->ip_dst), ip4->ip_p);
}

Maybe<ConnKey, PktErr>
Packet::parseFromL2()
{
    // In case of VLAN we want to remove the additional information and pass the packet as normal.
    uint _maclen = sizeof(struct ether_header) - 4;  // -4 for the first do loop.
    uint16_t ether_type;
    do
    {
        _maclen += 4;  // 4 is the size of vlan tag.
        auto maybe_ether_type = pkt_data.getTypePtr<uint16_t>(_maclen - 2); // Last 2 Bytes contain the ether type.
        if (!maybe_ether_type.ok()) {
            dbgTrace(D_PACKET)
                << "VLAN tag length is greater than the packet length: "
                << _maclen
                << " > "
                << pkt_data.size();
            return genError(PktErr::MAC_LEN_TOO_BIG);
        }
        ether_type = *(maybe_ether_type.unpack());
    } while (ether_type == constHTONS(ETHERTYPE_VLAN));

    l2_header = pkt_data.getSubBuffer(0, _maclen);
    l2_payload = pkt_data.getSubBuffer(_maclen, pkt_data.size());

    switch (ether_type) {
        case constHTONS(ETHERTYPE_IP): {
            return parseFromL3v4();
        }
        case constHTONS(ETHERTYPE_IPV6): {
            return parseFromL3v6();
        }
        default: {
            dbgTrace(D_PACKET) << "Unsupported Ethernet type: " << ether_type;
            return genError(PktErr::NON_IP_PACKET);
        }
    }
}

Maybe<ConnKey, PktErr>
Packet::parsePacket(PktType type, IPType proto)
{
    if (type == PktType::PKT_L2) return parseFromL2();

    l2_payload = pkt_data;
    switch (proto) {
        case IPType::V4: {
            return parseFromL3v4();
        }
        case IPType::V6: {
            return parseFromL3v6();
        }
        default: {
            dbgAssert(false) << "Unknown (neither IPv4, nor IPv6), or uninitialized packet type: " << proto;
        }
    }

    return genError(PktErr::UNKNOWN_L3_PROTOCOL);
}

std::vector<u_char>
Packet::getL2DataVec() const
{
    auto p = pkt_data.data();
    std::vector<u_char> buf(p, p+pkt_data.size());
    return buf;
}

void
Packet::setInterface(NetworkIfNum value)
{
    interface = value;
    is_interface = true;
}

void
Packet::setZecoOpaque(u_int64_t value)
{
    zeco_opaque = value;
    has_zeco_opaque = true;
}

Maybe<NetworkIfNum>
Packet::getInterface() const
{
    if (!is_interface) return genError("Could not set an interface to send the packet");
    return interface;
}

Maybe<u_int64_t>
Packet::getZecoOpaque() const
{
    if (!has_zeco_opaque) return genError("Could not get the zeco opaque");
    return zeco_opaque;
}
