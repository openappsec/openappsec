#ifndef __PACKET_H__
#define __PACKET_H__

#include <memory>
#include <vector>
#include <ostream>

#include "connkey.h"
#include "buffer.h"
#include "maybe_res.h"
#include "type_defs.h"

enum class CDir : u_char
{
    C2S,
    S2C
};

static inline CDir
otherCDir(CDir cdir)
{
    return static_cast<CDir>(static_cast<int>(CDir::S2C) - static_cast<int>(cdir));
}

static inline std::ostream &
operator<<(std::ostream &os, CDir cdir)
{
    switch (cdir) {
        case CDir::C2S: {
            return os << "c2s";
        }
        case CDir::S2C: {
            return os << "s2c";
        }
    }
    return os << "Could not match direction of a connection - neither C2S, nor S2C (" << static_cast<int>(cdir) << ")";
}

enum class PktErr
{
    UNINITIALIZED,
    NON_ETHERNET_FRAME,
    MAC_LEN_TOO_BIG,
    NON_IP_PACKET,
    UNKNOWN_L3_PROTOCOL,

    IP_SIZE_MISMATCH,
    IP_VERSION_MISMATCH,
    IP_HEADER_TOO_SMALL,

    PKT_TOO_SHORT_FOR_IP_HEADER,
    PKT_TOO_SHORT_FOR_IP_EXTENSION_HEADER,
    PKT_TOO_SHORT_FOR_IP_EXTENSION_HEADER_BODY,
    UNKNOWN_IPV6_EXTENSION_HEADER,

    PKT_TOO_SHORT_FOR_L4_HEADER,
    PKT_TOO_SHORT_FOR_TCP_OPTIONS,
    TCP_HEADER_TOO_SMALL,

    PKT_TOO_SHORT_FOR_ICMP_ERROR_DATA,
    ICMP_VERSION_MISMATCH,
};

enum class PktType
{
    PKT_L2 = 1,
    PKT_L3 = 2,
};

std::ostream & operator<<(std::ostream &os, const PktErr &err);

USE_DEBUG_FLAG(D_PACKET);

class Packet
{
public:
    explicit Packet() {}

    template <typename... Args>
    static Maybe<std::unique_ptr<Packet>, PktErr>
    genPacket(PktType type, IPType proto, Args&&... args)
    {
        // Same as make_unique, but I can't use make unique and keep the ctor private...
        auto pkt = std::unique_ptr<Packet>(new Packet());

        pkt->setPacketType(type);
        pkt->pkt_data = Buffer(std::forward<Args>(args)...);

        auto key = pkt->parsePacket(type, proto);

        if (!key.ok()) {
            return genError(key.getErr());
        }

        dbgTrace(D_PACKET) << "Extracted key: " << *key;
        pkt->key = *key;

        return std::move(pkt);
    }

    PktType getPacketType() const { return pkt_type; }
    IPType getPacketProto() const { return key.getType(); }

    bool isFragment() const { return is_fragment; }

    const Buffer & getL4Data() const { return l4_payload; }
    const Buffer & getL4Header() const { return l4_header; }
    const Buffer & getL3() const { return l3; }
    const Buffer & getL3Data() const { return l3_payload; }
    const Buffer & getL3Header() const { return l3_header; }
    const Buffer & getL2Data() const { return l2_payload; }
    const Buffer & getL2Header() const { return l2_header; }
    const Buffer & getPacket() const { return pkt_data; }

    const ConnKey & getKey() const { return key; }

    void setInterface(NetworkIfNum value);
    Maybe<NetworkIfNum> getInterface() const;
    void setKey(const ConnKey &_key) { key = _key; }
    CDir getCDir() const { return cdir; }
    void setCDir(CDir _cdir) { cdir = _cdir; }

    void setZecoOpaque(u_int64_t _zeco_opaque);
    Maybe<u_int64_t> getZecoOpaque() const;

    // Get the data (L2 and up) as a vector. Copies everything.
    std::vector<u_char> getL2DataVec() const;

    template<class Archive>
    void
    serialize(Archive &ar, uint32_t)
    {
        ar(
            key,
            cdir,
            pkt_type,
            has_zeco_opaque,
            zeco_opaque,
            is_interface,
            is_fragment,
            interface,
            pkt_data,
            l2_header,
            l2_payload,
            l3,
            l3_header,
            l3_payload,
            l4_header,
            l4_payload
        );
    }

private:
    ConnKey key;
    CDir cdir;
    PktType pkt_type;

    bool is_interface = false;
    bool is_fragment = false;
    NetworkIfNum interface;
    Buffer pkt_data;
    Buffer l2_header;
    Buffer l2_payload;
    Buffer l3;
    Buffer l3_header;
    Buffer l3_payload;
    Buffer l4_header;
    Buffer l4_payload;
    bool has_zeco_opaque = false;
    u_int64_t zeco_opaque;

    Maybe<ConnKey, PktErr> parsePacket(PktType type, IPType proto);
    Maybe<ConnKey, PktErr> parseFromL2();
    Maybe<ConnKey, PktErr> parseFromL3v4();
    Maybe<ConnKey, PktErr> parseFromL3v6();
    Maybe<IPProto, PktErr> getIPv6Proto(IPProto proto);
    Maybe<int, PktErr> getIPv6ExtLen(uint offset_to_ext_hdr, IPProto ext_hdr_type);
    Maybe<int, PktErr> getIPv6GenericExtLen(uint offset_to_ext_hdr, uint length_multiplier);
    Maybe<ConnKey, PktErr> parseFromL4(const IPAddr &src, const IPAddr &dst, IPProto proto);

    std::tuple<PortNumber, PortNumber> getICMPPortsV6();
    std::tuple<PortNumber, PortNumber> getICMPPortsV4();
    std::tuple<PortNumber, PortNumber> getICMPPorts(IPProto proto);

    void setPacketType(const PktType _pkt_type) { pkt_type = _pkt_type; }
    Maybe<uint, PktErr> getIcmpHdrLen(IPProto proto, IPType ip_type);
};

#endif // __PACKET_H__
