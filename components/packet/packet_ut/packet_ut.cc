#include <string>
#include <sstream>

#include "cptest.h"
#include "packet.h"
#include "c_common/network_defs.h"
#include "config.h"
#include "config_component.h"

using namespace std;
using namespace testing;

// !!!!!!!!!! NOTE !!!!!!!!!!
// If you are wondering how the hell to read the hex dumps, or how to make new tests -
// Wireshark has an option (under the File menu) to import hex dumps.

static const uint mac_len = 14;
static const uint ipv4_basic_hdr_size = 20;
static const uint ipv6_basic_hdr_size = 40;
static const uint tcp_basic_hdr_size = 20;
static const uint udp_hdr_size = 8;

// Using IsError(Maybe<T>) requires T to be printable. So we need to print unique_ptr<Packet>:
static ostream &
operator<<(ostream &os, const unique_ptr<Packet> &p)
{
    return os << "unique_ptr<Packet>(" << p.get() << ")";
}

class PacketTest : public Test
{
public:
    ConnKey v4_key, v6_key;

    PacketTest()
            :
        v4_key(
            IPAddr::createIPAddr("172.23.34.11").unpack(),
            0xae59,
            IPAddr::createIPAddr("172.23.53.31").unpack(),
            80,
            6
        ),
        v6_key(
            IPAddr::createIPAddr("2001:6f8:102d:0:2d0:9ff:fee3:e8de").unpack(),
            59201,
            IPAddr::createIPAddr("2001:6f8:900:7c0::2").unpack(),
            80,
            6
        )
    {
    }

    Maybe<unique_ptr<Packet>, PktErr>
    getV4PacketL2()
    {
        // IPv4 TCP with 12 bytes of TCP options, 0 data
        auto v = cptestParseHex(
            "0000:  cc d8 c1 b1 cc 77 00 50 56 b9 4f 5c 08 00 45 00 "
            "0010:  00 34 93 24 40 00 40 06 f8 46 ac 17 22 0b ac 17 "
            "0020:  35 1f ae 59 00 50 1a bb 79 14 5f 45 dc 97 80 10 "
            "0030:  00 6c 1a 8c 00 00 01 01 08 0a ff fe eb 97 68 00 "
            "0040:  da 7e                                           "
        );
        return Packet::genPacket(PktType::PKT_L2, IPType::V4, v);
    }

    Maybe<unique_ptr<Packet>, PktErr>
    getV4PacketL3()
    {
        // IPv4 TCP with 12 bytes of TCP options, 0 data
        auto v = cptestParseHex(
            "0000:  45 00 00 34 93 24 40 00 40 06 f8 46 ac 17 22 0b "
            "0010:  ac 17 35 1f ae 59 00 50 1a bb 79 14 5f 45 dc 97 "
            "0020:  80 10 00 6c 1a 8c 00 00 01 01 08 0a ff fe eb 97 "
            "0030:  68 00 da 7e                                     "
        );
        return Packet::genPacket(PktType::PKT_L3, IPType::V4, v);
    }

    Maybe<unique_ptr<Packet>, PktErr>
    getV6PacketL2()
    {
        // IPv6 TCP with 20 bytes of TCP options, 0 data
        auto v = cptestParseHex(
            "0000:  00 11 25 82 95 b5 00 d0 09 e3 e8 de 86 dd 60 00 "
            "0010:  00 00 00 28 06 40 20 01 06 f8 10 2d 00 00 02 d0 "
            "0020:  09 ff fe e3 e8 de 20 01 06 f8 09 00 07 c0 00 00 "
            "0030:  00 00 00 00 00 02 e7 41 00 50 ab dc d6 60 00 00 "
            "0040:  00 00 a0 02 16 80 41 a2 00 00 02 04 05 a0 04 02 "
            "0050:  08 0a 00 0a 22 a8 00 00 00 00 01 03 03 05       "
        );
        return Packet::genPacket(PktType::PKT_L2, IPType::V6, v);
    }
};

TEST_F(PacketTest, check_zeco_opaque)
{
    auto v4_pkt = getV4PacketL2().unpackMove();
    auto zeco_opaque = v4_pkt->getZecoOpaque();
    EXPECT_FALSE(zeco_opaque.ok());

    v4_pkt->setZecoOpaque(11);

    zeco_opaque = v4_pkt->getZecoOpaque();
    EXPECT_TRUE(zeco_opaque.ok());
    EXPECT_EQ(zeco_opaque.unpack(), 11u);
}

TEST_F(PacketTest, check_fixture_ctor)
{
    EXPECT_TRUE(getV4PacketL2().ok());
    EXPECT_TRUE(getV6PacketL2().ok());
}

TEST_F(PacketTest, l2_v4_good)
{
    auto v4_pkt = getV4PacketL2().unpackMove();
    EXPECT_EQ(v4_pkt->getPacket().size(), mac_len + 52);
    EXPECT_EQ(v4_pkt->getL3().size(), 52u);
    EXPECT_EQ(v4_pkt->getL3Header().size(), ipv4_basic_hdr_size);
    EXPECT_EQ(v4_pkt->getL4Header().size(), tcp_basic_hdr_size + 12);
    Buffer l2_buf = v4_pkt->getPacket();
    l2_buf.truncateHead(mac_len);
    EXPECT_EQ(v4_pkt->getL3(), l2_buf);
    EXPECT_EQ(v4_pkt->getKey(), v4_key);
}

TEST_F(PacketTest, l3_v4_good)
{
    auto v4_pkt = getV4PacketL3().unpackMove();
    EXPECT_EQ(v4_pkt->getPacket().size(), 52u);
    EXPECT_EQ(v4_pkt->getL3().size(), 52u);
    EXPECT_EQ(v4_pkt->getL3Header().size(), ipv4_basic_hdr_size);
    EXPECT_EQ(v4_pkt->getL4Header().size(), tcp_basic_hdr_size + 12);
    Buffer l2_buf = v4_pkt->getPacket();
    EXPECT_EQ(v4_pkt->getL3(), l2_buf);
    EXPECT_EQ(v4_pkt->getKey(), v4_key);
}

TEST_F(PacketTest, v6_good)
{
    auto v6_pkt = getV6PacketL2().unpackMove();
    EXPECT_EQ(v6_pkt->getPacket().size(), mac_len + 80);
    EXPECT_EQ(v6_pkt->getL3().size(), 80u);
    EXPECT_EQ(v6_pkt->getL3Header().size(), ipv6_basic_hdr_size);
    EXPECT_EQ(v6_pkt->getL4Header().size(), tcp_basic_hdr_size + 20);
    Buffer l2_buf = v6_pkt->getPacket();
    l2_buf.truncateHead(mac_len);
    EXPECT_EQ(v6_pkt->getL3(), l2_buf);
    EXPECT_EQ(v6_pkt->getKey(), v6_key);
}

TEST_F(PacketTest, l2_v4_get_l4)
{
    auto v4_pkt = getV4PacketL2().unpackMove();
    Buffer buf = v4_pkt->getL4Data();
    EXPECT_EQ(buf.size(), 0u);
}

TEST_F(PacketTest, l3_v4_get_l4)
{
    auto v4_pkt = getV4PacketL3().unpackMove();
    Buffer buf = v4_pkt->getL4Data();
    EXPECT_EQ(buf.size(), 0u);
}


TEST_F(PacketTest, v6_get_l4)
{
    auto v6_pkt = getV6PacketL2().unpackMove();
    Buffer buf = v6_pkt->getL4Data();
    EXPECT_EQ(buf.size(), 0u);
}

TEST(Packet, packet_with_padding)
{
    ConnKey ck(
        IPAddr::createIPAddr("192.168.170.8").unpack(),
        32795,
        IPAddr::createIPAddr("192.168.170.20").unpack(),
        53,
        17
    );
    auto v = cptestParseHex(
        "0000:  00 c0 9f 32 41 8c 00 e0 18 b1 0c ad 08 00 45 00 "
        "0010:  00 3d 00 00 40 00 40 11 65 42 c0 a8 aa 08 c0 a8 "
        "0020:  aa 14 80 1b 00 35 00 29 88 61 bc 1f 01 00 00 01 "
        "0030:  00 00 00 00 00 00 03 77 77 77 07 65 78 61 6d 70 "
        "0040:  6c 65 03 63 6f 6d 00 00 1c 00 01 00 00 00 00 00 "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V4, v);
    ASSERT_TRUE(ptr.ok());
    auto p = ptr.unpackMove();

    EXPECT_EQ(p->getL3().size(), 61u); // True size as reported by IP header.
    EXPECT_EQ(p->getL3Header().size(), ipv4_basic_hdr_size);
    EXPECT_EQ(p->getL4Header().size(), udp_hdr_size);
    EXPECT_EQ(p->getKey(), ck);
    EXPECT_EQ(p->getL4Data().size(), 33u);
}


TEST(Packet, v4_ip_options)
{
    ConnKey ck(
        IPAddr::createIPAddr("172.23.34.11").unpack(),
        44633,
        IPAddr::createIPAddr("172.23.53.31").unpack(),
        80,
        6
    );
    auto v = cptestParseHex(
        "0000:  cc d8 c1 b1 cc 77 00 50 56 b9 4f 5c 08 00 47 00 " // Modified: 4500 => 4700 for 2 option ints.
        "0010:  00 3c 93 24 40 00 40 06 f8 46 ac 17 22 0b ac 17 "
        "0020:  35 1f 01 04 12 34 56 78 00 00 ae 59 00 50 1a bb " // Inserted IP options: NOP; EOL;
        "0030:  79 14 5f 45 dc 97 80 10 00 6c 1a 8c 00 00 01 01 "
        "0040:  08 0a ff fe eb 97 68 00 da 7e                   "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V4, v);
    ASSERT_TRUE(ptr.ok());
    auto p = ptr.unpackMove();

    EXPECT_EQ(p->getKey(), ck);
    EXPECT_EQ(p->getL3().size(), 60u);
    EXPECT_EQ(p->getL3Header().size(), ipv4_basic_hdr_size + 8); // 8 bytes IP options
    EXPECT_EQ(p->getL4Header().size(), tcp_basic_hdr_size + 12); // 12 bytes TCP options

    // Get L4 fields
    EXPECT_EQ(p->getL4Data().size(), 0u);
}

TEST(Packet, l2_v4_udp)
{
    ConnKey ck(
        IPAddr::createIPAddr("192.168.170.8").unpack(),
        32795,
        IPAddr::createIPAddr("192.168.170.20").unpack(),
        53,
        17
    );
    auto v = cptestParseHex(
        "0000:  00 c0 9f 32 41 8c 00 e0 18 b1 0c ad 08 00 45 00 "
        "0010:  00 3d 00 00 40 00 40 11 65 42 c0 a8 aa 08 c0 a8 "
        "0020:  aa 14 80 1b 00 35 00 29 88 61 bc 1f 01 00 00 01 "
        "0030:  00 00 00 00 00 00 03 77 77 77 07 65 78 61 6d 70 "
        "0040:  6c 65 03 63 6f 6d 00 00 1c 00 01                "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V4, v);
    ASSERT_TRUE(ptr.ok());
    auto p = ptr.unpackMove();

    EXPECT_EQ(p->getL3().size(), 61u);
    EXPECT_EQ(p->getL3Header().size(), ipv4_basic_hdr_size);
    EXPECT_EQ(p->getL4Header().size(), udp_hdr_size);
    EXPECT_EQ(p->getKey(), ck);

    EXPECT_EQ(p->getL4Data().size(), 33u);
}

TEST(Packet, l3_v4_udp)
{
    ConnKey ck(
        IPAddr::createIPAddr("192.168.170.8").unpack(),
        32795,
        IPAddr::createIPAddr("192.168.170.20").unpack(),
        53,
        17
    );
    auto v = cptestParseHex(
        "0000:  45 00 00 3d 00 00 40 00 40 11 65 42 c0 a8 aa 08 "
        "0010:  c0 a8 aa 14 80 1b 00 35 00 29 88 61 bc 1f 01 00 "
        "0020:  00 01 00 00 00 00 00 00 03 77 77 77 07 65 78 61 "
        "0030:  6d 70 6c 65 03 63 6f 6d 00 00 1c 00 01          "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L3, IPType::V4, v);
    ASSERT_TRUE(ptr.ok());
    auto p = ptr.unpackMove();

    EXPECT_EQ(p->getL3().size(), 61u);
    EXPECT_EQ(p->getL3Header().size(), ipv4_basic_hdr_size);
    EXPECT_EQ(p->getL4Header().size(), udp_hdr_size);
    EXPECT_EQ(p->getKey(), ck);

    EXPECT_EQ(p->getL4Data().size(), 33u);
}

TEST(Packet, v6_ping)
{
    ::Environment env;
    ConfigComponent config_comp;
    ConnKey ck(
        IPAddr::createIPAddr("3ffe:507:0:1:200:86ff:fe05:80da").unpack(),
        31520,
        IPAddr::createIPAddr("3ffe:507:0:1:260:97ff:fe07:69ea").unpack(),
        1024,
        58
    );
    auto v = cptestParseHex(
        "0000:  00 60 97 07 69 ea 00 00 86 05 80 da 86 dd 60 00 "
        "0010:  00 00 00 10 3a 40 3f fe 05 07 00 00 00 01 02 00 "
        "0020:  86 ff fe 05 80 da 3f fe 05 07 00 00 00 01 02 60 "
        "0030:  97 ff fe 07 69 ea 80 00 ae 76 7b 20 04 00 1d c9 "
        "0040:  e7 36 ad df 0b 00                               "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V6, v);
    ASSERT_TRUE(ptr.ok());
    auto p = ptr.unpackMove();

    EXPECT_EQ(p->getL3().size(), 56u);
    EXPECT_EQ(p->getL3Header().size(), ipv6_basic_hdr_size);
    EXPECT_EQ(p->getL4Header().size(), sizeof(struct icmp6_hdr));
    EXPECT_EQ(p->getKey(), ck);
}

TEST(Packet, v6_IPPROTO_ROUTING_extension_hdr)
{
    // IPv6 TCP packet with IPPROTO_ROUTING extension header (56 bytes), 20 bytes of data
    ConnKey ck(
        IPAddr::createIPAddr("3001::200:1080:8110:11fe").unpack(),
        32768,
        IPAddr::createIPAddr("3000::215:1780:8116:b881").unpack(),
        80,
        6
    );
    auto v = cptestParseHex(
        "0000: 00 60 97 07 69 ea 00 00 86 05 80 da 86 dd 60 00 "
        "0010: 00 00 00 60 2b 80 30 01 00 00 00 00 00 00 02 00 "
        "0020: 10 80 81 10 11 fe 30 00 00 00 00 00 00 00 02 15 "
        "0030: 17 80 81 16 b8 81 06 06 00 01 00 00 00 00 30 02 "
        "0040: 00 00 00 00 00 00 02 00 10 80 81 10 12 62 30 03 "
        "0050: 00 00 00 00 00 00 02 00 10 80 81 10 10 60 ff 00 "
        "0060: 1d 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 "
        "0070: 00 50 11 11 11 11 22 22 22 22 50 18 67 68 2b d2 "
        "0080: 00 00 6d 6e 6f 70 71 72 73 74 75 76 77 61 62 63 "
        "0090: 64 65 66 67 68 69                               "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V6, v);
    ASSERT_TRUE(ptr.ok());
    auto p = ptr.unpackMove();

    static const uint routing_ext_hdr_size = 56;
    static const uint total_packet_len  = 150;

    EXPECT_EQ(p->getPacket().size(), total_packet_len);
    EXPECT_EQ(p->getL3().size(), total_packet_len - mac_len);
    EXPECT_EQ(p->getL3Header().size(), ipv6_basic_hdr_size + routing_ext_hdr_size);
    EXPECT_EQ(p->getL4Header().size(), tcp_basic_hdr_size);
    EXPECT_EQ(p->getKey(), ck);
    EXPECT_EQ(p->getL4Data().size(), 20u);
}


TEST(Packet, v6_IPPROTO_HOPOPT_and_IPPROTO_ROUTING_ext_hdrs)
{
    ConnKey ck(
        IPAddr::createIPAddr("3001::200:1080:8110:11fe").unpack(),
        32768,
        IPAddr::createIPAddr("3000::215:1780:8116:b881").unpack(),
        58205,
        17
    );
    auto v = cptestParseHex(
        "0000: 00 60 97 07 69 ea 00 00 86 05 80 da 86 dd 60 00 "
        "0010: 00 00 00 70 00 80 30 01 00 00 00 00 00 00 02 00 "
        "0020: 10 80 81 10 11 fe 30 00 00 00 00 00 00 00 02 15 "
        "0030: 17 80 81 16 b8 81 2b 01 00 00 00 00 00 00 00 00 "
        "0040: 00 00 00 00 00 00 11 06 00 01 00 00 00 00 30 02 "
        "0050: 00 00 00 00 00 00 02 00 10 80 81 10 12 62 30 03 "
        "0060: 00 00 00 00 00 00 02 00 10 80 81 10 10 60 ff 00 "
        "0070: 1d 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 "
        "0080: e3 5d 00 28 00 0c 61 62 63 64 65 66 67 68 69 6a "
        "0090: 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 61 62 63 "
        "00a0: 64 65 66 67 68 69                               "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V6, v);
    ASSERT_TRUE(ptr.ok());
    auto p = ptr.unpackMove();

    static const uint routing_ext_hdr_size = 56;
    static const uint hop_ext_hdr_size = 16;
    static const uint total_packet_len  = 166;
    static const uint total_extensions_size = routing_ext_hdr_size + hop_ext_hdr_size;

    EXPECT_EQ(p->getPacket().size(), total_packet_len);
    EXPECT_EQ(p->getL3().size(), total_packet_len - mac_len);
    EXPECT_EQ(p->getL3Header().size(), ipv6_basic_hdr_size + total_extensions_size);
    EXPECT_EQ(p->getL4Header().size(), udp_hdr_size);
    EXPECT_EQ(p->getKey(), ck);

    EXPECT_EQ(p->getL4Data().size(), 32u);
}

TEST(Packet, DISABLED_non_ethernet_mac_len)
{
    auto v = cptestParseHex(
        "0000:  cc d8 c1 b1 cc 77 00 50 56 b9 4f 5c 08 00 45 00 "
        "0010:  00 34 93 24 40 00 40 06 f8 46 ac 17 22 0b ac 17 "
        "0020:  35 1f ae 59 00 50 1a bb 79 14 5f 45 dc 97 80 10 "
        "0030:  00 6c 1a 8c 00 00 01 01 08 0a ff fe eb 97 68 00 "
        "0040:  da 7e                                           "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V4, v);
    EXPECT_THAT(ptr, IsError(PktErr::NON_ETHERNET_FRAME));
}

TEST(Packet, DISABLED_too_big_mac_len)
{
    auto v = cptestParseHex(
        "0000:  cc d8 c1 b1 cc 77 00 50 56 b9 4f 5c 08 00 45 00 "
        "0010:  00 34 93 24 40 00 40 06 f8 46 ac 17 22 0b ac 17 "
        "0020:  35 1f ae 59 00 50 1a bb 79 14 5f 45 dc 97 80 10 "
        "0030:  00 6c 1a 8c 00 00 01                            "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V4, v);
    EXPECT_THAT(ptr, IsError(PktErr::MAC_LEN_TOO_BIG));
}

TEST(Packet, non_ip_packet)
{
    auto v = cptestParseHex(
        "0000:  cc d8 c1 b1 cc 77 00 50 56 b9 4f 5c 08 88 45 00 "
        "0010:  00 34 93 24 40 00 40 06 f8 46 ac 17 22 0b ac 17 "
        "0020:  35 1f ae 59 00 50 1a bb 79 14 5f 45 dc 97 80 10 "
        "0030:  00 6c 1a 8c 00 00 01                            "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V4, v);
    EXPECT_THAT(ptr, IsError(PktErr::NON_IP_PACKET));
}

TEST(Packet, version_mismatch_v4)
{
    // Valid IPv4 packet, but Ethernet header says it is IPv6
    auto v = cptestParseHex(
        "0000:  cc d8 c1 b1 cc 77 00 50 56 b9 4f 5c 86 dd 45 00 "
        "0010:  00 34 93 24 40 00 40 06 f8 46 ac 17 22 0b ac 17 "
        "0020:  35 1f ae 59 00 50 1a bb 79 14 5f 45 dc 97 80 10 "
        "0030:  00 6c 1a 8c 00 00 01 01 08 0a ff fe eb 97 68 00 "
        "0040:  da 7e                                           "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V4, v);
    EXPECT_THAT(ptr, IsError(PktErr::IP_VERSION_MISMATCH));
}

TEST(Packet, version_mismatch_v6)
{
    // Valid IPv6 packet, but Ethernet header says it is IPv4
    auto v = cptestParseHex(
        "0000:  00 11 25 82 95 b5 00 d0 09 e3 e8 de 08 00 60 00 "
        "0010:  00 00 00 28 06 40 20 01 06 f8 10 2d 00 00 02 d0 "
        "0020:  09 ff fe e3 e8 de 20 01 06 f8 09 00 07 c0 00 00 "
        "0030:  00 00 00 00 00 02 e7 41 00 50 ab dc d6 60 00 00 "
        "0040:  00 00 a0 02 16 80 41 a2 00 00 02 04 05 a0 04 02 "
        "0050:  08 0a 00 0a 22 a8 00 00 00 00 01 03 03 05       "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V6, v);
    EXPECT_THAT(ptr, IsError(PktErr::IP_VERSION_MISMATCH));
}

TEST(Packet, empty_frame_v4)
{
    auto v = cptestParseHex(
        "0000:  00 c0 9f 32 41 8c 00 e0 18 b1 0c ad 08 00 "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V4, v);
    EXPECT_THAT(ptr, IsError(PktErr::PKT_TOO_SHORT_FOR_IP_HEADER));
}

TEST(Packet, empty_frame_v6)
{
    auto v = cptestParseHex(
        "0000:  00 c0 9f 32 41 8c 00 e0 18 b1 0c ad 86 dd "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V4, v);
    EXPECT_THAT(ptr, IsError(PktErr::PKT_TOO_SHORT_FOR_IP_HEADER));
}

TEST(Packet, ipv4_pkt_no_room_for_header)
{
    auto v = cptestParseHex(
        "0000:  00 c0 9f 32 41 8c 00 e0 18 b1 0c ad 08 00 45 00 "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V4, v);
    EXPECT_THAT(ptr, IsError(PktErr::PKT_TOO_SHORT_FOR_IP_HEADER));
}

TEST(Packet, ipv4_pkt_no_room_for_header_with_options)
{
    auto v = cptestParseHex(
        "0000:  00 c0 9f 32 41 8c 00 e0 18 b1 0c ad 08 00 48 00 "
        "0010:  00 1c 00 00 40 00 40 11 65 42 c0 a8 aa 08 c0 a8 "
        "0020:  aa 14 80 1b 00 35 00 29 88 61                   "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V4, v);
    EXPECT_THAT(ptr, IsError(PktErr::PKT_TOO_SHORT_FOR_IP_HEADER));
}

TEST(Packet, ipv6_pkt_no_room_for_header)
{
    auto v = cptestParseHex(
        "0000:  00 c0 9f 32 41 8c 00 e0 18 b1 0c ad 86 dd 60 00 "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V6, v);
    EXPECT_THAT(ptr, IsError(PktErr::PKT_TOO_SHORT_FOR_IP_HEADER));
}

TEST(Packet, ipv4_payload_length_smaller_than_ipv4_header)
{
    auto v = cptestParseHex(
        "0000:  00 c0 9f 32 41 8c 00 e0 18 b1 0c ad 08 00 45 00 "
        "0010:  00 10 00 00 40 00 40 11 65 42 c0 a8 aa 08 c0 a8 "
        "0020:  aa 14                                           "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V4, v);
    EXPECT_THAT(ptr, IsError(PktErr::IP_SIZE_MISMATCH));
}

TEST(Packet, v6_ext_hdr_not_complete)
{
    // IPv6 packet with IPPROTO_HOPOPTS cut at the middle of the header
    auto v = cptestParseHex(
        "0000: 00 60 97 07 69 ea 00 00 86 05 80 da 86 dd 60 00 "
        "0010: 00 00 00 01 00 80 30 01 00 00 00 00 00 00 02 00 "
        "0020: 10 80 81 10 11 fe 30 00 00 00 00 00 00 00 02 15 "
        "0030: 17 80 81 16 b8 81 3a                            "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V6, v);
    EXPECT_THAT(ptr, IsError(PktErr::PKT_TOO_SHORT_FOR_IP_EXTENSION_HEADER));
}


TEST(Packet, v6_no_room_for_ext_hdr_body)
{
    // IPv6 packet with IPPROTO_HOPOPTS ext header specified as 16 bytes, but packet too short
    auto v = cptestParseHex(
        "0000: 00 60 97 07 69 ea 00 00 86 05 80 da 86 dd 60 00 "
        "0010: 00 00 00 02 00 80 30 01 00 00 00 00 00 00 02 00 "
        "0020: 10 80 81 10 11 fe 30 00 00 00 00 00 00 00 02 15 "
        "0030: 17 80 81 16 b8 81 3a 01                         "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V6, v);
    EXPECT_THAT(ptr, IsError(PktErr::PKT_TOO_SHORT_FOR_IP_EXTENSION_HEADER_BODY));
}


TEST(Packet, ipv4_size_mismatch)
{
    auto v = cptestParseHex(
        "0000:  cc d8 c1 b1 cc 77 00 50 56 b9 4f 5c 08 00 45 00 "
        "0010:  00 35 93 24 40 00 40 06 f8 46 ac 17 22 0b ac 17 "
        "0020:  35 1f ae 59 00 50 1a bb 79 14 5f 45 dc 97 80 10 "
        "0030:  00 6c 1a 8c 00 00 01 01 08 0a ff fe eb 97 68 00 "
        "0040:  da 7e                                           "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V4, v);
    EXPECT_THAT(ptr, IsError(PktErr::IP_SIZE_MISMATCH));
}

TEST(Packet, ipv6_size_mismatch)
{
    auto v = cptestParseHex(
        "0000:  00 11 25 82 95 b5 00 d0 09 e3 e8 de 86 dd 60 00 "
        "0010:  00 00 00 29 06 40 20 01 06 f8 10 2d 00 00 02 d0 "
        "0020:  09 ff fe e3 e8 de 20 01 06 f8 09 00 07 c0 00 00 "
        "0030:  00 00 00 00 00 02 e7 41 00 50 ab dc d6 60 00 00 "
        "0040:  00 00 a0 02 16 80 41 a2 00 00 02 04 05 a0 04 02 "
        "0050:  08 0a 00 0a 22 a8 00 00 00 00 01 03 03 05       "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V6, v);
    EXPECT_THAT(ptr, IsError(PktErr::IP_SIZE_MISMATCH));
}


TEST(Packet, no_room_for_udp_header)
{
    auto v = cptestParseHex(
        "0000:  cc d8 c1 b1 cc 77 00 50 56 b9 4f 5c 08 00 45 00 "
        "0010:  00 18 93 24 40 00 40 11 f8 57 ac 17 22 0b ac 17 "
        "0020:  35 1f ae 59 00 50                               "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V4, v);
    EXPECT_THAT(ptr, IsError(PktErr::PKT_TOO_SHORT_FOR_L4_HEADER));
}

TEST(Packet, no_room_for_tcp_header)
{
    auto v = cptestParseHex(
        "0000:  cc d8 c1 b1 cc 77 00 50 56 b9 4f 5c 08 00 45 00 "
        "0010:  00 22 93 24 40 00 40 06 f8 58 ac 17 22 0b ac 17 "
        "0020:  35 1f ae 59 00 50 1a bb 79 14 5f 45 dc 97 80 10 "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V4, v);
    EXPECT_THAT(ptr, IsError(PktErr::PKT_TOO_SHORT_FOR_L4_HEADER));
}

TEST(Packet, tcp_header_len_too_short)
{
    auto v = cptestParseHex(
        "0000:  cc d8 c1 b1 cc 77 00 50 56 b9 4f 5c 08 00 45 00 "
        "0010:  00 28 93 24 40 00 40 06 f8 52 ac 17 22 0b ac 17 "
        "0020:  35 1f ae 59 00 50 1a bb 79 14 5f 45 dc 97 20 10 "
        "0030:  00 6c 1a 8c 00 00                               "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V4, v);
    EXPECT_THAT(ptr, IsError(PktErr::TCP_HEADER_TOO_SMALL));
}


TEST(Packet, tcp_header_len_too_big)
{
    auto v = cptestParseHex(
        "0000:  cc d8 c1 b1 cc 77 00 50 56 b9 4f 5c 08 00 45 00 "
        "0010:  00 29 93 24 40 00 40 06 f8 51 ac 17 22 0b ac 17 "
        "0020:  35 1f ae 59 00 50 1a bb 79 14 5f 45 dc 97 80 10 "
        "0030:  00 6c 1a 8c 00 00 01                            "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V4, v);
    EXPECT_THAT(ptr, IsError(PktErr::PKT_TOO_SHORT_FOR_TCP_OPTIONS));
}

TEST(Packet, get_l2_data_vec)
{
    auto v = cptestParseHex(        // Same as v4_udp
        "0000:  00 c0 9f 32 41 8c 00 e0 18 b1 0c ad 08 00 45 00 "
        "0010:  00 3d 00 00 40 00 40 11 65 42 c0 a8 aa 08 c0 a8 "
        "0020:  aa 14 80 1b 00 35 00 29 88 61 bc 1f 01 00 00 01 "
        "0030:  00 00 00 00 00 00 03 77 77 77 07 65 78 61 6d 70 "
        "0040:  6c 65 03 63 6f 6d 00 00 1c 00 01                "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V4, v);

    EXPECT_EQ(v, (*ptr)->getL2DataVec());
}

TEST(Packet, interface_set_and_get)
{
    auto v = cptestParseHex(              // Same as v4_udp
        "0000:  00 c0 9f 32 41 8c 00 e0 18 b1 0c ad 08 00 45 00 "
        "0010:  00 3d 00 00 40 00 40 11 65 42 c0 a8 aa 08 c0 a8 "
        "0020:  aa 14 80 1b 00 35 00 29 88 61 bc 1f 01 00 00 01 "
        "0030:  00 00 00 00 00 00 03 77 77 77 07 65 78 61 6d 70 "
        "0040:  6c 65 03 63 6f 6d 00 00 1c 00 01                "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V4, v);
    auto p = ptr.unpackMove();

    EXPECT_FALSE(p->getInterface().ok());

    p->setInterface(5);
    EXPECT_TRUE(p->getInterface().ok());
    EXPECT_EQ(5, p->getInterface().unpack());

    p->setInterface(42);
    EXPECT_TRUE(p->getInterface().ok());
    EXPECT_EQ(42, p->getInterface().unpack());
}

TEST(Packet, no_room_for_icmp_header)
{
    // only 7 bytes of ICMPV4 (min is 8)
    auto v = cptestParseHex(
        "0000:  00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00 "
        "0010:  00 1b 12 34 40 00 ff 01 6b ab 7f 00 00 01 7f 00 "
        "0020:  00 01 00 00 ff fd 00 01 00                      "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V4, v);
    ASSERT_FALSE(ptr.ok());
    EXPECT_EQ(ptr.getErr(), PktErr::PKT_TOO_SHORT_FOR_L4_HEADER);
}

TEST(Packet, icmp)
{
    ::Environment env;
    ConfigComponent config_comp;
    // correct ICMPV4 packet
    auto v = cptestParseHex(
        "0000:  00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00 "
        "0010:  00 1c 12 34 40 00 ff 01 6b aa 7f 00 00 01 7f 00 "
        "0020:  00 01 00 00 ff fd 00 01 00 01 00 00 00 00 00 00 "
        "0030:  00 00 00 00 00 00 00 00 00 00 00 00             "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V4, v);
    ASSERT_TRUE(ptr.ok());
    EXPECT_EQ(ptr->get()->getKey().getProto(), IPPROTO_ICMP);
    EXPECT_EQ(ptr->get()->getPacketProto(), IPType::V4);
    auto p = ptr.unpackMove();
    auto icmp = p->getL4Header().getTypePtr<struct icmphdr>(0).unpack();
    auto checksum = ntohs(icmp->checksum);
    EXPECT_EQ(icmp->type, ICMP_ECHOREPLY);
    EXPECT_EQ(icmp->code, 0);
    EXPECT_EQ(checksum, 0xfffd);
}

TEST(Packet, no_room_for_icmpv6_header)
{
    // only 7 bytes of ICMPV6 (min is 8)
    auto v = cptestParseHex(
        "0000:  00 00 00 00 00 00 00 00 00 00 00 00 86 dd 60 00 "
        "0010:  00 00 00 07 3a ff 00 00 00 00 00 00 00 00 00 00 "
        "0020:  00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 "
        "0030:  00 00 00 00 00 01 80 00 7f bc 00 00 00          "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V6, v);
    ASSERT_FALSE(ptr.ok());
    EXPECT_EQ(ptr.getErr(), PktErr::PKT_TOO_SHORT_FOR_L4_HEADER);
}

TEST(Packet, icmpv6)
{
    ::Environment env;
    ConfigComponent config_comp;
    // correct ICMPV6 packet
    auto v = cptestParseHex(
        "0000:  00 00 00 00 00 00 00 00 00 00 00 00 86 dd 60 00 "
        "0010:  00 00 00 0c 3a ff 00 00 00 00 00 00 00 00 00 00 "
        "0020:  00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 "
        "0030:  00 00 00 00 00 01 80 00 3b 51 00 00 00 00 11 22 "
        "0040:  33 44                                           "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V6, v);
    ASSERT_TRUE(ptr.ok());
    EXPECT_EQ(ptr->get()->getKey().getProto(), IPPROTO_ICMPV6);
    EXPECT_EQ(ptr->get()->getPacketProto(), IPType::V6);
    auto p = ptr.unpackMove();
    auto icmp = p->getL4Header().getTypePtr<struct icmp6_hdr>(0).unpack();
    auto checksum = ntohs(icmp->icmp6_cksum);
    EXPECT_EQ(icmp->icmp6_type, ICMP6_ECHO_REQUEST);
    EXPECT_EQ(icmp->icmp6_code, 0);
    EXPECT_EQ(checksum, 0x3b51);
}

TEST(Packet, icmp_over_ipv6)
{
    // correct ICMPV4 packet over IPV6
    auto v = cptestParseHex(
        "0000:  00 00 00 00 00 00 00 00 00 00 00 00 86 dd 60 00 "
        "0010:  00 00 00 0c 01 ff 00 00 00 00 00 00 00 00 00 00 "
        "0020:  00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 "
        "0030:  00 00 00 00 00 01 00 00 ff fd 00 01 00 01 00 00 "
        "0040:  00 00 00 00 00 00 "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V6, v);
    EXPECT_THAT(ptr, IsError(PktErr::ICMP_VERSION_MISMATCH));
}

TEST(Packet, icmpv6_over_ipv4)
{
    // correct ICMPV6 packet over IPV4
    auto v = cptestParseHex(
        "0000:  00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00 "
        "0010:  00 1c 12 34 40 00 ff 3a 6b aa 7f 00 00 01 7f 00 "
        "0020:  00 01 80 00 3b 51 00 00 00 00 11 22 33 44 00 00 "
        "0030:  00 00 00 00 00 00 00 00 00 00 00 00             "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V4, v);
    EXPECT_THAT(ptr, IsError(PktErr::ICMP_VERSION_MISMATCH));
}

TEST(Packet, tcp_fragment_noheader)
{
    // IPv4 TCP fragmented packet with no TCP header
    auto v = cptestParseHex(
        "0000:  00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00 "
        "0010:  00 28 12 34 00 5d ff 06 00 00 7f 00 00 01 7f 00 "
        "0020:  00 01 00 00 00 50 00 00 00 64 00 00 00 64 50 00 "
        "0030:  0f a0 a1 2a 00 00 00 00 00 00 00 00             "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V4, v);
    ConnKey key(
        IPAddr::createIPAddr("127.0.0.1").unpack(), 0,
        IPAddr::createIPAddr("127.0.0.1").unpack(), 0,
        6
    );
    EXPECT_EQ(key, ptr.unpack()->getKey());
}

TEST(Packet, tcp_notfragment)
{
    // IPv4 fragmented packet with TCP header
    auto v = cptestParseHex(
        "0000:  00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00 "
        "0010:  00 28 12 34 20 00 ff 06 00 00 7f 00 00 01 7f 00 "
        "0020:  00 01 00 00 00 50 00 00 00 64 00 00 00 64 50 00 "
        "0030:  0f a0 a1 2a 00 00 00 00 00 00 00 00             "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V4, v);
    ConnKey key(
        IPAddr::createIPAddr("127.0.0.1").unpack(), 0,
        IPAddr::createIPAddr("127.0.0.1").unpack(), 0,
        6
    );
    EXPECT_EQ(key, ptr.unpack()->getKey());
}

TEST(Packet, ipv6_fragment_noheader)
{
    // IPv6 fragmented packet with no L4 header
    auto v = cptestParseHex(
        "0000:  00 1d 09 94 65 38 68 5b 35 c0 61 b6 86 dd 60 02 "
        "0010:  12 89 00 1a 2c 40 26 07 f0 10 03 f9 00 00 00 00 "
        "0020:  00 00 00 00 10 01 26 07 f0 10 03 f9 00 00 00 00 "
        "0030:  00 00 00 11 00 00 11 00 05 a9 f8 8e b4 66 68 68 "
        "0040:  68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 "
        "0050:  68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V4, v);
    ConnKey key(
        IPAddr::createIPAddr("2607:f010:3f9::1001").unpack(), 0,
        IPAddr::createIPAddr("2607:f010:3f9::11:0").unpack(), 0,
        17
    );
    EXPECT_EQ(key, ptr.unpack()->getKey());
}

TEST(Packet, ipv6_fragment_with_header)
{
    // IPv6 fragmented packet with L4 header
    auto v = cptestParseHex(
        "0000:  00 1d 09 94 65 38 68 5b 35 c0 61 b6 86 dd 60 02 "
        "0010:  12 89 00 1a 2c 40 26 07 f0 10 03 f9 00 00 00 00 "
        "0020:  00 00 00 00 10 01 26 07 f0 10 03 f9 00 00 00 00 "
        "0030:  00 00 00 11 00 00 11 00 00 01 f8 8e b4 66 18 db "
        "0040:  18 db 15 0b 79 16 06 fd 14 ff 07 29 08 07 65 78 "
        "0050:  61 6d 70 6c 65 08 07 74 65 73 74 41 70 70 08 01 "
    );
    auto ptr = Packet::genPacket(PktType::PKT_L2, IPType::V6, v);
    ConnKey key(
        IPAddr::createIPAddr("2607:f010:3f9::1001").unpack(), 0,
        IPAddr::createIPAddr("2607:f010:3f9::11:0").unpack(), 0,
        17
    );
    EXPECT_EQ(key, ptr.unpack()->getKey());
}

TEST(CDir, printout_operator)
{
    stringstream buf_c2s;
    buf_c2s << CDir::C2S;
    EXPECT_EQ(buf_c2s.str(), "c2s");

    stringstream buf_s2c;
    buf_s2c << CDir::S2C;
    EXPECT_EQ(buf_s2c.str(), "s2c");
}
