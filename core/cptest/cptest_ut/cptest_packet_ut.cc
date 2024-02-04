#include "cptest/cptest_tcppacket.h"
#include <fstream>
#include "cptest.h"
#include "c_common/network_defs.h"
#include "byteorder.h"

using namespace std;
using namespace testing;

class PacketTest : public Test
{
public:
    // Extract TCP options from a packet
    static Buffer
    getOptions(const Packet *p)
    {
        auto tcpHdr = p->getL4Header();
        tcpHdr.truncateHead(sizeof(struct TcpHdr));
        return tcpHdr;
    }

    ConnKey ck4{IPAddr::createIPAddr("10.0.0.1").unpack(), 1234, IPAddr::createIPAddr("20.0.0.2").unpack(), 80, 6};
    ConnKey ck6{IPAddr::createIPAddr("10::1").unpack(), 1234, IPAddr::createIPAddr("20::2").unpack(), 80, 6};
};

TEST_F(PacketTest, base)
{
    TCPPacket p(CDir::C2S);
    EXPECT_EQ(ck4, p.build(ck4)->getKey());
}

TEST_F(PacketTest, move)
{
    TCPPacket p(CDir::C2S);
    auto p2 = std::move(p);
    EXPECT_EQ(ck4, p2.build(ck4)->getKey());
}

TEST_F(PacketTest, buildConn)
{
    auto pkt = TCPPacket(CDir::C2S).build(ck4);
    EXPECT_EQ(ck4, pkt->getKey());
}

TEST_F(PacketTest, reverse)
{
    TCPPacket p(CDir::S2C);
    ConnKey rev = ck6;
    rev.reverse();
    EXPECT_EQ(rev, p.build(ck6)->getKey());
}

TEST_F(PacketTest, payloadStr)
{
    auto pkt = TCPPacket(CDir::C2S)
        .setTCPPayload("hello")
        .build(ck4);
    EXPECT_EQ(Buffer(string("hello")), pkt->getL4Data());
}

TEST_F(PacketTest, payloadVec)
{
    auto pkt = TCPPacket(CDir::C2S)
        .setTCPPayload(vector<u_char>{'h', 'e', 'l', 'l', 'o'})
        .build(ck6);
    EXPECT_EQ(Buffer(string("hello")), pkt->getL4Data());
}

TEST_F(PacketTest, TcpParams)
{
    auto pkt = TCPPacket(CDir::C2S)
        .setTCPSeq(1234)
        .setTCPAck(5678)
        .setTCPWindow(1000)
        .setTCPFlags("SA")
        .setTCPUrgentPtr(0)
        .setTCPCksum(9999)
        .build(ck4);

    auto tcp = pkt->getL4Header().getTypePtr<struct TcpHdr>(0).unpack();

    EXPECT_EQ(constNTOHL(1234), tcp->seq);
    EXPECT_EQ(constNTOHL(5678), tcp->ack_seq);
    EXPECT_EQ(constNTOHS(1000), tcp->window);
    EXPECT_EQ(TH_SYN|TH_ACK,    tcp->flags);
    EXPECT_EQ(0,                tcp->urg_ptr);
    EXPECT_EQ(constNTOHS(9999), tcp->check);
}

TEST_F(PacketTest, getSeq)
{
    auto p = TCPPacket(CDir::C2S).setTCPSeq(1234).move();
    EXPECT_EQ(1234u, p.getTCPSeq());
}

TEST_F(PacketTest, l2HeaderV4)
{
    vector<u_char> mac = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x08, 0x00 };
    auto pkt = TCPPacket(CDir::C2S)
        .setL2Header(mac)
        .build(ck4);
    EXPECT_EQ(Buffer(vector<u_char>(mac)), pkt->getL2Header());
}

TEST_F(PacketTest, l2HeaderV6)
{
    vector<u_char> mac = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x86, 0xdd };
    auto pkt = TCPPacket(CDir::C2S)
        .setL2Header(mac)
        .build(ck6);
    EXPECT_EQ(Buffer(vector<u_char>(mac)), pkt->getL2Header());
}

TEST_F(PacketTest, optionsNop)
{
    auto pkt = TCPPacket(CDir::C2S)
        .addTCPOption(TCPOption::NOP)
        .build(ck4);

    // 1 NOP, padded with 3 more
    EXPECT_EQ(Buffer(vector<u_char>(4, '\x01')), getOptions(pkt.get()));
}

TEST_F(PacketTest, optionsNop6)
{
    auto pkt = TCPPacket(CDir::C2S)
        .addTCPOption(TCPOption::NOP)
        .addTCPOption(TCPOption::NOP)
        .addTCPOption(TCPOption::NOP)
        .addTCPOption(TCPOption::NOP)
        .addTCPOption(TCPOption::NOP)
        .addTCPOption(TCPOption::NOP)
        .build(ck6);

    // 6 NOPs, padded with 2 more
    EXPECT_EQ(Buffer(vector<u_char>(8, '\x01')), getOptions(pkt.get()));
}

TEST_F(PacketTest, optionsSACK)
{
    auto pkt = TCPPacket(CDir::C2S)
        .addTCPOption(TCPOption::SACK_PERMITTED)
        .build(ck4);

    // SACK_PERMITTED, len=2, 2 NOP padding
    EXPECT_EQ(Buffer(vector<u_char>{'\x04', '\x02', '\x01', '\x01'}), getOptions(pkt.get()));
}

TEST_F(PacketTest, optionsWscale)
{
    auto pkt = TCPPacket(CDir::C2S)
        .addTCPOption(TCPOption::windowScaling(5))
        .build(ck6);

    // Scaling, len=3, shift=5, 1 NOP padding
    EXPECT_EQ(Buffer(vector<u_char>{'\x03', '\x03', '\x05', '\x01'}), getOptions(pkt.get()));
}

TEST_F(PacketTest, optionsTstamp)
{
    auto pkt = TCPPacket(CDir::C2S)
        .addTCPOption(TCPOption::timeStamp(0x41424344, 0x45464748))
        .build(ck4);

    // Timestamp, len=10, value=ABCD, echo=EFGH, 2 NOP padding
    EXPECT_EQ(Buffer(string("\x08\x0a" "ABCDEFGH" "\x01\x01")), getOptions(pkt.get()));
}

TEST_F(PacketTest, optionsSack)
{
    std::vector<std::pair<uint, uint>> edges = { { 0x41424344, 0x45464748 }, { 0x30313233, 0x34353637 } };
    auto pkt = TCPPacket(CDir::C2S)
        .addTCPOption(TCPOption::selectiveACK(edges))
        .build(ck6);

    // SACK, len=18, pairs= ABCD, EFGH, 1234, 5678, 2 NOP padding
    EXPECT_EQ(Buffer(string("\x05\x12" "ABCDEFGH" "01234567" "\x01\x01")), getOptions(pkt.get()));
}

TEST_F(PacketTest, smallHeader)
{
    auto pkt = TCPPacket(CDir::C2S)
        .setL4HeaderSize(10)            // Too small, will fail
        .build(ck4);
    EXPECT_EQ(nullptr, pkt);
}

TEST_F(PacketTest, largeDataOffset)
{
    auto pkt = TCPPacket(CDir::C2S)
        .setL4DataOffset(6)                // 6*4 is larger than packet, will fail
        .build(ck6);
    EXPECT_EQ(nullptr, pkt);
}

TEST_F(PacketTest, cksumV4)
{
    // Get ourselves a reasonable IPv4 packet
    auto pkt = TCPPacket(CDir::C2S).build(ck4);
    auto buf = pkt->getPacket();
    auto p = buf.data();
    vector<u_char> data(p, p + buf.size());

    // XXX: constNTOHS commetned to make it work. Endianity bug?
    auto ip = pkt->getL3Header().getTypePtr<struct ip>(0).unpack();
    EXPECT_EQ(ip->ip_sum, TCPPacket::calcIPv4Checksum(data));

    auto tcp = pkt->getL4Header().getTypePtr<struct TcpHdr>(0).unpack();
    EXPECT_EQ(constNTOHS(tcp->check), TCPPacket::calcTCPv4Checksum(data));
}

TEST_F(PacketTest, cksumV6)
{
    // Get ourselves a reasonable IPv6 packet
    auto pkt = TCPPacket(CDir::C2S).build(ck6);
    auto buf = pkt->getPacket();
    auto p = buf.data();
    vector<u_char> data(p, p + buf.size());

    auto tcp = pkt->getL4Header().getTypePtr<struct TcpHdr>(0).unpack();
    EXPECT_EQ(constNTOHS(tcp->check), TCPPacket::calcTCPv6Checksum(data));
}
