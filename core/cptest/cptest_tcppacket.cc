#include "cptest/cptest_tcppacket.h"

#include "cptest.h"
#include "c_common/network_defs.h"
#include "packet.h"

using namespace std;

USE_DEBUG_FLAG(D_STREAMING);

//
// Append some data - various overloads - to a u_char vector
//

void
vec_append(vector<u_char> &target, const void *data, uint len)
{
    auto p = reinterpret_cast<const u_char *>(data);
    target.insert(target.end(), p, p + len);
}

void
vec_append(vector<u_char> &target, uint num)
{
    vec_append(target, &num, sizeof(num));
}

void
vec_append(vector<u_char> &target, const vector<u_char> &source)
{
    target.insert(target.end(), source.begin(), source.end());
}

//
// TCP Option generation
//

class TCPOption::Impl
{
public:
    explicit Impl(const string &_name, const vector<u_char> &_data);

    const string         name;
    const vector<u_char> data;
};


TCPOption::Impl::Impl(const string &_name, const vector<u_char> &_data)
        :
    name(_name),
    data(_data)
{
}

TCPOption::TCPOption(const string &_name, const vector<u_char> _data)
        :
    pimpl(make_unique<Impl>(_name, _data))
{
}

TCPOption::TCPOption(const TCPOption &from)
        :
    pimpl(make_unique<Impl>(*from.pimpl))
{
}

TCPOption::~TCPOption()
{
}

size_t
TCPOption::size() const
{
    return pimpl->data.size();
}

vector<u_char>
TCPOption::build() const
{
    return pimpl->data;
}

const TCPOption TCPOption::NOP("NOP", { 1 });                             // Type 1, no length (exceptional)
const TCPOption TCPOption::SACK_PERMITTED("sack permitted", { 4, 2 });    // Type 4, length 2

TCPOption
TCPOption::windowScaling(u_char shift_count)
{
    // Type 3, length 3, data = shift
    return TCPOption("window scaling", { 3, 3, shift_count });
}

TCPOption
TCPOption::timeStamp(uint value, uint echo_reply)
{
    vector<u_char> data { 8, 0 };       // Type 8, size set below
    vec_append(data, htonl(value));
    vec_append(data, htonl(echo_reply));
    data[1] = data.size();
    return TCPOption("timestamp", data);
}

TCPOption
TCPOption::selectiveACK(const vector<pair<uint, uint>> &edges)
{
    vector<u_char> data { 5, 0 };       // Type 8, size set below
    for (auto const &edge : edges) {
        vec_append(data, htonl(edge.first));
        vec_append(data, htonl(edge.second));
    }
    data[1] = data.size();
    return TCPOption("sack", data);
}

// Append a TCP option to a u_char vector
void
vec_append(vector<u_char> &target, const TCPOption &source)
{
    vec_append(target, source.build());
}


//
// Checksum calculation
// This is NOT an efficient implementation. It's used because it is straight-forward.
// Also, it's not the same as in the streamer, so we test the streamer's algorithm.
//

static uint16_t
bufCSumSimple(const u_char *buff, uint length)
{
    uint32_t acc = 0xffff;

    // Handle complete 16-bit blocks.
    for (size_t i = 0; i+1<length; i += 2) {
        uint16_t word;
        memcpy(&word, buff + i, 2);
        acc += ntohs(word);
        if (acc > 0xffff) acc -= 0xffff;
    }

    // Handle any partial block at the end of the data.
    if ((length % 2) == 1) {
        uint16_t word = 0;
        memcpy(&word, buff + length - 1, 1);
        acc += ntohs(word);
        if (acc > 0xffff) acc -= 0xffff;
    }

    return ~static_cast<uint16_t>(acc);
}

// TCP checksum, generic v4/v6 version
static uint16_t
tcpCSum(const vector<u_char> &pseudo_pkt_header, const u_char *tcp, uint total_tcplen)
{
    // Finish building the packet after having the pssudo header
    auto pseudo_header_size = pseudo_pkt_header.size();
    auto pseudo_pkt = pseudo_pkt_header;
    vec_append(pseudo_pkt, tcp, total_tcplen);

    // Set the pseudo packet's TCP checksum to 0, so it won't be included in the calculation
    auto pseudo_tcp = reinterpret_cast<struct TcpHdr *>(&pseudo_pkt[pseudo_header_size]);
    pseudo_tcp->check = 0;

    return bufCSumSimple(pseudo_pkt.data(), pseudo_pkt.size());
}

// This isn't efficient in the calculaiton of the psuedo header, and is not suitable for general use!
static uint16_t
tcpV4CSum(const struct ip *ip)
{
    auto tcp_buf = reinterpret_cast<const u_char *>(ip) + (ip->ip_hl * 4);
    uint iplen = ntohs(ip->ip_len);
    uint total_tcplen = iplen - (ip->ip_hl * 4);
    // Build a psuedo IP header for the calcualtion of the TCP checksum
    vector<u_char> pseudo_pkt;
    vec_append(pseudo_pkt, &(ip->ip_src), sizeof(ip->ip_src));
    vec_append(pseudo_pkt, &(ip->ip_dst), sizeof(ip->ip_dst));
    uint16_t ipproto = htons(IPPROTO_TCP);
    vec_append(pseudo_pkt, &(ipproto), sizeof(ipproto));
    uint16_t len = htons(total_tcplen);
    vec_append(pseudo_pkt, &len, sizeof(len));

    return tcpCSum(pseudo_pkt, tcp_buf, total_tcplen);
}

// This isn't efficient in the calculaiton of the psuedo header, and is not suitable for general use!
static uint16_t
tcpV6CSum(const struct ip6_hdr *ip6)
{
    auto tcp_buf = reinterpret_cast<const u_char *>(ip6) + sizeof(*ip6);
    uint total_tcplen = ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);    // Why so simple?
    // Build a psuedo IP header for the calcualtion of the TCP checksum
    vector<u_char> pseudo_pkt;
    vec_append(pseudo_pkt, &(ip6->ip6_src), sizeof(ip6->ip6_src));
    vec_append(pseudo_pkt, &(ip6->ip6_dst), sizeof(ip6->ip6_dst));
    uint16_t ipproto = htons(IPPROTO_TCP);
    vec_append(pseudo_pkt, &(ipproto), sizeof(ipproto));
    uint16_t len = htons(total_tcplen);
    vec_append(pseudo_pkt, &(len), sizeof(len));

    return tcpCSum(pseudo_pkt, tcp_buf, total_tcplen);
}

uint16_t
ipv4_csum(const struct ip *ip)
{
    // Copy the IP header aside
    const u_char *ip_p = reinterpret_cast<const u_char *>(ip);
    vector<u_char> ip_copy(ip_p, ip_p+(ip->ip_hl * 4));
    auto ip_copy_p = reinterpret_cast<struct ip *>(ip_copy.data());

    // Set the checksum to 0 so it won't be included in the calculation
    ip_copy_p->ip_sum = 0;

    // Calculate the checksum
    return bufCSumSimple(ip_copy.data(), ip_copy.size());
}

//
// TCP packet generation
// This code can generate various TCP packets, for testing purposes
//

class TCPPacket::Impl
{
public:
    Impl(CDir _cdir);
    unique_ptr<Packet> build(const ConnKey &ck) const;

    uint     tcp_seq        = 1200;      // Arbitrary
    uint     tcp_ack        = 3300000;   // Arbitrary
    uint16_t tcp_window     = 4096;      // Reasonable
    string   tcp_flags      = "A";       // Default to simple ACK
    bool     tcp_cksum_auto = true;      // Auto checksum by default
    uint16_t tcp_cksum_override;
    uint16_t tcp_urgent_ptr = 0;
    uint     tcp_header_size = sizeof(struct TcpHdr);
    int      tcp_data_offset = -1;

    vector<u_char>    l2_header;
    vector<u_char>    tcp_payload;
    vector<TCPOption> tcp_options;

private:
    bool  has_tcp_flag(char letter) const;
    uint l4_hdr_len() const;

    // Methods to build the packet data, step by step
    vector<u_char> build_pkt_bytes(const ConnKey &key) const;
    void emit_l2_hdr     (vector<u_char> &pkt) const;
    void emit_l3_hdr     (vector<u_char> &pkt, const ConnKey &ck) const;
    void emit_l4_hdr     (vector<u_char> &pkt, const ConnKey &ck) const;
    void emit_tcp_options(vector<u_char> &pkt) const;
    void emit_payload    (vector<u_char> &pkt) const;
    void fixup_l4_cksum  (vector<u_char> &pkt, IPType type) const;
    void fixup_l3_cksum  (vector<u_char> &pkt, IPType type) const;

    CDir cdir;
};

TCPPacket::Impl::Impl(CDir _cdir)
        :
    cdir(_cdir)
{
}

uint
TCPPacket::Impl::l4_hdr_len() const
{
    // Basic length
    uint sz = sizeof(struct TcpHdr);

    // TCP options
    for (auto const &opt : tcp_options) {
        sz += opt.size();
    }

    // Align to multiple of 4
    while (sz%4 != 0) {
        sz++;
    }

    return sz;
}

bool
TCPPacket::Impl::has_tcp_flag(char letter) const
{
    return tcp_flags.find(letter) != string::npos;
}

unique_ptr<Packet>
TCPPacket::Impl::build(const ConnKey &ck) const
{
    // Figure out the key to use
    auto key = ck;
    if (cdir == CDir::S2C) key.reverse();

    // Build the packet data
    auto data = build_pkt_bytes(key);

    // Build a Packet, set the conn and cdir
    auto pkt_type = l2_header.empty() ? PktType::PKT_L3 : PktType::PKT_L2;
    auto p = Packet::genPacket(pkt_type, key.getType(), data);

    if (!p.ok()) {
        dbgError(D_STREAMING) << "Failed to build packet for " << key << " err=" << (int)p.getErr() <<
            " payload: " << Buffer(data);
        return nullptr;
    }

    (*p)->setCDir(cdir);

    return p.unpackMove();
}

vector<u_char>
TCPPacket::Impl::build_pkt_bytes(const ConnKey &key) const
{
    vector<u_char> data;

    emit_l3_hdr(data, key);
    emit_l4_hdr(data, key);
    emit_payload(data);
    fixup_l4_cksum(data, key.getType());
    fixup_l3_cksum(data, key.getType());
    emit_l2_hdr(data);  // Insert l2_hdr at the beginning.

    return data;
}

void
TCPPacket::Impl::emit_l2_hdr(vector<u_char> &pkt) const
{
    // We use 'insert' and not vec_append because l2 header should be at the beginning.
    pkt.insert(pkt.begin(), l2_header.begin(), l2_header.end());
}

void
TCPPacket::Impl::emit_l3_hdr(vector<u_char> &pkt, const ConnKey &ck) const
{
    uint payload_length = l4_hdr_len() + tcp_payload.size();

    if (ck.getType() == IPType::V4) {
        struct ip iphdr = {
            ip_hl  : 5,
            ip_v   : 4,
            ip_tos : 0,
            ip_len : htons(sizeof(struct ip) + payload_length),
            ip_id  : htons(7766),
            ip_off : htons(0x4000),         // flags + offset. flags set to don't fragment
            ip_ttl : 64,
            ip_p   : IPPROTO_TCP,
            ip_sum : 0,                     // will be fixed by fixup_l3_cksum
            ip_src : ck.getSrc().getIPv4(), // already in network order in the ck
            ip_dst : ck.getDst().getIPv4(), // already in network order in the ck
        };
        vec_append(pkt, &iphdr, sizeof(iphdr));
    } else {
        struct ip6_hdr ip6hdr;

        // The IPv6 header is simple. Linux's headers, however, are like this:
        ip6hdr.ip6_ctlun.ip6_un1.ip6_un1_flow = 0;
        ip6hdr.ip6_ctlun.ip6_un1.ip6_un1_plen = htons(payload_length);
        ip6hdr.ip6_ctlun.ip6_un1.ip6_un1_nxt  = IPPROTO_TCP;
        ip6hdr.ip6_ctlun.ip6_un1.ip6_un1_hlim = 123;
        ip6hdr.ip6_ctlun.ip6_un2_vfc          = 0x60;               // Overwrites part of ip6_un1_flow
        ip6hdr.ip6_src                        = ck.getSrc().getIPv6();
        ip6hdr.ip6_dst                        = ck.getDst().getIPv6();

        vec_append(pkt, &ip6hdr, sizeof(ip6hdr));
    }
}

void
TCPPacket::Impl::emit_l4_hdr(vector<u_char> &pkt, const ConnKey &ck) const
{
    // Basic header
    struct TcpHdr tcp;
    tcp.source  = htons(ck.getSPort());
    tcp.dest    = htons(ck.getDPort());
    tcp.seq     = htonl(tcp_seq);
    tcp.ack_seq = htonl(tcp_ack);
    tcp.res1    = 0;                        // unused 4 bits
    tcp.doff    = static_cast<u_char>(tcp_data_offset > -1 ? tcp_data_offset
                    : l4_hdr_len() / 4);
    tcp.fin     = has_tcp_flag('F');
    tcp.syn     = has_tcp_flag('S');
    tcp.rst     = has_tcp_flag('R');
    tcp.psh     = has_tcp_flag('P');
    tcp.ack     = has_tcp_flag('A');
    tcp.urg     = has_tcp_flag('U');
    tcp.res2    = 0;                        // ECE and CWR. Never mind them.
    tcp.window  = htons(tcp_window);
    tcp.check   = 0;                        // will be fixed by fixup_l4_cksum
    tcp.urg_ptr = htons(tcp_urgent_ptr);

    vec_append(pkt, &tcp, tcp_header_size);

    // TCP Options
    emit_tcp_options(pkt);
}

void
TCPPacket::Impl::emit_tcp_options(vector<u_char> &pkt) const
{
    // Concatenate options in a vector, then append with NOPs to multiple of 4
    vector<u_char> optbuf;

    for (auto const &opt : tcp_options) {
        vec_append(optbuf, opt);
    }
    while (optbuf.size()%4 != 0) {
        vec_append(optbuf, TCPOption::NOP);
    }
    dbgAssert(optbuf.size() <= 40) << "too many tcp options. max is 40 bytes";

    vec_append(pkt, optbuf);
}

void
TCPPacket::Impl::emit_payload(vector<u_char> &pkt) const
{
    vec_append(pkt, tcp_payload);
}

void
TCPPacket::Impl::fixup_l4_cksum(vector<u_char> &pkt, IPType type) const
{
    u_char *l3 = pkt.data();
    if (type == IPType::V4) {
        if (pkt.size() < sizeof(struct ip) + sizeof(struct TcpHdr)) return;
        auto ip = reinterpret_cast<struct ip *>(l3);
        auto tcp = reinterpret_cast<struct TcpHdr *>(l3 + (ip->ip_hl*4));
        tcp->check = htons(tcp_cksum_auto ? tcpV4CSum(ip) : tcp_cksum_override);
    } else {
        if (pkt.size() < sizeof(struct ip6_hdr) + sizeof(struct TcpHdr)) return;
        auto ip6 = reinterpret_cast<struct ip6_hdr *>(l3);
        auto tcp = reinterpret_cast<struct TcpHdr *>(l3 + sizeof(*ip6));
        tcp->check = htons(tcp_cksum_auto ? tcpV6CSum(ip6) : tcp_cksum_override);
    }
}

void
TCPPacket::Impl::fixup_l3_cksum(vector<u_char> &pkt, IPType type) const
{
    if (type == IPType::V4) {
        auto ip = reinterpret_cast<struct ip *>(pkt.data());
        ip->ip_sum = ipv4_csum(ip);
    } else {
        // No checksum in IPv6 header. Hurray!
    }
}

TCPPacket::TCPPacket(CDir _cdir)
        :
    pimpl(make_unique<Impl>(_cdir))
{
}

TCPPacket::TCPPacket(TCPPacket &&from)
        :
    pimpl(std::move(from.pimpl))
{
}

TCPPacket::~TCPPacket()
{
}

TCPPacket &
TCPPacket::setTCPPayload(const vector<u_char> &payload)
{
    pimpl->tcp_payload = payload;
    return *this;
}

TCPPacket &
TCPPacket::setTCPPayload(const string &payload)
{
    vector<u_char> vec;
    vec.insert(vec.end(), payload.begin(), payload.end());
    return setTCPPayload(vec);
}

TCPPacket &
TCPPacket::addTCPOption(const TCPOption &option)
{
    pimpl->tcp_options.push_back(option);
    return *this;
}

TCPPacket &
TCPPacket::setL4HeaderSize(uint header_size)
{
    pimpl->tcp_header_size = header_size;
    return *this;
}

TCPPacket &
TCPPacket::setL4DataOffset(uint data_offset)
{
    pimpl->tcp_data_offset = data_offset;
    return *this;
}

TCPPacket &
TCPPacket::setTCPSeq(uint _tcp_seq)
{
    pimpl->tcp_seq = _tcp_seq;
    return *this;
}

TCPPacket &
TCPPacket::setTCPAck(uint _tcp_ack)
{
    pimpl->tcp_ack = _tcp_ack;
    return *this;
}

TCPPacket &
TCPPacket::setTCPWindow(uint16_t _tcp_window)
{
    pimpl->tcp_window = _tcp_window;
    return *this;
}

TCPPacket &
TCPPacket::setTCPFlags(string _tcp_flags)
{
    pimpl->tcp_flags = _tcp_flags;
    return *this;
}

TCPPacket &
TCPPacket::setTCPUrgentPtr(uint16_t _tcp_urgent_ptr)
{
    pimpl->tcp_urgent_ptr = _tcp_urgent_ptr;
    return *this;
}

TCPPacket &
TCPPacket::setTCPCksum(uint _tcp_cksum_override)
{
    pimpl->tcp_cksum_auto = false;
    pimpl->tcp_cksum_override = _tcp_cksum_override;
    return *this;
}

TCPPacket &
TCPPacket::setL2Header(const vector<u_char> &_l2_header)
{
    pimpl->l2_header = _l2_header;
    return *this;
}

uint
TCPPacket::getTCPSeq() const
{
    return pimpl->tcp_seq;
}

unique_ptr<Packet>
TCPPacket::build(const ConnKey &ck) const
{
    return pimpl->build(ck);
}

uint16_t
TCPPacket::calcTCPv4Checksum(const vector<u_char> &pkt)
{
    auto l3 = pkt.data();
    auto ip = reinterpret_cast<const struct ip *>(l3);
    return tcpV4CSum(ip);
}

uint16_t
TCPPacket::calcTCPv6Checksum(const vector<u_char> &pkt)
{
    auto l3 = pkt.data();
    auto ip6 = reinterpret_cast<const struct ip6_hdr *>(l3);
    return tcpV6CSum(ip6);
}

uint16_t
TCPPacket::calcIPv4Checksum(const vector<u_char> &pkt)
{
    auto l3 = pkt.data();
    auto ip = reinterpret_cast<const struct ip *>(l3);
    return ipv4_csum(ip);
}
