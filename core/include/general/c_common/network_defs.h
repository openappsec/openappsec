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

#ifndef __NETWORK_DEFS__
#define __NETWORK_DEFS__

// Various network layer definitions

// Note: we get Linux's annyoing TCP headers, not BSD's nicer ones.
// A significant difference is that TCP flags are bit fields, so masking is hard.
// Maybe we should just copy&paste nice headers and be more portable?

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <endian.h>

// Sometimes BSD's flag definitions are just so much more convenient.
// So let people use them.
// XXX: Very ugly. Better really switch to BSD.
#ifdef __cplusplus
using TCPFlags = u_char;
#else
typedef u_char TCPFlags;
#endif

#ifndef TH_FIN
static const u_char TH_FIN=0x01;
#endif
#ifndef TH_SYN
static const u_char TH_SYN=0x02;
#endif
#ifndef TH_RST
static const u_char TH_RST=0x04;
#endif
#ifndef TH_PSH
static const u_char TH_PSH=0x08;
#endif
#ifndef TH_ACK
static const u_char TH_ACK=0x10;
#endif
#ifndef TH_URG
static const u_char TH_URG=0x20;
#endif

// Linux TCP headers are not the same for all distros, so we bring tcp/udp structs here
// probably switch to BSD headers is a better options

struct UdpHdr
{
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};


struct TcpHdr
{
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
# if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t res1:4;
    uint8_t doff:4;
    union {
        struct {
            uint8_t fin:1;
            uint8_t syn:1;
            uint8_t rst:1;
            uint8_t psh:1;
            uint8_t ack:1;
            uint8_t urg:1;
            uint8_t res2:2;
        };
        uint8_t flags;
    };
# elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t doff:4;
    uint8_t res1:4;
    union {
        struct {
            uint8_t res2:2;
            uint8_t urg:1;
            uint8_t ack:1;
            uint8_t psh:1;
            uint8_t rst:1;
            uint8_t syn:1;
            uint8_t fin:1;
        };
        uint8_t flags;
    };
#else
#  error "Adjust your <bits/endian.h> defines"
#endif
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

#ifndef IPPROTO_MH
#define IPPROTO_MH      135
#endif

// GRE START
#ifndef GREPROTO_PPP
#define GREPROTO_PPP    0x880B
#endif

struct GreHdr
{
    uint16_t flags;
    uint16_t proto_type;
};

struct EnhancedGreHdr
{
    uint16_t flags;
    uint16_t proto_type;
    uint16_t data_length;
    uint16_t call_id;
};
// GRE END

// SCTP START
struct SctpHdr
{
    uint16_t sport;
    uint16_t dport;
    uint vtag;
    uint sum;
};

struct SctpChunkHdr
{
    u_char chunk_type;
    u_char chunk_flags;
    uint16_t chunk_length;
};
// SCTP END

// DCCP START
#ifndef DCCPO_CHANGE_L
#define DCCPO_CHANGE_L  32
#endif

#ifndef DCCPO_CHANGE_R
#define DCCPO_CHANGE_R  34
#endif

struct DccpHdr
{
    uint16_t dccph_sport;
    uint16_t dccph_dport;
    u_char dccph_doff;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_char  dccph_cscov : 4,
            dccph_ccval : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    u_char  dccph_ccval : 4,
            dccph_cscov : 4;
#else
#error unknown byte order
#endif // __BYTE_ORDER
    uint16_t dccph_checksum;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_char  dccph_x : 1,
            dccph_type : 4,
            dccph_reserved : 3;
#elif __BYTE_ORDER == __BIG_ENDIAN
    u_char  dccph_reserved : 3,
            dccph_type : 4,
            dccph_x : 1;
#else
#error unknown byte order
#endif // __BYTE_ORDER
    u_char dccph_seq2;
    uint16_t dccph_seq;
};

struct DccpHdrExt
{
    uint dccph_seq_low;
};

struct DccpOptHdr
{
    u_char type;
    u_char length;
};

struct DccpHdrAckBits
{
    uint16_t dccph_reserved1;
    uint16_t dccph_ack_nr_high;
    uint dccph_ack_nr_low;
};

struct DccpHdrRequest
{
    uint dccph_req_service;
};

struct DccpHdrResponse
{
    struct DccpHdrAckBits dccph_resp_ack;
    uint dccph_resp_service;
};

struct DccpHdrReset
{
    struct DccpHdrAckBits dccph_reset_ack;
    uint16_t dccph_reset_code;
    uint16_t dccph_reset_data[3];
};

enum DccpPacketType {
    DCCP_PKT_REQUEST = 0,
    DCCP_PKT_RESPONSE,
    DCCP_PKT_DATA,
    DCCP_PKT_ACK,
    DCCP_PKT_DATAACK,
    DCCP_PKT_CLOSEREQ,
    DCCP_PKT_CLOSE,
    DCCP_PKT_RESET,
    DCCP_PKT_SYNC,
    DCCP_PKT_SYNCACK,
    DCCP_PKT_INVALID,
};
// DCCP END

static inline TCPFlags
getTCPFlags(const struct TcpHdr *tcp)
{
    TCPFlags res = (TCPFlags)0;
    if (tcp->fin) res |= TH_FIN;
    if (tcp->syn) res |= TH_SYN;
    if (tcp->rst) res |= TH_RST;
    if (tcp->psh) res |= TH_PSH;
    if (tcp->ack) res |= TH_ACK;
    if (tcp->urg) res |= TH_URG;

    return res;
}

#endif // __NETWORK_DEFS__
