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

#ifndef __NETWORKING_HEADERS_H__
#define __NETWORKING_HEADERS_H__

#define ETH_P_IPV6  0x86DD
#define ETH_P_IP    0x0800
#define NF_DROP 0u
#define NF_ACCEPT 1u

#ifndef DCCPO_CHANGE_L
#define DCCPO_CHANGE_L  32
#endif

#ifndef DCCPO_CHANGE_R
#define DCCPO_CHANGE_R  34
#endif

typedef unsigned int sk_buff_data_t;

enum PROTOCOL {
    ICMP       = 1,   //0x1
    TCP        = 6,   //0x6
    UDP        = 17,  //0x11
    DCCP       = 33,  //0x21
    IPV6_FRAG  = 44,  //0x2c
    ICMPV6     = 58,  //0x3A
    SCTP       = 132  //0x84
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

struct net_device {
    int ifindex;
};

struct sk_buff {
    uint16_t protocol;
    union {
        struct iphdr   *ip_header;
        struct ipv6hdr *ipv6_header;
    } network_header;
    union {
        struct udphdr   *udp_header;
        struct tcphdr   *tcp_header;
        struct icmphdr  *icmp_header;
        struct icmp6hdr *icmp6_header;
        struct sctphdr  *sctp_header;
        struct dccphdr  *dccp_header;
    } transport_header;
    unsigned char *tail;
    unsigned char *data;
    unsigned char *head;
    unsigned int  len;
    struct sock   *sk;
    void          (*destructor)(struct sk_buff *);
    struct net_device *dev;
};

struct geneve_opt {
    __u16    opt_class;
    u_int8_t type;
#ifdef __LITTLE_ENDIAN_BITFIELD
    u_int8_t length:5;
    u_int8_t r3:1;
    u_int8_t r2:1;
    u_int8_t r1:1;
#else
    u_int8_t r1:1;
    u_int8_t r2:1;
    u_int8_t r3:1;
    u_int8_t length:5;
#endif
    u_int8_t opt_data[];
};

struct genevehdr {
#ifdef __LITTLE_ENDIAN_BITFIELD
    u_int8_t opt_len:6;
    u_int8_t ver:2;
    u_int8_t rsvd1:6;
    u_int8_t critical:1;
    u_int8_t oam:1;
#else
    u_int8_t ver:2;
    u_int8_t opt_len:6;
    u_int8_t oam:1;
    u_int8_t critical:1;
    u_int8_t rsvd1:6;
#endif
    __u16 proto_type;
    u_int8_t vni[3];
    u_int8_t rsvd2;
    struct geneve_opt options[];
};

struct sctphdr {
    u_int16_t source;
    u_int16_t dest;
    u_int32_t vtag;
    u_int32_t checksum;
};

struct ipv6hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t        priority : 4,
                    version : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t        version : 4,
                    priority : 4;
#else
#error unknown byte order
#endif // __BYTE_ORDER
    u_int8_t        flow_lbl[3];
    u_int16_t       payload_len;
    u_int8_t        nexthdr;
    u_int8_t        hop_limit;
    struct in6_addr saddr;
    struct in6_addr daddr;
};

struct dccp_hdr
{
    uint16_t    dccph_sport;
    uint16_t    dccph_dport;
    u_char      dccph_doff;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_char      dccph_cscov : 4,
                dccph_ccval : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    u_char      dccph_ccval : 4,
                dccph_cscov : 4;
#else
#error unknown byte order
#endif // __BYTE_ORDER
    uint16_t    dccph_checksum;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_char      dccph_x : 1,
                dccph_type : 4,
                dccph_reserved : 3;
#elif __BYTE_ORDER == __BIG_ENDIAN
    u_char      dccph_reserved : 3,
                dccph_type : 4,
                dccph_x : 1;
#else
#error unknown byte order
#endif // __BYTE_ORDER
    u_char      dccph_seq2;
    uint16_t    dccph_seq;
};

struct sctp_chunkhdr
{
    u_char chunk_type;
    u_char chunk_flags;
    uint16_t chunk_length;
};

struct dccp_hdr_ext
{
    uint dccph_seq_low;
};

struct dccp_hdr_request
{
    uint dccph_req_service;
};

struct dccp_opt_hdr
{
    u_char type;
    u_char length;
};

struct dccp_hdr_ack_bits
{
    uint16_t dccph_reserved1;
    uint16_t dccph_ack_nr_high;
    uint dccph_ack_nr_low;
};

struct dccp_hdr_response
{
    struct dccp_hdr_ack_bits dccph_resp_ack;
    uint dccph_resp_service;
};

struct dccp_hdr_reset
{
    struct dccp_hdr_ack_bits dccph_reset_ack;
    uint16_t dccph_reset_code;
    uint16_t dccph_reset_data[3];
};

#endif // __NETWORKING_HEADERS_H__
