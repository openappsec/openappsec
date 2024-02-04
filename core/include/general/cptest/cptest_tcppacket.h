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

#ifndef __CPTEST_TCPPACKET_H__
#define __CPTEST_TCPPACKET_H__

#include <vector>
#include <string>
#include <memory>
#include "packet.h"

// Generate TCP options
class TCPOption
{
public:
    explicit TCPOption(const std::string &_name, const std::vector<u_char> _data);
    TCPOption(const TCPOption &from);
    ~TCPOption();

    // Accessors
    size_t size() const;
    std::vector<u_char> build() const;

    // Well-known options - simple ones are constants, complex are are static functions
    static const TCPOption NOP;
    static const TCPOption SACK_PERMITTED;
    static TCPOption windowScaling(u_char shift_count);
    static TCPOption timeStamp(uint value, uint echo_reply);
    static TCPOption selectiveACK(const std::vector<std::pair<uint, uint>> &edges);

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

class TCPPacket
{
public:
    // Build an empty packet
    explicit TCPPacket(CDir _cdir);
    ~TCPPacket();

    // Movable, not copiable
    TCPPacket(TCPPacket &&from);
    TCPPacket(const TCPPacket &from) = delete;

    // Methods to set TCP properties. Return reference to this, to allow chaining
    TCPPacket & setTCPPayload(const std::vector<u_char> &payload);
    TCPPacket & setTCPPayload(const std::string &payload);
    TCPPacket & setTCPSeq(uint _tcp_seq);
    TCPPacket & setTCPAck(uint _tcp_ack);
    TCPPacket & setTCPWindow(uint16_t _tcp_window);
    TCPPacket & setTCPFlags(std::string _tcp_flags);
    TCPPacket & setTCPUrgentPtr(uint16_t _tcp_urgent_ptr);
    TCPPacket & setTCPCksum(uint _tcp_cksum_override);
    TCPPacket & setL2Header(const std::vector<u_char> &_l2_header);
    TCPPacket & addTCPOption(const TCPOption &tcp_option);
    TCPPacket & setL4HeaderSize(uint header_size);
    TCPPacket & setL4DataOffset(uint data_offset);

    TCPPacket && move() { return std::move(*this); }

    // Build a Packet
    std::unique_ptr<Packet> build(const ConnKey &ck) const;

    // Get the TCP sequence
    uint getTCPSeq() const;

    static uint16_t calcTCPv4Checksum(const std::vector<u_char> &pkt);
    static uint16_t calcTCPv6Checksum(const std::vector<u_char> &pkt);
    static uint16_t calcIPv4Checksum(const std::vector<u_char> &pkt);

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __CPTEST_TCPPACKET_H__
