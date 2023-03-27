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

#include "shmpktqueue.h"
#include <string>
#include <sstream>

#include "cptest.h"
#include "maybe_res.h"
#include "../shared_string_wrapper.h"

namespace bip = boost::interprocess;
using namespace std;

static const int segment_name_len = 128;
static const char *queue_name="queue";

static const char *packet_string = "aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeeffffffffff";
static const u_char *packet_data = reinterpret_cast<const u_char *>(packet_string);
static const uint16_t packet_len = 60;
static const uint16_t l2_len = 14;
static const uint16_t packet_ifn = 1;

static const char *short_packet_string = "aaaaaaaaaabbbbbbbbbbcccccccccc";
static const u_char *short_packet_data = reinterpret_cast<const u_char *>(short_packet_string);
static const uint16_t short_packet_len = 30;
static const uint16_t short_l2_len = 10;
static const uint16_t short_packet_ifn = 0;

static Buffer dns_req { cptestParseHex(
    "0000:  00 c0 9f 32 41 8c 00 e0 18 b1 0c ad 08 00 45 00 "
    "0010:  00 38 00 00 40 00 40 11 65 47 c0 a8 aa 08 c0 a8 "
    "0020:  aa 14 80 1b 00 35 00 24 85 ed 10 32 01 00 00 01 "
    "0030:  00 00 00 00 00 00 06 67 6f 6f 67 6c 65 03 63 6f "
    "0040:  6d 00 00 10 00 01                               ")
};
static const uint16_t dns_packet_len = 70;
static const uint16_t dns_l2_len = 14;
static const uint16_t dns_packet_ifn = 4000;


using PacketInfo = struct {
        shm_pkt_queue_msg_hdr msg_hdr;
        std::unique_ptr<char[]> data;
};


class ShmPktQueueTest : public ::testing::Test {

    public:
        ShmPktQueueTest()
        {
            time_t cur_time;
            time(&cur_time);
            snprintf(
                shm_segment_name,
                segment_name_len,
                "%s_%s",
                to_string(cur_time).c_str(),
                to_string(::getpid()).c_str()
            );
            segment = make_unique<bip::managed_shared_memory>(bip::create_only, shm_segment_name, 65536);
            queue_id = get_shm_pkt_queue_id();
        }

        ~ShmPktQueueTest()
        {
            delete_shm_pkt_queue(queue_id);
            boost::interprocess::shared_memory_object::remove(shm_segment_name);
        }

        int
        push_packet_to_queue(
            Buffer buf,
            shmq_msg_mode mode,
            shm_pkt_msg_proto l3_proto,
            u_int16_t l2_len,
            u_int16_t if_index)
        {
            return push_packet_to_queue(buf.data(), buf.size(), mode, l3_proto, l2_len, if_index);
        }

        int
        push_packet_to_queue(
            const unsigned char *data,
            u_int16_t length,
            shmq_msg_mode mode,
            shm_pkt_msg_proto l3_proto,
            u_int16_t l2_len,
            u_int16_t if_index)
        {
            return push_to_shm_pkt_queue(queue_id, data, length, mode, l3_proto, l2_len, if_index);
        }

        Maybe<PacketInfo>
        pop_packet_via_boost()
        {
            ring_buffer *queue = segment->find_or_construct<ring_buffer>(queue_name)();
            SharedStringWrapper node_content;
            PacketInfo packet_pop_by_boost;

            if (queue->pop(node_content)) {
                auto parsed_node = reinterpret_cast<const shm_pkt_queue_msg_hdr *>(node_content.data());
                packet_pop_by_boost.msg_hdr = *parsed_node;
                packet_pop_by_boost.data = std::unique_ptr<char[]>{new char[packet_pop_by_boost.msg_hdr.len]};
                std::memcpy(packet_pop_by_boost.data.get(), parsed_node->data, packet_pop_by_boost.msg_hdr.len);
                return std::move(packet_pop_by_boost);
            }
            return genError("Queue is empty");
        }

        Maybe<PacketInfo>
        pop_packet_by_c_api()
        {
            unsigned char *tmp_packet_pop_by_c_api = pop_from_shm_pkt_queue(queue_id);
            PacketInfo packet_pop_by_c_api;
            if (tmp_packet_pop_by_c_api) {
                auto parsed_node = reinterpret_cast<const shm_pkt_queue_msg_hdr *>(tmp_packet_pop_by_c_api);
                packet_pop_by_c_api.msg_hdr = *parsed_node;
                packet_pop_by_c_api.data = std::unique_ptr<char[]>{new char[packet_pop_by_c_api.msg_hdr.len]};
                std::memcpy(packet_pop_by_c_api.data.get(), parsed_node->data, packet_pop_by_c_api.msg_hdr.len);
                free(tmp_packet_pop_by_c_api);
                return std::move(packet_pop_by_c_api);
            }
            return genError("Queue is empty");
        }

        bool
        is_queue_empty()
        {
            return is_shm_pkt_queue_empty(queue_id);
        }

        int
        init_queue()
        {
            return init_shm_pkt_queue(queue_id, shm_segment_name, queue_name);
        }

        shm_pkt_queue_stub * getQueueID() { return queue_id; }
        char shm_segment_name[segment_name_len];

    private:
        shm_pkt_queue_stub *queue_id = nullptr;
        std::unique_ptr<bip::managed_shared_memory> segment = nullptr;
};

TEST_F(ShmPktQueueTest, check_queue_emptiness)
{
    EXPECT_EQ(init_queue(), 1);
    EXPECT_TRUE(is_queue_empty());
    EXPECT_EQ(
        push_packet_to_queue(packet_data, packet_len, shmq_msg_mode_l2, shmq_msg_no_proto, l2_len, packet_ifn),
        1
    );
    EXPECT_FALSE(is_queue_empty());
    auto packet_pop_by_boost = pop_packet_via_boost();
    EXPECT_TRUE(is_queue_empty());
}

TEST_F(ShmPktQueueTest, check_push_api)
{
    EXPECT_EQ(init_queue(), 1);
    EXPECT_EQ(
        push_packet_to_queue(packet_data, packet_len, shmq_msg_mode_l2, shmq_msg_no_proto, l2_len, packet_ifn),
        1
    );
    auto packet_pop_by_boost = pop_packet_via_boost();
    EXPECT_TRUE(packet_pop_by_boost.ok());
    EXPECT_EQ(packet_len, packet_pop_by_boost.unpack().msg_hdr.len);
    EXPECT_EQ(l2_len, packet_pop_by_boost.unpack().msg_hdr.maclen);
    EXPECT_EQ(packet_ifn, packet_pop_by_boost.unpack().msg_hdr.if_index);
    EXPECT_EQ(memcmp(packet_data, packet_pop_by_boost.unpack().data.get(), packet_len), 0);
}

TEST_F(ShmPktQueueTest, check_pop_api)
{
    EXPECT_EQ(init_queue(), 1);
    EXPECT_EQ(
        push_packet_to_queue(packet_data, packet_len, shmq_msg_mode_l2, shmq_msg_no_proto, l2_len, packet_ifn),
        1
    );
    auto packet_pop_by_c_api = pop_packet_by_c_api();
    EXPECT_TRUE(packet_pop_by_c_api.ok());
    EXPECT_EQ(packet_len, packet_pop_by_c_api.unpack().msg_hdr.len);
    EXPECT_EQ(l2_len, packet_pop_by_c_api.unpack().msg_hdr.maclen);
    EXPECT_EQ(packet_ifn, packet_pop_by_c_api.unpack().msg_hdr.if_index);
    EXPECT_EQ(memcmp(packet_data, packet_pop_by_c_api.unpack().data.get(), packet_len), 0);
}

TEST_F(ShmPktQueueTest, check_dns_real_packet)
{
    EXPECT_EQ(init_queue(), 1);
    EXPECT_EQ(push_packet_to_queue(dns_req, shmq_msg_mode_l2, shmq_msg_no_proto, dns_l2_len, dns_packet_ifn), 1);
    auto dns_packet_pop = pop_packet_by_c_api();
    EXPECT_TRUE(dns_packet_pop.ok());
    EXPECT_EQ(dns_packet_len, dns_packet_pop.unpack().msg_hdr.len);
    EXPECT_EQ(dns_l2_len, dns_packet_pop.unpack().msg_hdr.maclen);
    EXPECT_EQ(dns_packet_ifn, dns_packet_pop.unpack().msg_hdr.if_index);
    EXPECT_EQ(memcmp(dns_req.data(), dns_packet_pop.unpack().data.get(), dns_packet_len), 0);
}

TEST_F(ShmPktQueueTest, multiple_packets)
{
    EXPECT_EQ(init_queue(), 1);

    auto empty_packet_pop_by_c_api = pop_packet_by_c_api();
    EXPECT_FALSE(empty_packet_pop_by_c_api.ok());

    EXPECT_EQ(
        push_packet_to_queue(packet_data, packet_len, shmq_msg_mode_l2, shmq_msg_no_proto, l2_len, packet_ifn),
        1

    );
    EXPECT_EQ(
        push_packet_to_queue(
            short_packet_data,
            short_packet_len,
            shmq_msg_mode_l2,
            shmq_msg_no_proto,
            short_l2_len, short_packet_ifn
        ),
        1
    );
    EXPECT_EQ(push_packet_to_queue(dns_req, shmq_msg_mode_l2, shmq_msg_no_proto, dns_l2_len, dns_packet_ifn), 1);

    auto first_packet_pop_by_c_api = pop_packet_by_c_api();
    EXPECT_TRUE(first_packet_pop_by_c_api.ok());
    EXPECT_EQ(packet_len, first_packet_pop_by_c_api.unpack().msg_hdr.len);
    EXPECT_EQ(l2_len, first_packet_pop_by_c_api.unpack().msg_hdr.maclen);
    EXPECT_EQ(packet_ifn, first_packet_pop_by_c_api.unpack().msg_hdr.if_index);
    EXPECT_EQ(memcmp(packet_data, first_packet_pop_by_c_api.unpack().data.get(), packet_len), 0);

    auto second_packet_pop_by_c_api = pop_packet_by_c_api();
    EXPECT_TRUE(second_packet_pop_by_c_api.ok());
    EXPECT_EQ(short_packet_len, second_packet_pop_by_c_api.unpack().msg_hdr.len);
    EXPECT_EQ(short_l2_len, second_packet_pop_by_c_api.unpack().msg_hdr.maclen);
    EXPECT_EQ(short_packet_ifn, second_packet_pop_by_c_api.unpack().msg_hdr.if_index);
    EXPECT_EQ(memcmp(short_packet_data, second_packet_pop_by_c_api.unpack().data.get(), short_packet_len), 0);

    auto third_packet_pop_by_c_api = pop_packet_by_c_api();
    EXPECT_TRUE(third_packet_pop_by_c_api.ok());
    EXPECT_EQ(dns_packet_len, third_packet_pop_by_c_api.unpack().msg_hdr.len);
    EXPECT_EQ(dns_l2_len, third_packet_pop_by_c_api.unpack().msg_hdr.maclen);
    EXPECT_EQ(dns_packet_ifn, third_packet_pop_by_c_api.unpack().msg_hdr.if_index);
    EXPECT_EQ(memcmp(dns_req.data(), third_packet_pop_by_c_api.unpack().data.get(), dns_l2_len), 0);

    auto empty_post_packet_pop_by_c_api = pop_packet_by_c_api();
    EXPECT_FALSE(empty_post_packet_pop_by_c_api.ok());
}

TEST_F(ShmPktQueueTest, check_double_init)
{
    EXPECT_EQ(init_queue(), 1);
    EXPECT_EQ(init_queue(), 0);
}

TEST(NotShmPktQueueTest, check_improper_init)
{
    shm_pkt_queue_stub *queue_id = get_shm_pkt_queue_id();
    EXPECT_EQ(init_shm_pkt_queue(queue_id, "NoSuchShmDevice", queue_name), 0);
    EXPECT_EQ(
        push_to_shm_pkt_queue(
            queue_id,
            packet_data,
            packet_len,
            shmq_msg_mode_l2,
            shmq_msg_no_proto,
            l2_len,
            packet_ifn
        ),
        0
    );
    EXPECT_EQ(nullptr,  pop_from_shm_pkt_queue(queue_id));
    EXPECT_EQ(is_shm_pkt_queue_empty(queue_id), 1);
}

TEST(NotShmPktQueueTest, check_init_after_delete)
{
    shm_pkt_queue_stub *queue_id = get_shm_pkt_queue_id();
    delete_shm_pkt_queue(queue_id);
    EXPECT_THROW(init_shm_pkt_queue(queue_id, "NoSuchShmDevice", queue_name), std::out_of_range);
}
