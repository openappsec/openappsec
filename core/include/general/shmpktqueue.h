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

#ifndef __SHMPKTQUEUE_H__
#define __SHMPKTQUEUE_H__

#include <net/ethernet.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct shm_pkt_queue_stub shm_pkt_queue_stub;

typedef enum {
    shmq_msg_mode_l2    = 0x01, // Layer 2 packet
    shmq_msg_mode_l3    = 0x02, // Layer 3 packet
    shmq_msg_mode_bb    = 0x04, // Packet need to be bounced back to incoming interface
} shmq_msg_mode;

typedef enum {
    shmq_msg_no_proto   = 0,
    shmq_msg_proto_ipv4 = ETHERTYPE_IP,   // Internet Protocol version 4
    shmq_msg_proto_ipv6 = ETHERTYPE_IPV6, // Internet Protocol version 6
} shm_pkt_msg_proto;

typedef struct {
    uint16_t mode;          // Of type: shmq_msg_mode. Message mode flags.
    uint16_t l3_proto;      // Of type: shm_pkt_msg_proto. Message protocol: IPv4/IPv6, etc.
    uint16_t len;           // Data length
    uint16_t maclen;        // MAC header length. TODO: Remove it. Data content should be is enough
    uint16_t if_index;      // VPP Interface index
    unsigned char data[0];
} shm_pkt_queue_msg_hdr;

shm_pkt_queue_stub *get_shm_pkt_queue_id();

int init_shm_pkt_queue(shm_pkt_queue_stub *id, const char *shm_name, const char *queue_name);

int push_to_shm_pkt_queue(
    shm_pkt_queue_stub *id,
    const unsigned char *msg,
    uint16_t length,
    shmq_msg_mode mode,
    shm_pkt_msg_proto l3_proto,
    uint16_t l2_length,
    uint16_t if_index
);

unsigned char *pop_from_shm_pkt_queue(shm_pkt_queue_stub *id);

int is_shm_pkt_queue_empty(shm_pkt_queue_stub *id);

void delete_shm_pkt_queue(shm_pkt_queue_stub *id);

#ifdef __cplusplus
}
#endif

#endif // __SHMPKTQUEUE_H__
