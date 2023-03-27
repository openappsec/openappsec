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

#include <iostream>
#include <map>
#include <sstream>
#include <sys/time.h>
#include "common.h"

#include "shared_string_wrapper.h"

const int shm_pkt_queue_bad_alloc = -2;
namespace bip = boost::interprocess;

bip::managed_shared_memory::segment_manager *SharedStringWrapper::alloc = nullptr;

class Impl
{
public:
    int
    init_queue(const char *shm_name, const char *queue_name)
    {
        if(is_queue_initialized) {
            return 0;
        }
        try {
            segment = std::make_unique<bip::managed_shared_memory>(bip::open_only, shm_name);
        } catch(...){
            // Most likely the shared memory wasn't created yet.
            return 0;
        }

        SharedStringWrapper::setAlloc(segment->get_segment_manager());
        queue = segment->find_or_construct<ring_buffer>(queue_name)();
        if(queue == nullptr) {
            return 0;
        }
        is_queue_initialized = true;
        return 1;
    }

    int
    push_to_queue(
        const u_char *msg,
        uint16_t length,
        shmq_msg_mode mode,
        shm_pkt_msg_proto l3_proto,
        uint16_t l2_length,
        uint16_t if_index)
    {
        if(!is_queue_initialized) return 0;

        SharedStringWrapper packet_node;

        shm_pkt_queue_msg_hdr msg_hdr;
        msg_hdr.mode = mode;
        msg_hdr.l3_proto = l3_proto;
        msg_hdr.len = length;
        msg_hdr.maclen = l2_length;
        msg_hdr.if_index = if_index;

        packet_node.reserve(sizeof(msg_hdr) + length);
        packet_node.append(reinterpret_cast<u_char *>(&msg_hdr), sizeof(msg_hdr));
        packet_node.append(msg, length);
        return queue->push(packet_node);
    }

    u_char *
    pop_from_queue()
    {
        if (is_queue_initialized && queue->read_available()) {
            u_char *msg = reinterpret_cast<u_char *>(malloc(queue->front().size()));
            if (msg) {
                std::copy(queue->front().begin(), queue->front().end(), msg);
                queue->pop();
                return msg;
            }
        }
        return nullptr;
    }

    int
    is_queue_empty()
    {
        // uninitialized queue is treated as empty
        if(is_queue_initialized && queue->read_available()) {
            return 0;
        }
        return 1;
    }

    void
    clear(void)
    {
        while (!is_queue_empty()) { queue->pop(); }
    }

    static Impl&
    getRef(shm_pkt_queue_stub *id)
    {
        return map.at(id);
    }

    static shm_pkt_queue_stub*
    getId()
    {
        ++index;
        auto ptr = reinterpret_cast<shm_pkt_queue_stub*>(index);
        map.insert(std::make_pair(ptr, Impl()));
        return ptr;
    }

    static void
    deleteId(shm_pkt_queue_stub *id)
    {
        map.erase(id);
    }

private:
    ring_buffer *queue = nullptr;
    std::unique_ptr<bip::managed_shared_memory> segment = nullptr;
    bool is_queue_initialized = false;

    static std::map<shm_pkt_queue_stub*, Impl> map;
    static u_int64_t index;
};

std::map<shm_pkt_queue_stub *, Impl> Impl::map;
u_int64_t Impl::index = 0;

shm_pkt_queue_stub*
get_shm_pkt_queue_id()
{
    return Impl::getId();
}

int
init_shm_pkt_queue(shm_pkt_queue_stub *id, const char *shm_name, const char *queue_name)
{
    return Impl::getRef(id).init_queue(shm_name, queue_name);
}

int
push_to_shm_pkt_queue(
    shm_pkt_queue_stub *id,
    const unsigned char *msg,
    uint16_t length,
    shmq_msg_mode type,
    shm_pkt_msg_proto l3_proto,
    uint16_t l2_length,
    uint16_t if_index)
{
    return Impl::getRef(id).push_to_queue(msg, length, type, l3_proto, l2_length, if_index);
}

unsigned char*
pop_from_shm_pkt_queue(shm_pkt_queue_stub *id)
{
    return Impl::getRef(id).pop_from_queue();
}

int
is_shm_pkt_queue_empty(shm_pkt_queue_stub *id)
{
    return Impl::getRef(id).is_queue_empty();
}

void
delete_shm_pkt_queue(shm_pkt_queue_stub *id)
{
    return Impl::deleteId(id);
}
