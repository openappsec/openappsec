// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "shared_ring_queue.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include "shared_ipc_debug.h"

static const uint16_t empty_buff_mgmt_magic = 0xfffe;
static const uint16_t skip_buff_mgmt_magic = 0xfffd;
static const uint32_t max_write_size = 0xfffc;
const uint16_t max_num_of_data_segments = sizeof(DataSegment)/sizeof(uint16_t);

char g_rx_location_name[MAX_ONE_WAY_QUEUE_NAME_LENGTH] = "";
char g_tx_location_name[MAX_ONE_WAY_QUEUE_NAME_LENGTH] = "";
int32_t g_rx_fd = -1;
int32_t g_tx_fd = -1;
int32_t g_memory_size = -1;

static uint16_t g_num_of_data_segments = 0;

static int
getNumOfDataSegmentsNeeded(uint16_t data_size)
{
    int res = (data_size + SHARED_MEMORY_SEGMENT_ENTRY_SIZE - 1) / SHARED_MEMORY_SEGMENT_ENTRY_SIZE;
    writeDebug(
        TraceLevel, "Checking amount of segments needed. Res: %d, data size: %u, shmem entry size: %u",
        res,
        data_size,
        SHARED_MEMORY_SEGMENT_ENTRY_SIZE
    );
    return res;
}

static int
isThereEnoughMemoryInQueue(uint16_t write_pos, uint16_t read_pos, uint8_t num_of_elem_to_push)
{
    int res;

    writeDebug(
        TraceLevel, "Checking if memory has space for new elements. "
        "Num of elements to push: %u, write index: %u, read index: %u, amount of queue segments: %u",
        num_of_elem_to_push,
        write_pos,
        read_pos,
        g_num_of_data_segments
    );
    if (num_of_elem_to_push >= g_num_of_data_segments) {
        writeDebug(TraceLevel, "Amount of elements to push is larger then amount of available elements in the queue");
        return 0;
    }

    // add skipped elements during write that does not fit from cur write position till end of queue
    if (write_pos + num_of_elem_to_push > g_num_of_data_segments) {
        num_of_elem_to_push += g_num_of_data_segments - write_pos;
    }

    // removing the aspect of circularity in queue and simulating as if the queue continued at its end
    if (write_pos + num_of_elem_to_push >= g_num_of_data_segments) {
        read_pos += g_num_of_data_segments;
    }

    res = write_pos + num_of_elem_to_push < read_pos || write_pos >= read_pos;
    writeDebug(TraceLevel, "Finished checking if there is enough place in shared memory. Res: %d", res);
    return res;
}

static int
isGetPossitionSucceccful(SharedRingQueue *queue, uint16_t *read_pos, uint16_t *write_pos)
{
    if (g_num_of_data_segments == 0) return 0;

    *read_pos = queue->read_pos;
    *write_pos = queue->write_pos;

    if (queue->num_of_data_segments != g_num_of_data_segments) return 0;
    if (queue->size_of_memory != g_memory_size) return 0;
    if (*read_pos > g_num_of_data_segments) return 0;
    if (*write_pos > g_num_of_data_segments) return 0;

    return 1;
}

void
resetRingQueue(SharedRingQueue *queue, uint16_t num_of_data_segments)
{
    uint16_t *buffer_mgmt;
    unsigned int idx;

    queue->read_pos = 0;
    queue->write_pos = 0;
    queue->num_of_data_segments = num_of_data_segments;
    buffer_mgmt = (uint16_t *)queue->mgmt_segment.data;
    for (idx = 0; idx < queue->num_of_data_segments; idx++) {
        buffer_mgmt[idx] = empty_buff_mgmt_magic;
    }
}

SharedRingQueue *
createSharedRingQueue(const char *shared_location_name, uint16_t num_of_data_segments, int is_owner, int is_tx)
{
    SharedRingQueue *queue = NULL;
    uint16_t *buffer_mgmt;
    uint16_t shmem_fd_flags = is_owner ? O_RDWR | O_CREAT : O_RDWR;
    int32_t fd = -1;
    uint32_t size_of_memory;
    unsigned int idx;

    writeDebug(TraceLevel, "Creating a new shared ring queue");

    if (num_of_data_segments > max_num_of_data_segments) {
        writeDebug(
            WarningLevel,
            "createSharedRingQueue: Cannot create data segment with %d elements (max number of elements is %u)\n",
            num_of_data_segments,
            max_num_of_data_segments
        );
        return NULL;
    }

    g_num_of_data_segments = num_of_data_segments;

    fd = shm_open(shared_location_name, shmem_fd_flags, S_IRWXU | S_IRWXG | S_IRWXO);
    if (fd == -1) {
        writeDebug(
            WarningLevel,
            "createSharedRingQueue: Failed to open shared memory for '%s'. Errno: %d\n",
            shared_location_name,
            errno
        );
        return NULL;
    }

    size_of_memory = sizeof(SharedRingQueue) + (num_of_data_segments * sizeof(DataSegment));
    if (is_owner && ftruncate(fd, size_of_memory + 1) != 0) {
        writeDebug(
            WarningLevel,
            "createSharedRingQueue: Failed to ftruncate shared memory '%s' to size '%x'\n",
            shared_location_name,
            size_of_memory
        );
        close(fd);
        return NULL;
    }

    queue = (SharedRingQueue *)mmap(0, size_of_memory, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (queue == NULL) {
        writeDebug(
            WarningLevel,
            "createSharedRingQueue: Error allocating queue for '%s' of size=%x\n",
            shared_location_name,
            size_of_memory
        );
        close(fd);
        return NULL;
    }

    if (is_owner) {
        snprintf(queue->shared_location_name, MAX_ONE_WAY_QUEUE_NAME_LENGTH, "%s", shared_location_name);
        queue->num_of_data_segments = num_of_data_segments;
        queue->read_pos = 0;
        queue->write_pos = 0;
        queue->size_of_memory = size_of_memory;
        buffer_mgmt = (uint16_t *)queue->mgmt_segment.data;
        for (idx = 0; idx < queue->num_of_data_segments; idx++) {
            buffer_mgmt[idx] = empty_buff_mgmt_magic;
        }
        queue->owner_fd = fd;
    } else {
        queue->user_fd = fd;
    }

    g_memory_size = size_of_memory;
    if (is_tx) {
        g_tx_fd = fd;
        snprintf(g_tx_location_name, MAX_ONE_WAY_QUEUE_NAME_LENGTH, "%s", shared_location_name);
    } else {
        g_rx_fd = fd;
        snprintf(g_rx_location_name, MAX_ONE_WAY_QUEUE_NAME_LENGTH, "%s", shared_location_name);
    }

    writeDebug(
        TraceLevel,
        "Successfully created a new shared ring queue. "
        "Shared memory path: %s, number of segments: %u, is owner: %d, "
        "fd flags: %u, fd: %d, memory size: %u, read index: %u, write index: %u",
        shared_location_name,
        queue->num_of_data_segments,
        is_owner,
        shmem_fd_flags,
        fd,
        queue->size_of_memory,
        queue->read_pos,
        queue->write_pos
    );

    return queue;
}

void
destroySharedRingQueue(SharedRingQueue *queue, int is_owner, int is_tx)
{
    uint32_t size_of_memory = g_memory_size;
    int32_t fd = 0;

    if(is_owner) {
        queue->owner_fd = 0;
    } else {
        queue->user_fd = 0;
    }

    if (is_tx) {
        fd = g_tx_fd;
        g_tx_fd = -1;
    } else {
        fd = g_rx_fd;
        g_rx_fd = -1;
    }

    if (munmap(queue, size_of_memory) != 0) {
        writeDebug(WarningLevel, "destroySharedRingQueue: Failed to unmap shared ring queue\n");
    }
    if (fd > 0) close(fd);
    fd = 0;

    // shm_open cleanup
    if(is_owner) {
        shm_unlink(is_tx ? g_tx_location_name : g_rx_location_name);
    }
    writeDebug(TraceLevel, "Successfully destroyed shared ring queue. Is owner: %d", is_owner);
}

void
dumpRingQueueShmem(SharedRingQueue *queue)
{
    uint16_t segment_idx;
    uint16_t data_idx;
    uint16_t *buffer_mgmt = NULL;
    char data_byte;

    writeDebug(
        WarningLevel,
        "owner_fd: %d, user_fd: %d, size_of_memory: %d, write_pos: %d, read_pos: %d, num_of_data_segments: %d\n",
        queue->owner_fd,
        queue->user_fd,
        queue->size_of_memory,
        queue->write_pos,
        queue->read_pos,
        queue->num_of_data_segments
    );

    writeDebug(WarningLevel, "mgmt_segment:");
    buffer_mgmt = (uint16_t *)queue->mgmt_segment.data;
    for (segment_idx = 0; segment_idx < queue->num_of_data_segments; segment_idx++) {
        writeDebug(WarningLevel, "%s%u", (segment_idx == 0 ? " " : ", "), buffer_mgmt[segment_idx]);
    }

    writeDebug(WarningLevel, "\ndata_segment: ");
    for (segment_idx = 0; segment_idx < queue->num_of_data_segments; segment_idx++) {
        writeDebug(WarningLevel, "\nMgmt index: %u, value: %u,\nactual data: ", segment_idx, buffer_mgmt[segment_idx]);
        for (data_idx = 0; data_idx < SHARED_MEMORY_SEGMENT_ENTRY_SIZE; data_idx++) {
            data_byte = queue->data_segment[segment_idx].data[data_idx];
            writeDebug(WarningLevel, isprint(data_byte) ? "%c" : "%02X", data_byte);
        }
    }
    writeDebug(WarningLevel, "\nEnd of memory\n");
}

int
peekToQueue(SharedRingQueue *queue, const char **output_buffer, uint16_t *output_buffer_size)
{
    uint16_t read_pos;
    uint16_t write_pos;
    uint16_t *buffer_mgmt = (uint16_t *)queue->mgmt_segment.data;

    if (!isGetPossitionSucceccful(queue, &read_pos, &write_pos)) {
        writeDebug(WarningLevel, "Corrupted shared memory - cannot peek");
        return -1;
    }

    writeDebug(
        TraceLevel,
        "Reading data from queue. Read index: %u, number of queue elements: %u",
        read_pos,
        g_num_of_data_segments
    );

    if (read_pos == write_pos) {
        writeDebug(WarningLevel, "peekToQueue: Failed to read from an empty queue\n");
        return -1;
    }

    if (read_pos >= g_num_of_data_segments) {
        writeDebug(
            WarningLevel,
            "peekToQueue: Failed to read from a corrupted queue! (read_pos= %d > num_of_data_segments=%d)\n",
            read_pos,
            g_num_of_data_segments
        );
        return CORRUPTED_SHMEM_ERROR;
    }

    if (buffer_mgmt[read_pos] == skip_buff_mgmt_magic) {
        for ( ; read_pos < g_num_of_data_segments && buffer_mgmt[read_pos] == skip_buff_mgmt_magic; ++read_pos) {
            buffer_mgmt[read_pos] = empty_buff_mgmt_magic;
        }
    }

    if (read_pos == g_num_of_data_segments) read_pos = 0;

    *output_buffer_size = buffer_mgmt[read_pos];
    *output_buffer = queue->data_segment[read_pos].data;

    queue->read_pos = read_pos;

    writeDebug(
        TraceLevel,
        "Successfully read data from queue. Data size: %u, new Read index: %u",
        *output_buffer_size,
        queue->read_pos
    );
    return 0;
}

int
pushBuffersToQueue(
    SharedRingQueue *queue,
    const char **input_buffers,
    const uint16_t *input_buffers_sizes,
    const uint8_t num_of_input_buffers
)
{
    int idx;
    uint32_t large_total_elem_size = 0;
    uint16_t read_pos;
    uint16_t write_pos;
    uint16_t total_elem_size;
    uint16_t *buffer_mgmt = (uint16_t *)queue->mgmt_segment.data;
    uint16_t end_pos;
    uint16_t num_of_segments_to_write;
    char *current_copy_pos;

    if (!isGetPossitionSucceccful(queue, &read_pos, &write_pos)) {
        writeDebug(WarningLevel, "Corrupted shared memory - cannot push new buffers");
        return -1;
    }

    writeDebug(
        TraceLevel,
        "Writing new data to queue. write index: %u, number of queue elements: %u, number of elements to push: %u",
        write_pos,
        g_num_of_data_segments,
        num_of_input_buffers
    );

    for (idx = 0; idx < num_of_input_buffers; idx++) {
        large_total_elem_size += input_buffers_sizes[idx];

        if (large_total_elem_size > max_write_size) {
            writeDebug(
                WarningLevel,
                "Requested write size %u exceeds the %u write limit",
                large_total_elem_size,
                max_write_size
            );
            return -2;
        }
    }
    total_elem_size = (uint16_t)large_total_elem_size;

    num_of_segments_to_write = getNumOfDataSegmentsNeeded(total_elem_size);

    writeDebug(
        TraceLevel,
        "Checking if there is enough space to push new data. Total new data size: %u, number of segments needed: %u",
        total_elem_size,
        num_of_segments_to_write
    );


    if (!isThereEnoughMemoryInQueue(write_pos, read_pos, num_of_segments_to_write)) {
        writeDebug(DebugLevel, "Cannot write to a full queue");
        return -3;
    }

    if (write_pos >= g_num_of_data_segments) {
        writeDebug(
            DebugLevel,
            "Cannot write to a location outside the queue. Write index: %u, number of queue elements: %u",
            write_pos,
            g_num_of_data_segments
        );
        return -4;
    }

    if (write_pos + num_of_segments_to_write > g_num_of_data_segments) {
        for ( ; write_pos < g_num_of_data_segments; ++write_pos) {
            buffer_mgmt[write_pos] = skip_buff_mgmt_magic;
        }
        write_pos = 0;
    }

    writeDebug(
        TraceLevel,
        "Setting new management data. Write index: %u, total elements in index: %u",
        write_pos,
        total_elem_size
    );

    buffer_mgmt[write_pos] = total_elem_size;
    current_copy_pos = queue->data_segment[write_pos].data;
    for (idx = 0; idx < num_of_input_buffers; idx++) {
        writeDebug(
            TraceLevel,
            "Writing data to queue. Data index: %u, data size: %u, copy destination: %p",
            idx,
            input_buffers_sizes[idx],
            current_copy_pos
        );
        memcpy(current_copy_pos, input_buffers[idx], input_buffers_sizes[idx]);
        current_copy_pos += input_buffers_sizes[idx];
    }
    write_pos++;

    end_pos = write_pos + num_of_segments_to_write - 1;
    for ( ; write_pos < end_pos; ++write_pos) {
        buffer_mgmt[write_pos] = skip_buff_mgmt_magic;
    }

    if (write_pos >= g_num_of_data_segments) write_pos = 0;
    queue->write_pos = write_pos;
    writeDebug(TraceLevel, "Successfully pushed data to queue. New write index: %u", write_pos);

    return 0;
}

int
pushToQueue(SharedRingQueue *queue, const char *input_buffer, const uint16_t input_buffer_size)
{
    return pushBuffersToQueue(queue, &input_buffer, &input_buffer_size, 1);
}

int
popFromQueue(SharedRingQueue *queue)
{
    uint16_t num_of_read_segments;
    uint16_t read_pos;
    uint16_t write_pos;
    uint16_t end_pos;
    uint16_t *buffer_mgmt = (uint16_t *)queue->mgmt_segment.data;

    if (!isGetPossitionSucceccful(queue, &read_pos, &write_pos)) {
        writeDebug(WarningLevel, "Corrupted shared memory - cannot pop data");
        return -1;
    }

    writeDebug(
        TraceLevel,
        "Removing data from queue. new data to queue. Read index: %u, number of queue elements: %u",
        read_pos,
        g_num_of_data_segments
    );

    if (read_pos == write_pos) {
        writeDebug(TraceLevel, "Cannot pop data from empty queue");
        return -1;
    }
    num_of_read_segments = getNumOfDataSegmentsNeeded(buffer_mgmt[read_pos]);

    if (read_pos + num_of_read_segments > g_num_of_data_segments) {
        for ( ; read_pos < g_num_of_data_segments; ++read_pos ) {
            buffer_mgmt[read_pos] = empty_buff_mgmt_magic;
        }
        read_pos = 0;
    }

    end_pos = read_pos + num_of_read_segments;

    for ( ; read_pos < end_pos; ++read_pos ) {
        buffer_mgmt[read_pos] = empty_buff_mgmt_magic;
    }

    if (read_pos < g_num_of_data_segments && buffer_mgmt[read_pos] == skip_buff_mgmt_magic) {
        for ( ; read_pos < g_num_of_data_segments; ++read_pos ) {
            buffer_mgmt[read_pos] = empty_buff_mgmt_magic;
        }
    }

    writeDebug(
        TraceLevel,
        "Size of data to remove: %u, number of queue elements to free: %u, current read index: %u, end index: %u",
        buffer_mgmt[read_pos],
        num_of_read_segments,
        read_pos,
        end_pos
    );

    if (read_pos == g_num_of_data_segments) read_pos = 0;

    queue->read_pos = read_pos;
    writeDebug(TraceLevel, "Successfully popped data from queue. New read index: %u", read_pos);

    return 0;
}

int
isQueueEmpty(SharedRingQueue *queue)
{
    return queue->read_pos == queue->write_pos;
}

int
isCorruptedQueue(SharedRingQueue *queue, int is_tx)
{
    writeDebug(
        TraceLevel,
        "Checking if shared ring queue is corrupted. "
        "g_num_of_data_segments = %u, queue->num_of_data_segments = %u, queue->read_pos = %u, queue->write_pos = %u, "
        "g_memory_size = %d, queue->size_of_memory = %d, "
        "queue->shared_location_name = %s, g_tx_location_name = %s, g_rx_location_name = %s, is_tx = %d",
        g_num_of_data_segments,
        queue->num_of_data_segments,
        queue->read_pos,
        queue->write_pos,
        g_memory_size,
        queue->size_of_memory,
        queue->shared_location_name,
        g_tx_location_name,
        g_rx_location_name,
        is_tx
    );

    if (g_num_of_data_segments == 0) return 0;

    if (queue->num_of_data_segments != g_num_of_data_segments) return 1;
    if (queue->size_of_memory != g_memory_size) return 1;
    if (queue->read_pos > g_num_of_data_segments) return 1;
    if (queue->write_pos > g_num_of_data_segments) return 1;
    if (strcmp(queue->shared_location_name, is_tx ? g_tx_location_name : g_rx_location_name) != 0) return 1;

    return 0;
}
