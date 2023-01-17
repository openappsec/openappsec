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

#include "shmem_ipc.h"

#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>

#include "shared_ring_queue.h"
#include "shared_ipc_debug.h"

#define UNUSED(x) (void)(x)

const int corrupted_shmem_error = CORRUPTED_SHMEM_ERROR;
static const size_t max_one_way_queue_name_length = MAX_ONE_WAY_QUEUE_NAME_LENGTH;
static const size_t max_shmem_path_length = 72;

struct SharedMemoryIPC {
    char shm_name[32];
    SharedRingQueue *rx_queue;
    SharedRingQueue *tx_queue;
};

void
debugInitial(int is_error, const char *func, const char *file, int line_num, const char *fmt, ...)
{
    UNUSED(is_error);
    UNUSED(func);
    UNUSED(file);
    UNUSED(line_num);

    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

void (*debug_int)(int is_error, const char *func, const char *file, int line_num, const char *fmt, ...) = debugInitial;

static int
isTowardsOwner(int is_owner, int is_tx)
{
    if (is_owner) return !is_tx;
    return is_tx;
}

static SharedRingQueue *
createOneWayIPCQueue(
    const char *name,
    const uint32_t user_id,
    const uint32_t group_id,
    int is_tx_queue,
    int is_owner,
    uint16_t num_of_queue_elem
)
{
    SharedRingQueue *ring_queue = NULL;
    char queue_name[max_one_way_queue_name_length];
    char shmem_path[max_shmem_path_length];
    const char *direction = isTowardsOwner(is_owner, is_tx_queue) ? "rx" : "tx";
    snprintf(queue_name, sizeof(queue_name) - 1, "__cp_nano_%s_shared_memory_%s__", direction, name);

    writeDebug(
        TraceLevel,
        "Creating one way IPC queue. Name: %s, direction: %s, size: %d",
        name,
        direction,
        num_of_queue_elem
    );
    ring_queue = createSharedRingQueue(queue_name, num_of_queue_elem, is_owner, isTowardsOwner(is_owner, is_tx_queue));
    if (ring_queue == NULL) {
        writeDebug(
            WarningLevel,
            "Failed to create %s shared ring queue of size=%d for '%s'\n",
            direction,
            num_of_queue_elem,
            queue_name
        );
        return NULL;
    }
    int ret = snprintf(shmem_path, sizeof(shmem_path) - 1, "/dev/shm/%s", queue_name);
    if (ret < 0 || (size_t)ret < (strlen(direction) + strlen(name))) {
        return NULL;
    }

    if (is_owner && chmod(shmem_path, 0666) == -1) {
        writeDebug(WarningLevel, "Failed to set the permissions");
        destroySharedRingQueue(ring_queue, is_owner, isTowardsOwner(is_owner, is_tx_queue));
        return NULL;
    }

    writeDebug(
        TraceLevel,
        "Successfully created one way IPC queue. "
        "Name: %s, user id: %u, group id: %u, is owner: %d, number of queue elements: %u, direction: %s, path: %s",
        queue_name,
        user_id,
        group_id,
        is_owner,
        num_of_queue_elem,
        direction,
        shmem_path
    );
    return ring_queue;
}

SharedMemoryIPC *
initIpc(
    const char queue_name[32],
    uint32_t user_id,
    uint32_t group_id,
    int is_owner,
    uint16_t num_of_queue_elem,
    void (*debug_func)(int is_error, const char *func, const char *file, int line_num, const char *fmt, ...))
{
    SharedMemoryIPC *ipc = NULL;
    debug_int = debug_func;

    writeDebug(
        TraceLevel,
        "Initializing new IPC. "
        "Queue name: %s, user id: %u, group id: %u, is owner: %d, number of queue elements: %u\n",
        queue_name,
        user_id,
        group_id,
        is_owner,
        num_of_queue_elem
    );

    ipc = malloc(sizeof(SharedMemoryIPC));
    if (ipc == NULL) {
        writeDebug(WarningLevel, "Failed to allocate Shared Memory IPC for '%s'\n", queue_name);
        debug_int = debugInitial;
        return NULL;
    }

    ipc->rx_queue = NULL;
    ipc->tx_queue = NULL;

    ipc->rx_queue = createOneWayIPCQueue(queue_name, user_id, group_id, 0, is_owner, num_of_queue_elem);
    if (ipc->rx_queue == NULL) {
        writeDebug(
            WarningLevel,
            "Failed to allocate rx queue. "
            "Queue name: %s, user id: %u, group id: %u, is owner: %d, number of queue elements: %u",
            queue_name,
            user_id,
            group_id,
            is_owner,
            num_of_queue_elem
        );

        destroyIpc(ipc, is_owner);
        debug_int = debugInitial;
        return NULL;
    }

    ipc->tx_queue = createOneWayIPCQueue(queue_name, user_id, group_id, 1, is_owner, num_of_queue_elem);
    if (ipc->tx_queue == NULL) {
        writeDebug(
            WarningLevel,
            "Failed to allocate rx queue. "
            "Queue name: %s, user id: %u, group id: %u, is owner: %d, number of queue elements: %u",
            queue_name,
            user_id,
            group_id,
            is_owner,
            num_of_queue_elem
        );
        destroyIpc(ipc, is_owner);
        debug_int = debugInitial;
        return NULL;
    }

    writeDebug(TraceLevel, "Successfully allocated IPC");

    strncpy(ipc->shm_name, queue_name, sizeof(ipc->shm_name));
    return ipc;
}

void
resetIpc(SharedMemoryIPC *ipc, uint16_t num_of_data_segments)
{
    writeDebug(TraceLevel, "Reseting IPC queues\n");
    resetRingQueue(ipc->rx_queue, num_of_data_segments);
    resetRingQueue(ipc->tx_queue, num_of_data_segments);
}

void
destroyIpc(SharedMemoryIPC *shmem, int is_owner)
{
    writeDebug(TraceLevel, "Destroying IPC queues\n");

    if (shmem->rx_queue != NULL) {
        destroySharedRingQueue(shmem->rx_queue, is_owner, isTowardsOwner(is_owner, 0));
        shmem->rx_queue = NULL;
    }
    if (shmem->tx_queue != NULL) {
        destroySharedRingQueue(shmem->tx_queue, is_owner, isTowardsOwner(is_owner, 1));
        shmem->tx_queue = NULL;
    }
    debug_int = debugInitial;
    free(shmem);
}

void
dumpIpcMemory(SharedMemoryIPC *ipc)
{
    writeDebug(WarningLevel, "Ipc memory dump:\n");
    writeDebug(WarningLevel, "RX queue:\n");
    dumpRingQueueShmem(ipc->rx_queue);
    writeDebug(WarningLevel, "TX queue:\n");
    dumpRingQueueShmem(ipc->tx_queue);
}

int
sendData(SharedMemoryIPC *ipc, const uint16_t data_to_send_size, const char *data_to_send)
{
    writeDebug(TraceLevel, "Sending data of size %u\n", data_to_send_size);
    return pushToQueue(ipc->tx_queue, data_to_send, data_to_send_size);
}

int
sendChunkedData(
    SharedMemoryIPC *ipc,
    const uint16_t *data_to_send_sizes,
    const char **data_elem_to_send,
    const uint8_t num_of_data_elem
)
{
    writeDebug(TraceLevel, "Sending %u chunks of data\n", num_of_data_elem);

    return pushBuffersToQueue(ipc->tx_queue, data_elem_to_send, data_to_send_sizes, num_of_data_elem);
}

int
receiveData(SharedMemoryIPC *ipc, uint16_t *received_data_size, const char **received_data)
{
    int res = peekToQueue(ipc->rx_queue, received_data, received_data_size);
    writeDebug(TraceLevel, "Received data from queue. Res: %d, data size: %u\n", res, *received_data_size);
    return res;
}

int
popData(SharedMemoryIPC *ipc)
{
    int res = popFromQueue(ipc->rx_queue);
    writeDebug(TraceLevel, "Popped data from queue. Res: %d\n", res);
    return res;
}

int
isDataAvailable(SharedMemoryIPC *ipc)
{
    int res = !isQueueEmpty(ipc->rx_queue);
    writeDebug(TraceLevel, "Checking if there is data pending to be read. Res: %d\n", res);
    return res;
}

int
isCorruptedShmem(SharedMemoryIPC *ipc, int is_owner)
{
    if (isCorruptedQueue(ipc->rx_queue, isTowardsOwner(is_owner, 0)) ||
        isCorruptedQueue(ipc->tx_queue, isTowardsOwner(is_owner, 1))
    ) {
        writeDebug(WarningLevel, "Detected corrupted shared memory queue. Shared memory name: %s", ipc->shm_name);
        return 1;
    }

    return 0;
}
