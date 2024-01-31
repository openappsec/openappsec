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

#ifndef __SHMEM_IPC_H__
#define __SHMEM_IPC_H__

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus

typedef struct SharedMemoryIPC SharedMemoryIPC;
extern const int corrupted_shmem_error;

SharedMemoryIPC * initIpc(
    const char queue_name[32],
    const uint32_t user_id,
    const uint32_t group_id,
    int is_owner,
    uint16_t num_of_queue_elem,
    void (*debug_func)(int is_error, const char *func, const char *file, int line_num, const char *fmt, ...)
);

void destroyIpc(SharedMemoryIPC *ipc, int is_owner);

int sendData(SharedMemoryIPC *ipc, const uint16_t data_to_send_size, const char *data_to_send);

int
sendChunkedData(
    SharedMemoryIPC *ipc,
    const uint16_t *data_to_send_sizes,
    const char **data_elem_to_send,
    const uint8_t num_of_data_elem
);

int receiveData(SharedMemoryIPC *ipc, uint16_t *received_data_size, const char **received_data);

int popData(SharedMemoryIPC *ipc);

int isDataAvailable(SharedMemoryIPC *ipc);

void resetIpc(SharedMemoryIPC *ipc, uint16_t num_of_data_segments);

void dumpIpcMemory(SharedMemoryIPC *ipc);

int isCorruptedShmem(SharedMemoryIPC *ipc, int is_owner);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // __SHMEM_IPC_H__
