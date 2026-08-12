# Shared-Memory IPC

Attachments (the nginx C module, kernel modules) run inside third-party
processes and talk to the agent-core nano-service over **shared memory**, not
sockets. `core/`'s IPC layer is the transport. These are **C-ABI** headers
(`extern "C"`) precisely so the C attachment code can link them.

Reach for it when: wiring an attachment <-> nano-service channel, or debugging
why traffic/verdicts aren't crossing between nginx and the handler. For the
nginx-attachment view of this, see
[WAAP_NGINX_ATTACHMENT.md](../../WAAP_NGINX_ATTACHMENT.md).

## Two transports

| Header | Transport | Used for |
|--------|-----------|----------|
| `core/include/attachments/shmem_ipc.h` | Bidirectional **request/verdict** ring queue | HTTP transaction data + verdicts between nginx module and the HTTP transaction handler |
| `core/include/general/shmpktqueue.h` | One-way **packet** queue | L2/L3 packet hand-off (e.g. VPP/network path) |

Implementations: `core/shmem_ipc/`, `core/shmem_ipc_2/` (v2), `core/shmem_infra/`
(shared ring-buffer mechanics), `core/shm_pkt_queue/` (the packet queue).
There's a GoogleMock double `core/include/services_sdk/interfaces/mock/mock_shmem_ipc.h`.

## shmem_ipc.h -- request/verdict queue

```c
typedef struct SharedMemoryIPC SharedMemoryIPC;

// One endpoint of the channel. is_owner = 1 on the agent-core side, 0 on the attachment.
SharedMemoryIPC * initIpc(
    const char queue_name[32], uint32_t user_id, uint32_t group_id,
    int is_owner, uint16_t num_of_queue_elem,
    void (*debug_func)(int is_error, const char *func, const char *file, int line_num, const char *fmt, ...));
void destroyIpc(SharedMemoryIPC *ipc, int is_owner);

// Producer side
int sendData(SharedMemoryIPC *ipc, uint16_t data_to_send_size, const char *data_to_send);
int sendChunkedData(SharedMemoryIPC *ipc, const uint16_t *sizes, const char **elems, uint8_t num_elems);

// Consumer side
int isDataAvailable(SharedMemoryIPC *ipc);
int receiveData(SharedMemoryIPC *ipc, uint16_t *received_data_size, const char **received_data);
int popData(SharedMemoryIPC *ipc);              // release the entry after reading

// Maintenance / health
void resetIpc(SharedMemoryIPC *ipc, uint16_t num_of_data_segments);
int  isCorruptedShmem(SharedMemoryIPC *ipc, int is_owner);   // detect a torn/garbage ring
void dumpIpcMemory(SharedMemoryIPC *ipc);
uint16_t getSegmentEntrySize(void);
extern const int corrupted_shmem_error;
```

Lifecycle and flow:
1. Both sides `initIpc` the **same `queue_name`**; one passes `is_owner=1`
   (agent core), the other `is_owner=0` (attachment). `num_of_queue_elem` sizes
   the ring.
2. Producer `sendData` / `sendChunkedData` (chunked sends a multi-segment
   message without concatenating it first).
3. Consumer polls `isDataAvailable`, `receiveData` to get a borrowed pointer to
   the entry, then `popData` to free the slot. The pointer is valid until you
   pop, so copy out before popping if you need to keep it.
4. `isCorruptedShmem` guards against a crashed peer leaving a torn ring; on
   `corrupted_shmem_error` the channel is `resetIpc`'d.

The `debug_func` callback lets the C ring route its logging back into the host's
logger (the agent passes one that forwards to `Debug`).

## shmpktqueue.h -- packet queue

A lighter one-way queue for whole packets (L2/L3), with a small typed header:

```c
typedef struct { uint16_t mode, l3_proto, len, maclen, if_index; unsigned char data[0]; }
        shm_pkt_queue_msg_hdr;

shm_pkt_queue_stub *get_shm_pkt_queue_id(void);
int  init_shm_pkt_queue(shm_pkt_queue_stub *id, const char *shm_name, const char *queue_name);
int  push_to_shm_pkt_queue(shm_pkt_queue_stub *id, const unsigned char *msg, uint16_t length,
                           shmq_msg_mode mode, shm_pkt_msg_proto l3_proto,
                           uint16_t l2_length, uint16_t if_index);
unsigned char *pop_from_shm_pkt_queue(shm_pkt_queue_stub *id);
int  is_shm_pkt_queue_empty(shm_pkt_queue_stub *id);
void delete_shm_pkt_queue(shm_pkt_queue_stub *id);
```

`mode` flags (`shmq_msg_mode_l2/l3/bb`) and `l3_proto`
(`shmq_msg_proto_ipv4/ipv6`) describe each message; `bb` means "bounce back to
the incoming interface."

## Testing

`mock_shmem_ipc.h` lets you fake the channel in a unit test so a component can be
driven without a real shared-memory peer. For end-to-end checks the real ring is
exercised by the attachment integration paths.

## Key files

| File | Role |
|------|------|
| `core/include/attachments/shmem_ipc.h` | Request/verdict ring C ABI. |
| `core/include/attachments/shmem_ipc_2.h` | v2 of the ring API. |
| `core/include/general/shmpktqueue.h` | Packet queue C ABI. |
| `core/shmem_infra/` | Shared ring-buffer mechanics. |
| `core/shmem_ipc/`, `core/shmem_ipc_2/`, `core/shm_pkt_queue/` | Implementations. |
| `core/include/services_sdk/interfaces/mock/mock_shmem_ipc.h` | Test double. |
