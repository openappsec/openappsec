# core/ Overview and Directory Map

`core/` is built into a set of static/shared libraries that are linked into the
nano-services (`nodes/`) and, for the IPC pieces, the attachments
(`attachments/`). Everything outside `core/include/` is implementation; the
public surface a component should `#include` lives under `core/include/`.

## The include tree (`core/include/`)

```
core/include/
+-- general/          Foundational, dependency-light headers (DI, types, macros)
+-- services_sdk/
|   +-- interfaces/   The I_* service contracts components Consume/Provide
|   +-- resources/    Capabilities: Event/Listener, Component, Context, Config,
|   |                 Report, Metric, Table opaque storage, Version
|   +-- utilities/    Small helpers: Maybe-friendly containers, caches, flags,
|                     enum helpers, cereal map adapters
+-- attachments/      C-ABI IPC headers shared with the C nginx/kernel modules
+-- internal/         Low-level implementation headers (not for direct use)
```

Rule of thumb: include the public umbrella header (e.g. `event.h`,
`listener.h`, `singleton.h`), never the `*_impl.h` or `impl/` headers it pulls
in. The impl headers `#error` out if included directly.

### `general/` highlights

| Header | Purpose |
|--------|---------|
| `singleton.h` | Dependency-injection registry (`Provide` / `Consume`). |
| `common.h` | Platform macros, integer typedefs, small std extensions. |
| `debug.h` | Logging macros (`dbgTrace`/`dbgInfo`/`dbgWarning`/...), `dbgAssert`, `AlertInfo`. |
| `maybe_res.h` | `Maybe<T, Err>` result type and `genError(...)`. |
| `buffer.h` | Segmented byte `Buffer` (owned / static / volatile segments). |
| `table.h` | Keyed in-memory state table with TTL (the `Table<Key>` component). |
| `mainloop.h` | The `MainloopComponent` that provides `I_MainLoop`. |
| `environment.h` | The environment/context component. |
| `config_component.h`, `logging_comp.h`, `time_proxy.h`, `rest_server.h`, `encryptor.h` | The components providing the matching `I_*` interfaces. |
| `intelligence_comp_v2.h` | Threat-intelligence client component. |
| `tenant_manager.h`, `tenant_profile_pair.h` | Multi-tenancy. |
| `scope_exit.h`, `tostring.h`, `hash_combine.h` | RAII guard, stringification, hashing. |

## core/ subdirectories (implementation libraries)

Each directory is a library (with its `CMakeLists.txt`) plus a `*_ut/` test
target. Grouped by role:

### Runtime foundation
| Dir | Responsibility |
|-----|----------------|
| `singleton/` | The `Singleton` registry implementation. |
| `event_is/` | Event/Listener dispatch internals. |
| `mainloop/` | Cooperative scheduler (provides `I_MainLoop`). |
| `environment/` | Context stack, tracing/spans, tenant+profile scoping (16 files). |
| `config/` | Configuration loading/parsing, profile-aware settings. |
| `debug_is/` | Debug/logging framework backing `debug.h`. |
| `table/` | TTL state tables + opaque per-key storage. |
| `version/` | Build/version metadata. |

### Communication & I/O
| Dir | Responsibility |
|-----|----------------|
| `messaging/`, `messaging_buffer/` | Async/sync HTTP to the management plane (FOG), with buffering (20 files). |
| `rest/` | Inbound REST server framework. |
| `curl_http_client/` | libcurl-based HTTP client. |
| `socket_is/`, `ioctl_is/`, `trap_is/`, `shell_cmd/` | OS-level I/O, ioctl, signal/trap handling, shell execution. |
| `shmem_ipc/`, `shmem_ipc_2/`, `shmem_infra/`, `shm_pkt_queue/` | Shared-memory IPC ring buffers used by attachments. |
| `message/` | Message envelope/serialization helpers. |

### Domain services
| Dir | Responsibility |
|-----|----------------|
| `intelligence_is/`, `intelligence_is_v2/` | Threat-intelligence query/registration clients (v2 is current, 20 files). |
| `report/`, `report_messaging/` | Security log/report objects and their delivery. |
| `metric/` | Telemetry metrics (counters, averages, gauges). |
| `logging/` | Structured logging component (12 files). |
| `agent_details/`, `agent_details_reporter/`, `env_details/` | Agent identity/version and environment metadata. |
| `instance_awareness/` | Multi-instance/worker awareness. |
| `tenant_manager/` | Tenant/profile lifecycle for multi-tenancy. |
| `cpu/`, `memory_consumption/` | Resource self-monitoring. |
| `encryptor/` | AES-256 / XOR / Base64 encode-decode. |
| `connkey/` | Connection-key (5-tuple) generation and hashing. |
| `compression/`, `buffers/` | Compression utilities and the `Buffer` implementation. |
| `agent_core_utilities/` | Filesystem/string/process helpers (`NGEN::...`). |
| `attachments/` | C++ side of attachment registration/IPC. |

### Build / test support
| Dir | Responsibility |
|-----|----------------|
| `cptest/` | The project test harness on top of GoogleTest/CMock (`cptest.h`). |
| `core_ut/` | Cross-cutting core unit tests. |
| `external_sdk/` | Glue for externally consumed SDK headers. |
| `build/` | Generated build artifacts (out-of-source). |

## How core/ is compiled

`core/` is added first by the root `CMakeLists.txt:12` (before `components` and
`attachments`), so its libraries and `events/include` headers are available to
everything downstream. Unit tests are declared with the `add_unit_test(name,
"a_ut.cc;b_ut.cc", "lib1;lib2")` helper and link a baseline UT library set
defined in `CMakeCommon.txt:51` (version, debug_is, report, cptest, singleton,
environment, buffers, rest, config, ...). See [the build notes in
CLAUDE.md](../../CLAUDE.md) for the linker-dependency gotcha when a unit test
touches `Debug`.
