# core/ Infrastructure Documentation

`core/` is the shared C++11 library underpinning every open-appsec Infinity Next
nano-service and attachment in this repo. It provides the dependency-injection
model, the event pipeline, the cooperative scheduler, and the foundational
services (messaging, config, logging, state tables, time, encryption, IPC) that
the security components in `components/` build on top of.

These docs are **task-oriented**: each one tells you *when* you'd reach for a
piece of `core/`, then shows the API to do it. Start from the decision table
below — find your situation, use the component it points to, read the linked doc
for the recipe.

## "I need to..." -> which core component to use

| When you need to... | Use | Doc |
|---------------------|-----|-----|
| Run periodic/deferred/background work, timers, async loops, or wake on an fd | `I_MainLoop` (`addRecurringRoutine` / `addOneTimeRoutine` / `addFileRoutine`) | [mainloop-and-scheduling](mainloop-and-scheduling.md) |
| Find and call another service's implementation | `Singleton::Consume<I_X>::by<Self>()` | [singletons-and-components](singletons-and-components.md) |
| Add a new long-lived service to a nano-service | `Component` + list it in `NodeComponents<...>` | [singletons-and-components](singletons-and-components.md) |
| React to something that happened elsewhere, decoupled from the producer | `Listener<Event>` + `event.notify()` | [event-system](event-system.md) |
| Ask "whoever can, answer this" and collect every reply | `Event<T, Reply>` + `event.query()` | [event-system](event-system.md) |
| Return success-or-error without throwing | `Maybe<T, Err>` + `genError(...)` | [foundational-types](foundational-types.md) |
| Hold/parse HTTP payload bytes without copying | `Buffer` (OWNED / STATIC / VOLATILE segments) | [foundational-types](foundational-types.md) |
| Keep per-connection / per-session state that auto-expires | `Table<Key>` / `I_Table` opaque state + TTL | [foundational-types](foundational-types.md) |
| Pass request-scoped data deep without threading it through every call | `I_Environment` context stack (`get<T>` / `registerValue<T>`) | [interfaces-and-resources](interfaces-and-resources.md) |
| Read configuration / policy / settings (and react to reloads) | `getConfiguration*` / `getSetting*` / `getProfileAgentSetting*` | [configuration](configuration.md) |
| Call the management plane (FOG) over HTTP | `I_Messaging` (sync/async) | [interfaces-and-resources](interfaces-and-resources.md) |
| Expose an inbound REST endpoint into the service | `I_RestApi` | [interfaces-and-resources](interfaces-and-resources.md) |
| Emit a security log / report | `I_Logging` + `Report` / `LogGen` | [interfaces-and-resources](interfaces-and-resources.md) |
| Emit a telemetry metric (counter/avg/gauge) | `GenericMetric` | [interfaces-and-resources](interfaces-and-resources.md) |
| Log a debug line or raise a routed alert | `dbgInfo/dbgWarning/...` macros + `AlertInfo` | [foundational-types](foundational-types.md) |
| Encrypt / obfuscate sensitive data | `I_Encryptor` (AES-256 / XOR / Base64, streaming) | [core-utilities](core-utilities.md) |
| Read/write files, trim/normalize strings, run a regex | `NGEN::Filesystem/Strings/Regex` | [core-utilities](core-utilities.md) |
| Key per-connection state by 5-tuple / compare-print IPs | `IPAddr` / `ConnKey` (`connkey.h`) | [core-utilities](core-utilities.md) |
| Compress/decompress an HTTP body (gzip/zlib/brotli) | `compression_utils.h` (streaming C ABI) | [core-utilities](core-utilities.md) |
| Get current time, or control time in tests | `I_TimeGet` / `I_TimeSet` | [interfaces-and-resources](interfaces-and-resources.md) |
| Query threat intelligence | `I_Intelligence` (v2) | [interfaces-and-resources](interfaces-and-resources.md) |
| Scope work to a tenant/profile | `I_Environment::setActiveTenantAndProfile` / `I_TenantManager` | [interfaces-and-resources](interfaces-and-resources.md) |
| Run a shell command, use a socket, or ioctl | `I_ShellCmd` / `I_SocketIS` / `I_Ioctl` | [interfaces-and-resources](interfaces-and-resources.md) |
| Exchange data with the nginx/kernel attachment over shared memory | `shmem_ipc.h` / `shmpktqueue.h` (C ABI) | [ipc](ipc.md) |
| Write a unit test (Maybe matchers, fixtures, hex/packet helpers) | `cptest.h` | [test-harness](test-harness.md) |
| Unit-test a component without real services | GoogleMock doubles in `interfaces/mock/` (`mock_*.h`, self-registering) | [test-harness](test-harness.md) + [interfaces-and-resources -> Testing with mocks](interfaces-and-resources.md#testing-with-mocks) |

If your need isn't here, scan [overview.md](overview.md) — it lists every
`core/` subsystem and what it's for.

## Reference docs (read end-to-end when learning the area)

| Doc | What it covers |
|-----|----------------|
| [overview.md](overview.md) | Directory map of `core/`, the `include/` tree, and the responsibility of every subsystem. The "what exists" map. |
| [singletons-and-components.md](singletons-and-components.md) | How services find each other (`Provide`/`Consume`) and how a nano-service is assembled and brought up. |
| [event-system.md](event-system.md) | The decoupled `Event`/`Listener` pipeline and the HTTP transaction flow. |
| [mainloop-and-scheduling.md](mainloop-and-scheduling.md) | The cooperative scheduler and the `yield()` contract every routine must honor. |
| [configuration.md](configuration.md) | The Configuration component end-to-end: Configuration vs Resource vs Setting, register/load/read lifecycle, context scoping, reload callbacks, testing. |
| [interfaces-and-resources.md](interfaces-and-resources.md) | The `I_*` service catalog (with "reach for it when" notes) and the `resources/` capabilities. |
| [foundational-types.md](foundational-types.md) | The value types in nearly every file: `Maybe`, `Buffer`, `Table`, `debug.h`. |
| [core-utilities.md](core-utilities.md) | `NGEN::` filesystem/strings/regex helpers, `connkey` (IPAddr/ConnKey), `I_Encryptor`, and the compression C ABI. |
| [ipc.md](ipc.md) | The shared-memory IPC transport between attachments and nano-services (`shmem_ipc`, `shmpktqueue`). |
| [test-harness.md](test-harness.md) | `cptest` -- Maybe matchers, `MockProvider` mock registration, fixtures, hex/packet helpers. |

## Mental model in one paragraph

A nano-service `main()` instantiates a `NodeComponents<...>` (or
`NodeComponentsWithTable<Key, ...>`) listing the `Component`s it needs. The core
services (Environment, Debug, Config, MainLoop, Messaging, Logging, Time, ...)
are always prepended. On `run()`, every component is `preload()`-ed, config is
loaded, every component is `init()`-ed, then `I_MainLoop::run()` takes over.
Components find each other through the `Singleton` registry, not direct
references. Work flows as `Event`s that `Listener`s subscribe to; periodic or
long-running work is scheduled as `I_MainLoop` routines that cooperatively
`yield()`.

## Key entry-point files

| File | Role |
|------|------|
| `core/include/general/singleton.h` | DI registry (`Provide` / `Consume`). |
| `core/include/services_sdk/resources/component.h` | `Component` base (lifecycle hooks). |
| `core/include/services_sdk/resources/components_list.h` | `NodeComponents` / `NodeComponentsWithTable` service assembly. |
| `core/include/services_sdk/resources/event.h` | `Event<T, Reply>` template. |
| `core/include/services_sdk/resources/listener.h` | `Listener<T>` template. |
| `core/include/services_sdk/interfaces/i_mainloop.h` | Scheduler contract. |
| `core/include/general/maybe_res.h` | `Maybe<T, Err>` result type. |
| `core/include/general/debug.h` | Logging macros + `AlertInfo`. |
