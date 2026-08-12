# Interfaces and Resources

`core/include/services_sdk/` is the public SDK a component programs against:

- **`interfaces/`** -- the `I_*` service contracts. A component `Consume`s these
  to use a service (and the matching core component `Provide`s the
  implementation).
- **`resources/`** -- concrete capability classes a component uses directly
  (events, the component base, contexts, config accessors, reports, metrics,
  table opaque storage).
- **`utilities/`** -- small standalone helpers.

For prose on the most-used interfaces, see the root
[CORE_INTERFACES.md](../../CORE_INTERFACES.md); this doc is the core-local index.

## interfaces/ -- the I_* contracts

Consume any of these with `Singleton::Consume<I_X>::by<Self>()`. The "reach for
it when" column is the trigger; the **Mock** column is the test double to use
(see [Testing with mocks](#testing-with-mocks) below).

| Interface | Reach for it when you need to... | Mock |
|-----------|----------------------------------|------|
| `i_mainloop.h` | schedule periodic/deferred/async/file work (see [mainloop](mainloop-and-scheduling.md)) | `mock_mainloop.h` |
| `i_environment.h` | read/set request-scoped context, scope to tenant+profile, get trace/span ids | `mock_environment.h` |
| `i_messaging.h` | send HTTP to the management plane (FOG), sync or async, or download a file | `mock_messaging.h` |
| `i_rest_api.h` | expose an inbound REST endpoint into the service | `mock_rest_api.h` |
| `i_table.h` / `i_table_iter.h` | keep/iterate per-key opaque state with TTL (see [foundational-types](foundational-types.md)) | `mock_table.h` |
| `i_logging.h` | emit a structured security log / `Report` | `mock_logging.h` |
| `i_time_get.h` / `i_time_set.h` | read current time; set/advance time deterministically in tests | `mock_time_get.h` / `mock_time_set.h` |
| `i_encryptor.h` | encrypt/obfuscate sensitive data (AES-256 / XOR / Base64) | `mock_encryptor.h` |
| `i_agent_details.h` / `i_agent_details_reporter.h` | read agent identity/version; report agent status | `mock_agent_details.h` / `mock_agent_details_reporter.h` |
| `i_env_details.h` | read platform/orchestration metadata | `mock_env_details.h` |
| `i_instance_awareness.h` | learn this worker's id among siblings | `mock_instance_awareness.h` |
| `i_intelligence_is_v2.h` | query/register threat intelligence (current API) | `mock_intelligence.h` |
| `i_tenant_manager.h` | register/look up tenants and profiles | `mock_tenant_manager.h` |
| `i_cpu.h` | read CPU self-usage | `mock_cpu.h` |
| `i_shell_cmd.h` | run a shell command | `mock_shell_cmd.h` |
| `i_socket_is.h` | use a socket abstraction | `mock_socket_is.h` |
| `i_ioctl.h` | receive ioctl events (e.g. policy-update notifications) | `mock_ioctl.h` |
| `i_signal_handler.h` / `i_trap_handler.h` | handle signals / traps | `mock_trap_handler.h` |
| `i_health_check_manager.h` | report liveness/health | `mock_health_check_manager.h` |
| `i_failopen.h` | control fail-open behavior | -- |
| `i_http_client.h` | make a generic (libcurl) HTTP call | `mock_http_client.h` |
| `i_proxy_configuration.h` | read proxy settings | `mock_proxy_configuration.h` |

Subfolders: `interfaces/intelligence_is_v2/`, `interfaces/messaging/` (request
types, connection options), `interfaces/mock/` (the GoogleMock doubles above).

## Testing with mocks

Every core service ships a ready-made GoogleMock double in
`core/include/services_sdk/interfaces/mock/` (naming convention:
`I_Foo` -> `mock_foo.h` -> `class MockFoo`). They are the standard way to unit-test
a component without standing up real services.

Each mock self-registers as the provider for its interface -- it derives from
`Singleton::Provide<I_X>::From<MockProvider<I_X>>` -- so simply constructing the
mock in your test fixture makes every `Singleton::Consume<I_X>::by<...>()` in the
code-under-test resolve to it. No manual registration needed.

```cpp
#include "mock_mainloop.h"
#include "mock_time_get.h"
#include "cptest.h"

class MyCompTest : public Test {
    StrictMock<MockMainLoop> mock_mainloop;   // registers as I_MainLoop provider
    NiceMock<MockTimeGet>    mock_time;       // registers as I_TimeGet provider
    MyComp comp;                              // its Consume<...> lookups hit the mocks
};

TEST_F(MyCompTest, schedulesFlush) {
    EXPECT_CALL(mock_mainloop,
        addRecurringRoutine(_, _, _, _, _)).WillOnce(Return(1));
    comp.init();
}
```

Available mocks (one per interface, plus a few infra doubles):
`mock_mainloop`, `mock_environment`, `mock_messaging`, `mock_rest_api`,
`mock_table`, `mock_logging`, `mock_time_get`, `mock_time_set`,
`mock_encryptor`, `mock_agent_details`, `mock_agent_details_reporter`,
`mock_env_details`, `mock_instance_awareness`, `mock_intelligence`,
`mock_tenant_manager`, `mock_cpu`, `mock_shell_cmd`, `mock_socket_is`,
`mock_ioctl`, `mock_trap_handler`, `mock_health_check_manager`,
`mock_http_client`, `mock_proxy_configuration`, `mock_shmem_ipc`,
`hiredis_mock`.

Capturing-and-driving routines: the common pattern with `MockMainLoop` is to
`SaveArg<>` the `Routine` lambda passed to `addRecurringRoutine` / `addOneTimeRoutine`,
then invoke it from the test to exercise the scheduled work deterministically --
no real loop, no real time. Pair with `MockTimeGet` to control the clock. See
the project's mainloop testing note in
[mainloop-and-scheduling.md](mainloop-and-scheduling.md#testing-note).

Test-harness helpers live in `core/include/general/cptest/`:
`cptest_maybe.h` (matchers for `Maybe<T,Err>` -- assert `ok()`/value/error),
`cptest_singleton.h` (singleton setup/teardown helpers), `cptest_file.h`,
`cptest_basic.h`, `cptest_tcppacket.h`.

## resources/ -- capabilities used directly

| Header(s) | Purpose |
|-----------|---------|
| `event.h`, `listener.h`, `event_is/` | Event pipeline. See [event-system.md](event-system.md). |
| `component.h`, `component_is/`, `components_list.h` | Component base + service assembly. See [singletons-and-components.md](singletons-and-components.md). |
| `context.h`, `environment/`, `environment_evaluator.h` | `Context` objects pushed/popped on the environment stack; expression evaluation against context. |
| `config.h`, `config/` | Typed config accessors (`getConfiguration<T>(...)`, profile/asset-scoped settings). |
| `report/`, `report_messaging.h`, `log_generator.h`, `log_utils.h` | Build security `Report`s and ship them via logging/messaging. |
| `metric/`, `generic_metric.h`, `bulk_generic_metric.h` | Declare and emit telemetry metrics. |
| `table/`, `table_opaque.h`, `table_iter.h` | The opaque per-key state stored in a `Table<Key>`. |
| `cpu/`, `cpu.h`, `memory_consumption.h` | Resource self-metrics. |
| `intelligence_*` , `read_attribute*.h` | Intelligence query/result models. |
| `health_check_status/`, `service_health_update_event.h` | Health reporting types. |
| `agent_details.h`, `env_details.h`, `version.h` | Identity/metadata value types. |
| `debug_flags.h` | The `D_*` debug-flag declarations used by `dbg*` macros. |
| `tag_and_enum_management.h`, `key_wrapper.h` | Tag/enum registries, key wrapping. |

## utilities/ -- standalone helpers

| Header | Purpose |
|--------|---------|
| `agent_core_utilities.h` | `NGEN::` filesystem/string/process helpers. |
| `cache.h`, `caching/` | TTL/LRU-style caches. |
| `flags.h` | Type-safe bit flags over an enum. |
| `enum_array.h`, `enum_range.h` | Enum-indexed array and range-for over enums. |
| `connkey.h` | Connection 5-tuple key. |
| `socket_is.h` | Socket helper. |
| `virtual_container.h`, `virtual_modifiers.h` | Type-erased container / modifier adapters. |
| `customized_cereal_map.h`, `customized_cereal_multimap.h` | cereal (de)serialization adapters for maps. |
| `fog_rest_error.h` | Standard FOG REST error shape. |
| `rest/` | REST request/response helper types. |

## The environment/context pattern

`I_Environment::get<T>(name)` walks the active context stack from newest to
oldest and returns the first match as a `Maybe<T, Context::Error>`. Producers
push a `Context`, `registerValue<T>(name, v)` into it, and the value is visible
to everything that runs while that context is active (request-local state,
tenant/profile overrides, tracing ids). This is how request-scoped data reaches
deep code without threading it through every signature.
