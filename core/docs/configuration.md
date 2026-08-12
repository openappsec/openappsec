# Configuration Component

The Configuration component (`ConfigComponent`, providing `Config::I_Config`)
is how every nano-service reads its policy and settings. You almost never touch
`I_Config` directly -- you use the free functions in
`core/include/services_sdk/resources/config.h`, which are the ergonomic wrapper
over the interface.

`#include "config.h"` to get all of them.

## The three buckets: Configuration vs Resource vs Setting

Config values live in three separately-registered namespaces. Picking the right
one matters because they load from different places and have different scoping.

| Bucket | What it is | Typical source | Accessor family |
|--------|------------|----------------|-----------------|
| **Configuration** | Per-asset / per-context **policy** the customer set (can be context-dependent) | the policy JSON pushed from FOG | `getConfiguration*` |
| **Resource** | Bundled/static data the agent ships with | resource files | `getResource*` |
| **Setting** | Service-level knobs (not per-asset) | settings JSON / command line | `getSetting*` |
| **Profile-agent setting** | A flat per-profile agent setting addressed by name | profile settings | `getProfileAgentSetting*` |

Rule of thumb: customer-facing policy that varies per asset/context ->
**Configuration**. A global on/off or tuning number for the whole service ->
**Setting**. A named profile knob -> **profile-agent setting**.

## Tags map to a JSON path

Every accessor and register call takes a variadic list of string **tags** that
address a nested path in the loaded JSON. `{"WAAP", "WebApplicationSecurity"}`
reads `config["WAAP"]["WebApplicationSecurity"]`.

## Lifecycle: register, load, read

1. **Register** what you expect, once, in your component's `preload()` (before
   config is loaded). This tells the loader the type and path to deserialize:

   ```cpp
   void WaapComponent::preload() {
       registerExpectedConfiguration<WaapConfigApplication>({"WAAP", "WebApplicationSecurity"});
       registerExpectedConfiguration<WaapConfigAPI>({"WAAP", "WebAPISecurity"});
       registerExpectedSetting<std::string>("agentType");
       registerExpectedConfigFile("waap", Config::ConfigFileType::Policy);
   }
   ```

   The type `T` must be cereal-deserializable (it has a `load`/`serialize`).

2. **Load** happens for you: the `ConfigComponent` loads/parses the policy and
   settings during startup (and on reload). You don't call `loadConfiguration`
   except in tests.

3. **Read** at runtime:

   ```cpp
   // Maybe<T> -- absent/!ok if the tag isn't present or no context matches:
   auto maybe_app = getConfiguration<WaapConfigApplication>("WAAP", "WebApplicationSecurity");
   if (maybe_app.ok()) { use(*maybe_app); }

   // ...or collapse the Maybe with a default:
   std::string redis_host = getConfigurationWithDefault<std::string>("127.0.0.1", "connection", "Redis IP");
   int         redis_port = getConfigurationWithDefault<int>(6379, "connection", "Redis Port");

   // settings:
   auto agent_type = getSetting<std::string>("agentType");                 // Maybe<string>
   bool only_defined = getSettingWithDefault<bool>(false, "allowOnlyDefinedApplications");

   // profile-agent settings (addressed by name, optionally by regex):
   uint timeout = getProfileAgentSettingWithDefault<uint>(60, "tuningDecisionExpirationTimeout");
   ```

Each `getX` has a `Maybe`-returning form and a `getXWithDefault(default, tags...)`
form. Prefer `WithDefault` on the hot path -- it avoids the `Maybe` unpack and
documents the fallback.

## Context-dependent configuration

Configuration (unlike Setting) can be **context-scoped**: the same tag can hold
different values depending on the active environment (asset, tenant, profile).
That's why `getConfiguration` resolves against the current `I_Environment`
context stack.

- `getConfiguration<T>(tags...)` returns the value that matches the **current**
  context (or the unconditioned value).
- `getConfigurationMultimatch<T>(tags...)` returns a `Config::ConfigRange<T>` of
  **all** matching values (when several context-conditioned entries apply) --
  iterate it when you must consider every match, not just the active one.

So: set the active tenant/profile on `I_Environment` first (or run inside the
request context), then read -- the config you get back is the one scoped to that
context.

## Errors

`getConfiguration*` returns `Maybe<T, Config::Errors>` with
`Config::Errors { MISSING_TAG, MISSING_CONTEXT, BAD_NODE }`
(`config/config_types.h:31`). `MISSING_TAG` = path not present;
`MISSING_CONTEXT` = present but no entry matches the active context;
`BAD_NODE` = present but failed to deserialize into `T`.

## Config flags, paths, and files

```cpp
// runtime flags (string-valued, e.g. paths / mode switches):
std::string v = getConfigurationFlagWithDefault("/etc/cp/conf", "filesystem_path");

// well-known paths:
const std::string &fs   = getFilesystemPathConfig();
const std::string &logs = getLogFilesPathConfig();

// resolve a policy/data file path for a tenant/profile:
std::string p = getPolicyConfigPath("waap", Config::ConfigFileType::Policy, tenant, profile);
```

`ConfigFileType { Policy, Data, RawData }` (`config_types.h:32`). Declare files
you read with `registerExpectedConfigFile(name, type)`.

## Reacting to reloads

Policy can be reloaded at runtime (`reloadConfiguration(version)`). If your
component caches anything derived from config, register callbacks so you can
rebuild it:

```cpp
auto h = registerConfigLoadCb([this]() { rebuildCaches(); });
// also: registerConfigPrepareCb (before swap), registerConfigAbortCb (load failed)
// unregister with unregisterConfigLoadCb(h) in fini()
```

## Writing config (tests / programmatic)

`setConfiguration<T>(value, tags...)`, `setResource`, `setSetting` push a value
in directly. These are mainly for unit tests (seed the config, then exercise the
code that reads it) rather than production.

## Testing

Use the GoogleMock double `core/include/services_sdk/interfaces/mock/mock_config.h`
(`class MockConfig`) when you need to fake `Config::I_Config` directly. More
often, though, you test config-reading code by **seeding real values**: bring up
a `ConfigComponent` (or its test fixture), `setConfiguration<T>(...)` /
`loadConfiguration(json_stream)`, then call the code under test -- the free
`getConfiguration*` functions resolve through the registered provider. This
exercises the real registration + path-resolution logic, which a bare mock
skips.

```cpp
std::stringstream policy(R"({"WAAP": {"WebApplicationSecurity": { ... }}})");
Singleton::Consume<Config::I_Config>::from<ConfigComponent>()->loadConfiguration(policy);
auto cfg = getConfiguration<WaapConfigApplication>("WAAP", "WebApplicationSecurity");
ASSERT_TRUE(cfg.ok());
```

See [interfaces-and-resources.md -> Testing with mocks](interfaces-and-resources.md#testing-with-mocks)
for the broader mock catalog.

## Key files

| File | Role |
|------|------|
| `core/include/services_sdk/resources/config.h` | The free-function API (`getConfiguration*`, `registerExpected*`, flags, paths, reload). |
| `core/include/services_sdk/resources/config/i_config.h` | `Config::I_Config` interface (provided by `ConfigComponent`). |
| `core/include/general/config_component.h` | `ConfigComponent` (provides `Config::I_Config`). |
| `core/include/services_sdk/resources/config/config_types.h` | `Config::Errors`, `Config::ConfigFileType`. |
| `core/include/services_sdk/resources/config/generic_config.h` | `SpecificConfig<T>` registration machinery. |
| `core/include/services_sdk/interfaces/mock/mock_config.h` | `MockConfig` test double. |
