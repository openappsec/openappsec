# Singletons and Components

The core wiring model has two halves:

1. **`Singleton`** -- a type-indexed registry that lets one object expose an
   interface (`I_Face`) and lets others look it up, without either side holding
   a direct pointer to the other.
2. **`Component` + `NodeComponents`** -- the lifecycle and assembly layer that
   instantiates the objects, brings them up in the right order, and runs the
   main loop.

## Singleton: Provide / Consume

Defined in `core/include/general/singleton.h` and
`core/include/general/impl/singleton.h`. The registry itself is just:

```cpp
static std::map<std::type_index, std::set<void *>>            singles;        // interfaces
static std::map<std::type_index, std::unique_ptr<OwnedSingleton>> owned_singles; // owned objects
```

### Providing an interface

A class advertises that it implements `I_Face` by inheriting
`Singleton::Provide<I_Face>::From<Self>`. Registration/unregistration happen
automatically in that base's constructor/destructor
(`impl/singleton.h:33-34`):

```cpp
class MyManager
    : public Component,
      public Singleton::Provide<I_MyService>::From<MyManager>
{
    // ... implements I_MyService ...
};
```

There is also `Singleton::Provide<I_Face>::Self` for the self-registering
variant (`impl/singleton.h:44-50`). You do **not** call `registerSingleton`
yourself -- the `Provide` base does it.

### Consuming an interface

A class declares a dependency by inheriting `Singleton::Consume<I_Face>`, then
fetches the implementation on demand (`impl/singleton.h:52-98`):

```cpp
class MyUser
    : public Component,
      Singleton::Consume<I_MainLoop>,
      Singleton::Consume<I_Messaging>
{
    void doWork() {
        auto *mainloop = Singleton::Consume<I_MainLoop>::by<MyUser>();
        auto *msg      = Singleton::Consume<I_Messaging>::by<MyUser>();
        // ...
    }
};
```

The lookup variants (all `static`, all return `I_Face *`):

| Call | Meaning |
|------|---------|
| `Consume<I>::by<Self>()` | "I (Self) consume I." The common case. |
| `Consume<I>::from<Provider>()` | Assert a specific provider type exists. |
| `Consume<I>::to<Comp>()` | Comp either Provides or Consumes I. Used by `getInterface<Comp,I>()`. |

The `static_assert`s ensure a class can only fetch an interface it has
formally declared a relationship to -- this is the compile-time guard that
keeps dependencies explicit.

### Owned singletons

For objects the registry should *own* (construct/destroy), use
`Singleton::newOwned<T>(args...)`, `getOwned<T>()`, `existsOwned<T>()`,
`setOwned<T>(ptr)`, `deleteOwned<T>()` (`impl/singleton.h:107-146`). These store
a `unique_ptr` rather than a borrowed pointer.

## Component lifecycle

`core/include/services_sdk/resources/component.h` is tiny -- a name plus three
virtual hooks:

```cpp
class Component {
public:
    Component(const std::string &component_name);
    virtual void preload() {}  // earliest: declare config, allocate, register routines
    virtual void init()    {}  // after all preloads + config load: wire up, start work
    virtual void fini()    {}  // teardown (called in reverse order)
    const std::string & getName() const;
};
```

Most real components inherit `Component` **and** one or more
`Singleton::Provide<...>` / `Singleton::Consume<...>` bases. A typical header
(pattern seen across `components/`):

```cpp
class AntibotComponent
    : public Component,
      Singleton::Consume<I_MainLoop>,
      Singleton::Consume<I_Table>,
      Singleton::Consume<I_TimeGet>,
      Singleton::Consume<I_Environment>
{
public:
    AntibotComponent();
    void preload() override;
    void init() override;
    void fini() override;
private:
    class Impl;                 // PIMPL: the Provide<...> implementation
    std::unique_ptr<Impl> pimpl;
};
```

## Assembling a nano-service

`core/include/services_sdk/resources/components_list.h`:

```cpp
template <typename ... Components>
class NodeComponents : public Infra::ComponentListCore<Components...> {
public:
    int run(const std::string &nano_service_name, int argc, char **argv);
};

template <typename TableKey, typename ... Components>
class NodeComponentsWithTable
    : public NodeComponents<Table<TableKey>, Components...> {};
```

`ComponentListCore` prepends the always-present core services (Environment,
Debug, Version, Buffers, MetricScraper, Messaging, MainloopComponent,
ConfigComponent, InstanceAwareness, IntelligenceV2, AgentDetails, LoggingComp,
TimeProxy, SignalHandler, RestServer, Encryptor, SocketIS, CPU, MemoryCalculator,
TenantManager, GenericRulebase, EnvDetails, ...) ahead of the components you
list, so you only enumerate the domain-specific ones.

`NodeComponentsWithTable<Key, ...>` additionally injects a `Table<Key>` so the
service has per-key (e.g. per-connection / per-session) opaque state. The HTTP
transaction handler uses this with a session-id key.

### What `run()` does (order matters)

1. `handleArgs(argc, argv)` -- parse command line.
2. `preloadComponents()` -- every component's `preload()`, in declaration order.
3. `loadConfiguration()` -- parse settings/policy.
4. `init()` -- every component's `init()`, in declaration order.
5. `I_MainLoop::run()` -- hand control to the scheduler (see
   [mainloop-and-scheduling.md](mainloop-and-scheduling.md)).
6. On shutdown, `fini()` -- in **reverse** declaration order.

Because core services are prepended, they `preload`/`init` before your
components and `fini` after them -- so `I_MainLoop`, `I_Config`, `I_Logging`,
etc. are always available inside your `init()` and routines.

### A minimal main()

```cpp
int main(int argc, char **argv)
{
    NodeComponentsWithTable<SessionID,
        NginxAttachment,
        HttpManager,
        WaapComponent,
        /* ... */ > comps;

    comps.registerGlobalValue<uint>("Nano service API Port Range start", 12000);
    return comps.run("HTTP Transaction Handler", argc, argv);
}
```

See `nodes/<service>/main.cc` for the real, fuller lists.

## Testing: mocks plug into the same registry

The `Provide`/`Consume` indirection is what makes the code testable. For every
core interface there is a GoogleMock double under
`core/include/services_sdk/interfaces/mock/` that derives from
`Singleton::Provide<I_X>::From<MockProvider<I_X>>` -- i.e. it registers through
the *exact same* registry a real provider uses. Constructing the mock in a test
fixture transparently replaces the real service for any
`Singleton::Consume<I_X>::by<...>()` in the code-under-test; you never touch
`registerSingleton` yourself.

```cpp
#include "mock_messaging.h"
StrictMock<MockMessaging> mock_messaging;   // now I_Messaging resolves to this
MyComp comp;                                // comp's Consume<I_Messaging> hits the mock
```

See [interfaces-and-resources.md -> Testing with mocks](interfaces-and-resources.md#testing-with-mocks)
for the full catalog (one mock per interface) and the cptest helpers.
