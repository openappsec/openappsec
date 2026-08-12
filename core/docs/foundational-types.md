# Foundational Types

These appear in almost every `core/` and `components/` file. Knowing them makes
the rest of the codebase readable.

## Maybe<T, Err> -- result type

`core/include/general/maybe_res.h`. The project's exception-free error channel:
a value either holds a `T` or an `Error<Err>`.

```cpp
Maybe<int, std::string> parsePort(const std::string &s);

auto res = parsePort(raw);
if (!res.ok()) {
    dbgWarning(D_FOO) << "bad port: " << res.getErr();
    return;
}
int port = res.unpack();   // or *res / res.unpackMove()
```

- Create a success by returning the `T` directly.
- Create a failure with `genError(...)` (`maybe_res.h:68`), which builds an
  `Error<Err>` deducible at the return site.
- `Error<void>` is specialized for "failed, no detail" -- `Maybe<T>` defaults
  to `Err = void`, so `genError(...)` with no payload is common.
- `Maybe` is cereal-serializable (the `Error` carries `serialize` +
  `getSerializationVersion`), so it can cross the wire / table sync.

`I_Environment::get<T>()` returns `Maybe<T, Context::Error>`; `I_MainLoop::
getCurrentRoutineId()` returns `Maybe<RoutineID>` -- the type is everywhere.

**Testing:** include `core/include/general/cptest/cptest_maybe.h` for GoogleTest
matchers that assert on a `Maybe` directly (is it `ok()`, does it hold an
expected value, does it carry an expected error) instead of unpacking by hand.

## Buffer -- segmented bytes

`core/include/general/buffer.h` (impl in `core/buffers/`). A `Buffer` is a
sequence of segments that can be **owned** (heap copy), **static** (points at a
string literal / long-lived data), or **volatile** (borrowed, must outlive the
buffer). This lets the data path avoid copies: a parser can wrap an incoming
chunk as a volatile segment and slice it without allocating. Concatenation,
sub-ranges, and comparison are provided. Prefer `Buffer` over `std::string`
when handling request/response payloads on the hot path.

## Table<Key> and opaque state

`core/include/general/table.h` (interface `i_table.h`,
`resources/table_opaque.h`). A `Table<Key>` is a keyed in-memory store with
per-entry **TTL expiration**, used as a service component
(`NodeComponentsWithTable<Key, ...>` injects one). The value stored under a key
is *opaque*: components attach their own state objects by type.

```cpp
auto *table = Singleton::Consume<I_Table>::by<MyComp>();
if (!table->hasState<MyState>()) table->createState<MyState>(/*ctor args*/);
MyState &st = table->getState<MyState>();   // this key's MyState
table->setExpiration(std::chrono::minutes(10));
```

`I_TableSpecific<Key>` adds key-level ops: `createEntry(key, expire)`,
`setActiveKey(key)`, `expireEntries()`, `count()`, plus cereal `saveEntry` /
`loadEntry` for syncing state between instances (`SyncMode::DUPLICATE_ENTRY` vs
`TRANSFER_ENTRY`). The HTTP handler keys this by session id so each connection
carries its own `Waf2Transaction` and friends.

Memory note: this branch favors memory-lean structures; see
[waap-memory-discipline] guidance and avoid STL hash containers in WAAP
learning code -- prefer sorted vectors / run-length collapse.

**Testing:** use `core/include/services_sdk/interfaces/mock/mock_table.h`
(`class MockTable`) to fake table access in unit tests -- it self-registers as
the `I_Table` provider.

## debug.h -- logging and alerts

`core/include/general/debug.h`. Five severity macros, gated by a `D_*` flag
(declared in `resources/debug_flags.h`) so categories can be toggled at
runtime:

```cpp
dbgTrace(D_WAAP)   << "entered scoring";   // most verbose
dbgDebug(D_WAAP)   << "score=" << score;
dbgInfo(D_WAAP)    << "decision made";
dbgWarning(D_WAAP) << "unexpected header: " << h;
dbgError(D_WAAP)   << "parse failed";      // least verbose
```

Other macros: `dbgFlow(...)` (scope enter/exit tracing), `dbgAssert(cond) <<
msg` (hard assert with message; `dbgAssertOpt` is the recoverable variant).

`AlertInfo` (`debug.h:41`) attaches a team (`AlertTeam::{CORE, WAAP, SDWAN,
IOT}`), a functionality string, and a description to an alert so it can be
deduplicated by id/family and routed to the owning team.

### Style reminders for log lines

Per the repo codestyle (vera++ T021): break long `dbgX(...) << ...` chains onto
new lines at an 8-space continuation indent -- do **not** align the `<<` to a
token on the previous line, and keep lines <= 119 chars. See
[CLAUDE.md](../../CLAUDE.md) for the full codestyle rules.

## Small utilities worth knowing

| Type | Header | Use |
|------|--------|-----|
| `scope_exit` | `general/scope_exit.h` | RAII: run a lambda on scope exit. |
| `Flags<Enum>` | `utilities/flags.h` | Type-safe bitset over an enum. |
| `EnumArray<Enum,T>` | `utilities/enum_array.h` | Array indexed by enum values. |
| `Cache<...>` | `utilities/cache.h` | TTL/size-bounded cache. |
| `toString(...)` | `general/tostring.h` | Uniform stringification (used by `Maybe`/debug). |
| `hash_combine` | `general/hash_combine.h` | Combine hashes for composite keys. |
