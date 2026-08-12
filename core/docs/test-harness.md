# Test Harness (cptest)

`core/cptest/` is the project's unit-test support layer on top of GoogleTest +
GoogleMock. `#include "cptest.h"` and you get gtest/gmock plus the
agent-specific helpers below. Test files follow the `*_ut.cc` convention and are
declared with `add_unit_test(...)` (see [overview.md](overview.md)).

Reach for it when: writing any unit test in this repo -- it's the standard
include, and it carries the `Maybe` matchers and the mock-registration glue you
need to test `Singleton`-based code.

## What `cptest.h` pulls in

`core/include/general/cptest.h` aggregates:
`cptest/cptest_basic.h`, `cptest/cptest_file.h`, `cptest/cptest_singleton.h`,
`cptest/cptest_maybe.h`, plus `buffer.h`, `scope_exit.h`, `tostring.h`. It also
provides hex helpers for packet tests:

```cpp
std::vector<u_char> cptestParseHex(const std::string &hex_text);     // tcpdump -xx -> bytes
std::string         cptestGenerateHex(const std::vector<u_char> &v, bool print_offsets);
std::ostream &      operator<<(std::ostream &, const Buffer &);      // Buffer is printable in EXPECT
```

## Maybe matchers (`cptest_maybe.h`)

Assert on a `Maybe<T, Err>` directly instead of unpacking by hand:

```cpp
Maybe<int> m = parse(...);
EXPECT_THAT(m, IsValue(3));        // ok() and value == 3
EXPECT_THAT(m, IsValue(_));        // ok() (any value)
EXPECT_THAT(m, IsError(_));        // !ok() (any error)
EXPECT_THAT(m, IsError("bad tag"));// !ok() and error matches
```

`IsValue(matcher)` checks `ok()` then runs `matcher` on `unpack()`;
`IsError(matcher)` checks `!ok()` then runs it on `getErr()`. Any gmock matcher
works inside them.

## Singleton / mock registration (`cptest_singleton.h`)

The single most important helper:

```cpp
template<typename I_Face>
class MockProvider : Singleton::Provide<I_Face> {};
```

This is the base every core/component mock uses --
`class MockMainLoop : public Singleton::Provide<I_MainLoop>::From<MockProvider<I_MainLoop>>`.
The upshot: **constructing a mock in your fixture registers it as the provider**
for its interface, so the code-under-test's `Consume<I_Face>::by<...>()` resolves
to your mock. No manual wiring. (Full catalog:
[interfaces-and-resources.md -> Testing with mocks](interfaces-and-resources.md#testing-with-mocks).)

## Basic helpers (`cptest_basic.h`)

```cpp
void cptestPrepareToDie();                              // call before EXPECT_DEATH
std::string cptestFnameInExeDir(const std::string &);   // path to a file next to the test binary
std::string cptestFnameInSrcDir(const std::string &);   // path to a file in the test's source dir

// gmock action: save *(arg<k>) (a pointee) into `output` -- for out-params behind a pointer
SaveVoidArgPointee<k, T>(output);
```

`cptestFnameInSrcDir` is how tests load fixture files committed next to the
`*_ut.cc`.

## File and packet helpers

- `cptest_file.h` -- temp-file / file-fixture helpers for tests that read/write
  the filesystem.
- `cptest_tcppacket.h` -- build/parse TCP packets for the networking components
  (pairs with the `cksum*`/`connkey` utilities).

## A representative fixture

```cpp
#include "cptest.h"
#include "mock_mainloop.h"
#include "mock_time_get.h"

using namespace testing;

class MyCompTest : public Test {
public:
    NiceMock<MockTimeGet>   mock_time;     // registers as I_TimeGet
    StrictMock<MockMainLoop> mock_ml;      // registers as I_MainLoop
    MyComp comp;                           // its Consume<...> lookups hit the mocks
};

TEST_F(MyCompTest, parsesConfig) {
    auto res = comp.parse("...");
    EXPECT_THAT(res, IsValue(_));
}
```

## Linker note

A standalone UT whose code-under-test calls into `Debug` (`dbgTrace`/`dbgWarning`)
must link `agent_core_utilities` and friends, not just the lib under test --
otherwise the Coverage build fails with `undefined reference to D_*_FLAG`. See
[CLAUDE.md](../../CLAUDE.md) for the exact dependency list.

## Key files

| File | Role |
|------|------|
| `core/include/general/cptest.h` | Umbrella include + hex helpers. |
| `core/include/general/cptest/cptest_maybe.h` | `IsValue` / `IsError` matchers. |
| `core/include/general/cptest/cptest_singleton.h` | `MockProvider<I_Face>` (mock registration). |
| `core/include/general/cptest/cptest_basic.h` | Death-test prep, fixture paths, `SaveVoidArgPointee`. |
| `core/include/general/cptest/cptest_file.h` | File fixtures. |
| `core/include/general/cptest/cptest_tcppacket.h` | TCP packet build/parse. |
| `core/cptest/` | Implementations (`cptest.cc`, `cptest_data_buf.cc`, `cptest_tcppacket.cc`). |
