# MainLoop and Scheduling

`I_MainLoop` (`core/include/services_sdk/interfaces/i_mainloop.h`) is the
cooperative scheduler at the heart of every nano-service. There is a single
thread running the loop; "routines" are cooperatively scheduled coroutine-like
units of work. A routine runs until it `yield()`s -- it is never preempted --
so routines must yield regularly and must not block the thread.

Provided by the `MainloopComponent` (`core/include/general/mainloop.h`); consume
it with `Singleton::Consume<I_MainLoop>::by<Self>()`.

## Routine types

```cpp
enum class RoutineType { RealTime, Timer, System, Offline };
```

- **RealTime** -- latency-sensitive, runs as often as the scheduler allows.
- **Timer** -- periodic work driven by an interval.
- **System** -- auxiliary/background system work.
- **Offline** -- work not on the hot path (used heavily in unit tests to drive a
  code path deterministically without a live socket; see the project's mock
  setup conventions).

## Registering routines

All registration calls return a `RoutineID` and take a `routine_name` (shows up
in logs) and an `is_primary` flag. The loop keeps running only while at least
one **primary** routine is alive -- primary routines are the service's reason to
exist; secondary ones (REST, upgrade, telemetry) shouldn't keep it alive on
their own.

```cpp
// run once, soon:
RoutineID addOneTimeRoutine(RoutineType, Routine func, const string &name, bool is_primary = false);

// run every `time`:
RoutineID addRecurringRoutine(RoutineType, microseconds time, Routine func,
                              const string &name, bool is_primary = false);

// like recurring, but phase-aligned to `offset` so many routines don't bunch up:
RoutineID addBalancedIntervalRoutine(RoutineType, microseconds interval, Routine func,
                                     const string &name, microseconds offset = 0us,
                                     bool is_primary = false);

// wake when fd is readable (event-driven I/O):
RoutineID addFileRoutine(RoutineType, int fd, Routine func, const string &name,
                         bool is_primary = false);
```

`Routine` is just `std::function<void(void)>`.

## Yielding (the cooperative contract)

```cpp
void yield(bool force = false);        // give the scheduler a turn
void yield(std::chrono::microseconds); // sleep this routine for a duration
void yield(int) = delete;              // blocks ambiguous yield(0)
```

- `yield()` -- "I've done a chunk; run others, then maybe call me again." If the
  routine still had time budget left, the scheduler may resume it immediately.
- `yield(true)` -- "I have nothing to do right now; don't call me straight back."
- `yield(microseconds)` -- timed sleep for this routine only (does not block the
  thread; other routines run).

Inside any loop in a routine, yield. A tight loop that never yields starves
every other routine in the process.

## Lifecycle / control

```cpp
bool                  doesRoutineExist(RoutineID);
Maybe<RoutineID>      getCurrentRoutineId() const;   // who am I
void                  updateCurrentStress(bool is_busy);

void run();                 // start the loop (called by NodeComponents::run)
void halt(); void halt(RoutineID);   // pause
void resume(RoutineID);
void stop(); void stop(RoutineID); void stopAll();   // terminate
```

`run()` is invoked for you by `NodeComponents::run()` after all components are
`init()`-ed -- you rarely call it directly. `getCurrentRoutineId()` returns a
`Maybe` because there may be no routine context (e.g. before the loop starts).

## Typical usage in a component

```cpp
void MyComp::init() {
    auto *mainloop = Singleton::Consume<I_MainLoop>::by<MyComp>();
    mainloop->addRecurringRoutine(
        I_MainLoop::RoutineType::Timer,
        std::chrono::seconds(30),
        [this]() { flushPendingState(); },
        "MyComp periodic flush");
}
```

## Testing note

For unit tests that need a mainloop-driven path, the project convention is to
use an **Offline** routine on a mocked mainloop and invoke the sub-object
directly, rather than adding test-only public wrappers to production code.

Use the ready-made mock `core/include/services_sdk/interfaces/mock/mock_mainloop.h`
(`class MockMainLoop`). It self-registers as the `I_MainLoop` provider, so the
code-under-test's `Consume<I_MainLoop>` lookups resolve to it. The standard
recipe is to capture the scheduled lambda and run it yourself:

```cpp
#include "mock_mainloop.h"
StrictMock<MockMainLoop> mock_mainloop;
I_MainLoop::Routine flush;
EXPECT_CALL(mock_mainloop, addRecurringRoutine(_, _, _, _, _))
    .WillOnce(DoAll(SaveArg<2>(&flush), Return(1)));
comp.init();        // registers its routine -> captured into `flush`
flush();            // drive the periodic work deterministically, no real loop
```

Pair with `mock_time_get.h` (`MockTimeGet`) to control the clock. See
[interfaces-and-resources.md -> Testing with mocks](interfaces-and-resources.md#testing-with-mocks)
for the full mock catalog and the cptest helpers.
