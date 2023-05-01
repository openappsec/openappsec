// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __I_MAINLOOP_H__
#define __I_MAINLOOP_H__

#include <functional>
#include <string>
#include <chrono>

#include "maybe_res.h"

class I_MainLoop
{
public:
    using Routine = std::function<void(void)>;
    using RoutineID = uint;
    enum class RoutineType { RealTime, Timer, System, Offline };

    // There are two types of routines:
    // 1. The primary routines that perform the main functionality of the product.
    // 2. The secondary routines that perform auxiliary functionality (upgrade, REST, etc.)
    // The mainloop needs to run only as long as there are any primary routines in effect.
    virtual RoutineID
    addOneTimeRoutine(
        RoutineType priority,
        Routine func,
        const std::string &routine_name,
        bool is_primary = false
    ) = 0;

    virtual RoutineID
    addRecurringRoutine(
        RoutineType priority,
        std::chrono::microseconds time,
        Routine func,
        const std::string &routine_name,
        bool is_primary = false
    ) = 0;

    virtual RoutineID
    addFileRoutine(
        RoutineType priority,
        int fd,
        Routine func,
        const std::string &routine_name,
        bool is_primary = false
    ) = 0;

    virtual bool doesRoutineExist(RoutineID id) = 0;

    virtual Maybe<I_MainLoop::RoutineID> getCurrentRoutineId() const = 0;

    virtual void updateCurrentStress(bool is_busy) = 0;

    virtual void run() = 0;

    // When a routine yields the scheduler may choose to let it continue to run (in the case the routine didn't use
    // all of the time that was allocated to it). However, if the routine doesn't have more work to do at the moment
    // and wants not to be called directly again by the scheduler, it can force the scheduler not to call it back
    // immediately by setting `force` to true.
    virtual void yield(bool force = false) = 0;
    virtual void yield(std::chrono::microseconds time) = 0;
    void yield(int) = delete; // This prevents the syntax `yield(0)` which is otherwise ambiguous

    virtual void stopAll() = 0;
    virtual void stop() = 0;
    virtual void stop(RoutineID id) = 0;

    virtual void halt() = 0;
    virtual void halt(RoutineID id) = 0;

    virtual void resume(RoutineID id) = 0;

protected:
    virtual ~I_MainLoop() {}
};

#endif // __I_MAINLOOP_H__
