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

#include "coroutine.h"

using namespace std;

static void defaultPull(boost::coroutines2::detail::push_coroutine<void> &) {}

RoutineWrapper::RoutineWrapper(
    I_MainLoop::RoutineType _pri,
    I_MainLoop::Routine func,
    bool _is_primary,
    const string &_routine_name)
        :
    pri(_pri),
    pull(defaultPull), // will be replace by `invoke` on the first invokation
    routine( [func] (pull_type &pull) { invoke(pull, func); } ),
    is_primary(_is_primary),
    routine_name(_routine_name)
{
}

RoutineWrapper::~RoutineWrapper()
{
    pull = pull_type(defaultPull);
}

bool
RoutineWrapper::isActive() const
{
    return static_cast<bool>(routine);
}

bool
RoutineWrapper::shouldRun(const I_MainLoop::RoutineType &limit) const
{
    return !is_halt && pri<=limit;
}

void
RoutineWrapper::run()
{
    active = this; // Will be used by `invoke` to set the `pull` on the first invokation
    routine();
}

void
RoutineWrapper::yield()
{
    pull();
}

void
RoutineWrapper::halt()
{
    is_halt = true;
}

void
RoutineWrapper::resume()
{
    is_halt = false;
}

void
RoutineWrapper::invoke(pull_type &pull, I_MainLoop::Routine func)
{
    dbgAssert(active != nullptr) << "Trying to invoke without an active routine";
    active->pull = move(pull); // First invokation (other invokaction will start inside `func`), set the `pull` object
    func();
}

RoutineWrapper *RoutineWrapper::active = nullptr;
