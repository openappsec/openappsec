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

#ifndef __I_TRAP_HANDLER_H__
#define __I_TRAP_HANDLER_H__

#include <signal.h>

#include "maybe_res.h"
#include "common_is/trap_common.h"

class I_TrapHandler
{
public:
    using SignalHandler = std::function<Maybe<bool>(AgentTrapCmd)>;
    virtual Maybe<bool> registerTrap(AgentTrapCmd cmd, SignalHandler signal_handler) = 0;
    virtual void signalFunctionHandler(siginfo_t *info) = 0;

protected:
    virtual ~I_TrapHandler() {}
};

#endif // __I_TRAP_HANDLER_H__
