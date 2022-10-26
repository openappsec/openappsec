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

#ifndef __TRAP_HANDLER_H__
#define __TRAP_HANDLER_H__

#include <memory>

#include "singleton.h"
#include "i_trap_handler.h"
#include "i_ioctl.h"
#include "i_mainloop.h"
#include "component.h"

class TrapHandler
        :
    public Component,
    Singleton::Provide<I_TrapHandler>,
    Singleton::Consume<I_Ioctl>,
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_TrapHandler>
{
public:
    TrapHandler();
    ~TrapHandler();

    void init();
    void fini();

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __TRAP_HANDLER_H__
