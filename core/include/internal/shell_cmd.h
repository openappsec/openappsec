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

#ifndef __SHELL_CMD_H__
#define __SHELL_CMD_H__

#include "i_shell_cmd.h"
#include "i_mainloop.h"
#include "i_time_get.h"
#include "singleton.h"
#include "component.h"

class ShellCmd
        :
    public Component,
    Singleton::Provide<I_ShellCmd>,
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_TimeGet>
{
public:
    ShellCmd();
    ~ShellCmd();

    void preload() override;
    void init() override;
    void fini() override;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __SHELL_CMD_H__
