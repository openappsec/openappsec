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

#ifndef __PACKAGE_HANDLER_H__
#define __PACKAGE_HANDLER_H__

#include "i_package_handler.h"
#include "i_orchestration_tools.h"
#include "i_shell_cmd.h"
#include "i_environment.h"
#include "component.h"

class PackageHandler
        :
    public Component,
    Singleton::Provide<I_PackageHandler>,
    Singleton::Consume<I_ShellCmd>,
    Singleton::Consume<I_OrchestrationTools>,
    Singleton::Consume<I_Environment>
{
public:
    PackageHandler();
    ~PackageHandler();

    void preload() override;

    void init() override;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __PACKAGE_HANDLER_H__
