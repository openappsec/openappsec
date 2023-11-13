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

#ifndef __LOCAL_POLICY_MGMT_GEN_H__
#define __LOCAL_POLICY_MGMT_GEN_H__

#include "config.h"
#include "component.h"
#include "i_mainloop.h"
#include "i_local_policy_mgmt_gen.h"
#include "i_env_details.h"
#include "i_shell_cmd.h"
#include "i_orchestration_tools.h"

class LocalPolicyMgmtGenerator
        :
    public Component,
    Singleton::Provide<I_LocalPolicyMgmtGen>,
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_EnvDetails>,
    Singleton::Consume<I_ShellCmd>,
    Singleton::Consume<I_Environment>,
    Singleton::Consume<I_OrchestrationTools>,
    Singleton::Consume<I_Messaging>
{
public:
    LocalPolicyMgmtGenerator();
    ~LocalPolicyMgmtGenerator();

    void init() override;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __LOCAL_POLICY_MGMT_GEN_H__
