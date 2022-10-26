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

#ifndef __K8S_POLICY_GEN_H__
#define __K8S_POLICY_GEN_H__

#include "config.h"
#include "component.h"
#include "i_mainloop.h"
#include "i_environment.h"
#include "i_k8s_policy_gen.h"

class K8sPolicyGenerator
        :
    public Component,
    Singleton::Provide<I_K8S_Policy_Gen>,
    Singleton::Consume<Config::I_Config>,
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_Environment>
{
public:
    K8sPolicyGenerator();
    ~K8sPolicyGenerator();

    void preload() override;

    void init() override;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __K8S_POLICY_GEN_H__
