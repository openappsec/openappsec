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

#ifndef __CONFIG_COMPONENT_H__
#define __CONFIG_COMPONENT_H__

#include <string>
#include <vector>

#include "config.h"
#include "singleton.h"
#include "i_rest_api.h"
#include "i_time_get.h"
#include "i_mainloop.h"
#include "i_environment.h"
#include "i_messaging.h"
#include "i_instance_awareness.h"
#include "i_tenant_manager.h"
#include "component.h"

class ConfigComponent
        :
    public Component,
    Singleton::Provide<Config::I_Config>,
    Singleton::Consume<I_RestApi>,
    Singleton::Consume<I_TimeGet>,
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_Environment>,
    Singleton::Consume<I_Messaging>,
    Singleton::Consume<I_InstanceAwareness>,
    Singleton::Consume<I_TenantManager>
{
public:
    ConfigComponent();
    ~ConfigComponent();

    void preload();

    void init();

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __CONFIG_COMPONENT_H__
