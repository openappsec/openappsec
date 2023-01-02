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

#ifndef __WAAP_H__
#define __WAAP_H__

#include <memory>

#include "singleton.h"
#include "i_mainloop.h"
#include "i_table.h"
#include "i_static_resources_handler.h"
#include "http_inspection_events.h"
#include "i_instance_awareness.h"
#include "table_opaque.h"
#include "component.h"

// forward decleration
class I_Telemetry;
class I_DeepAnalyzer;
class I_WaapAssetStatesManager;

class I_Messaging;
class I_AgentDetails;
class I_Encryptor;

class WaapComponent
        :
    public Component,
    Singleton::Consume<I_StaticResourcesHandler>,
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_TimeGet>,
    Singleton::Consume<I_Table>,
    Singleton::Consume<I_Telemetry>,
    Singleton::Consume<I_DeepAnalyzer>,
    Singleton::Consume<I_InstanceAwareness>,
    Singleton::Consume<I_WaapAssetStatesManager>,
    Singleton::Consume<I_AgentDetails>,
    Singleton::Consume<I_Messaging>,
    Singleton::Consume<I_Encryptor>,
    Singleton::Consume<I_Environment>
{
public:
    WaapComponent();
    ~WaapComponent();

    void preload();

    void init();
    void fini();

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __WAAP_H__
