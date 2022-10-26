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

#ifndef __SIGNAL_HANDLER_H__
#define __SIGNAL_HANDLER_H__

#include "config.h"
#include "i_mainloop.h"
#include "i_time_get.h"
#include "i_agent_details.h"
#include "i_environment.h"
#include "i_messaging.h"
#include "i_signal_handler.h"
#include "config/i_config.h"
#include "component.h"

class SignalHandler
        :
    public Component,
    Singleton::Provide<I_SignalHandler>,
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_TimeGet>,
    Singleton::Consume<I_AgentDetails>,
    Singleton::Consume<I_Environment>,
    Singleton::Consume<I_Messaging>,
    Singleton::Consume<Config::I_Config>
{
public:
    SignalHandler();
    ~SignalHandler();

    void init();
    void preload();

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __SIGNAL_HANDLER_H__
