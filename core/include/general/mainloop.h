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

#ifndef __MAINLOOP_H__
#define __MAINLOOP_H__

#include <memory>

#include "i_mainloop.h"
#include "i_environment.h"
#include "i_time_get.h"
#include "i_messaging.h"
#include "i_agent_details.h"
#include "i_signal_handler.h"
#include "singleton.h"
#include "component.h"

extern bool fini_signal_flag;

class MainloopComponent
        :
    public Component,
    Singleton::Provide<I_MainLoop>,
    Singleton::Consume<I_Environment>,
    Singleton::Consume<I_TimeGet>,
    Singleton::Consume<I_Messaging>,
    Singleton::Consume<I_AgentDetails>,
    Singleton::Consume<I_SignalHandler>
{
public:
    MainloopComponent();
    ~MainloopComponent();

    void preload();

    void init();
    void fini();

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __MAINLOOP_H__
