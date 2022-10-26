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

#ifndef __AGENT_DETAILS_REPORTER_H__
#define __AGENT_DETAILS_REPORTER_H__

#include "singleton.h"
#include "component.h"
#include "i_agent_details_reporter.h"
#include "i_messaging.h"
#include "i_environment.h"
#include "i_mainloop.h"
#include "i_rest_api.h"
#include "component.h"

class AgentDetailsReporter
        :
    public Component,
    Singleton::Provide<I_AgentDetailsReporter>,
    Singleton::Consume<I_Messaging>,
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_Environment>,
    Singleton::Consume<I_RestApi>
{
public:
    AgentDetailsReporter();
    ~AgentDetailsReporter();

    void preload() override;

    void init() override;
    void fini() override;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __AGENT_DETAILS_REPORTER_H__
