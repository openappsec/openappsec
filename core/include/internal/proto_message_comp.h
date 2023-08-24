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

#ifndef __PROTO_MESSAGE_COMP_H__
#define __PROTO_MESSAGE_COMP_H__

#include <memory>
#include <string>

#include "singleton.h"
#include "i_mainloop.h"
#include "i_encryptor.h"
#include "i_messaging.h"
#include "i_agent_details.h"
#include "i_environment.h"
#include "i_rest_api.h"
#include "i_messaging_buffer.h"
#include "i_shell_cmd.h"
#include "i_proxy_configuration.h"
#include "component.h"

class ProtoMessageComp
        :
    public Component,
    Singleton::Provide<I_Messaging>,
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_TimeGet>,
    Singleton::Consume<I_AgentDetails>,
    Singleton::Consume<I_Encryptor>,
    Singleton::Consume<I_Environment>,
    Singleton::Consume<I_MessagingBuffer>,
    Singleton::Consume<I_ShellCmd>,
    Singleton::Consume<I_ProxyConfiguration>
{
public:
    ProtoMessageComp();
    ~ProtoMessageComp();

    void init();
    void fini();

    void preload();

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __PROTO_MESSAGE_COMP_H__
