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

#ifndef __NGINX_ATTACHMENT_H__
#define __NGINX_ATTACHMENT_H__

#include "singleton.h"
#include "i_mainloop.h"
#include "i_table.h"
#include "i_gradual_deployment.h"
#include "i_http_manager.h"
#include "i_static_resources_handler.h"
#include "i_socket_is.h"
#include "i_environment.h"
#include "i_shell_cmd.h"
#include "i_tenant_manager.h"
#include "transaction_table_metric.h"
#include "nginx_attachment_metric.h"
#include "nginx_intaker_metric.h"
#include "component.h"

using SessionID = uint32_t;

class NginxAttachment
        :
    public Component,
    Singleton::Provide<I_StaticResourcesHandler>,
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_GradualDeployment>,
    Singleton::Consume<I_TableSpecific<SessionID>>,
    Singleton::Consume<I_HttpManager>,
    Singleton::Consume<I_TimeGet>,
    Singleton::Consume<I_Socket>,
    Singleton::Consume<I_InstanceAwareness>,
    Singleton::Consume<I_Environment>,
    Singleton::Consume<I_ShellCmd>,
    Singleton::Consume<I_TenantManager>
{
public:
    NginxAttachment();
    ~NginxAttachment();

    void preload();

    void init();
    void fini();

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __NGINX_ATTACHMENT_H__
