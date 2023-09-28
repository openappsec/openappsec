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

#ifndef __ORCHESTRATION_COMP_H__
#define __ORCHESTRATION_COMP_H__

#include "i_messaging.h"
#include "i_mainloop.h"
#include "i_shell_cmd.h"
#include "i_encryptor.h"
#include "i_orchestration_status.h"
#include "i_rest_api.h"
#include "i_orchestration_tools.h"
#include "i_downloader.h"
#include "i_service_controller.h"
#include "i_manifest_controller.h"
#include "i_update_communication.h"
#include "i_details_resolver.h"
#include "i_shell_cmd.h"
#include "i_agent_details.h"
#include "i_environment.h"
#include "i_tenant_manager.h"
#include "i_package_handler.h"
#include "i_env_details.h"
#include "component.h"

class OrchestrationComp
        :
    public Component,
    Singleton::Consume<I_Messaging>,
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_ShellCmd>,
    Singleton::Consume<I_TimeGet>,
    Singleton::Consume<I_AgentDetails>,
    Singleton::Consume<I_OrchestrationTools>,
    Singleton::Consume<I_OrchestrationStatus>,
    Singleton::Consume<I_Encryptor>,
    Singleton::Consume<I_Environment>,
    Singleton::Consume<I_DetailsResolver>,
    Singleton::Consume<I_RestApi>,
    Singleton::Consume<I_TenantManager>,
    Singleton::Consume<I_PackageHandler>,
    Singleton::Consume<I_ServiceController>,
    Singleton::Consume<I_UpdateCommunication>,
    Singleton::Consume<I_Downloader>,
    Singleton::Consume<I_ManifestController>,
    Singleton::Consume<I_EnvDetails>
{
public:
    OrchestrationComp();
    ~OrchestrationComp();

    void preload() override;

    void init() override;
    void fini() override;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __ORCHESTRATION_COMP_H__
