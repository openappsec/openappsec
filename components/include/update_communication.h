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

#ifndef __UPDATE_COMMUNICATION_H__
#define __UPDATE_COMMUNICATION_H__

#include "i_update_communication.h"
#include "i_environment.h"
#include "i_rest_api.h"
#include "i_mainloop.h"
#include "i_service_controller.h"
#include "i_orchestration_tools.h"
#include "component.h"

class UpdateCommunication
        :
    public Component,
    Singleton::Provide<I_UpdateCommunication>,
    Singleton::Consume<I_RestApi>,
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_ServiceController>,
    Singleton::Consume<I_OrchestrationTools>
{
public:
    UpdateCommunication();
    ~UpdateCommunication();

    void preload() override;

    void init() override;
    void fini() override;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __UPDATE_COMMUNICATION_H__
