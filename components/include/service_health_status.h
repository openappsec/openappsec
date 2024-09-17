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

#ifndef __SERVICE_HEALTH_STATUS_H__
#define __SERVICE_HEALTH_STATUS_H__

#include "singleton.h"
#include "i_rest_api.h"
#include "i_environment.h"
#include "component.h"

class ServiceHealthStatus
        :
    public Component,
    Singleton::Consume<I_RestApi>,
    Singleton::Consume<I_Environment>
{
public:
    ServiceHealthStatus();
    ~ServiceHealthStatus();

    void init() override;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __SERVICE_HEALTH_STATUS_H__
