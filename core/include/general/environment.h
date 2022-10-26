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

#ifndef __ENVIRONMENT_H__
#define __ENVIRONMENT_H__

#include <memory>
#include "i_environment.h"
#include "i_tenant_manager.h"
#include "singleton.h"
#include "component.h"

class I_RestApi;

class Environment
        :
    public Component,
    Singleton::Provide<I_Environment>,
    Singleton::Consume<I_RestApi>,
    Singleton::Consume<I_TenantManager>
{
public:
    Environment();
    ~Environment();

    void init();
    void fini();
    void preload();

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __ENVIRONMENT_H__
