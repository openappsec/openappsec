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

#ifndef __DETAILS_RESOLVER_H__
#define __DETAILS_RESOLVER_H__

#include <memory>
#include <string>

#include "i_orchestration_tools.h"
#include "i_details_resolver.h"
#include "i_shell_cmd.h"
#include "singleton.h"
#include "component.h"

class DetailsResolver
        :
    public Component,
    Singleton::Provide<I_DetailsResolver>,
    Singleton::Consume<I_OrchestrationTools>
{
public:
    DetailsResolver();
    ~DetailsResolver();

    void preload() override;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __DETAILS_RESOLVER_H__
