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

#ifndef __GRADUAL_DEPLOYMENT_H__
#define __GRADUAL_DEPLOYMENT_H__

#include "i_gradual_deployment.h"

#include "singleton.h"
#include "i_rest_api.h"
#include "i_table.h"
#include "i_mainloop.h"
#include "component.h"

class GradualDeployment
        :
    public Component,
    Singleton::Provide<I_GradualDeployment>,
    Singleton::Consume<I_RestApi>,
    Singleton::Consume<I_MainLoop>
{
public:
    GradualDeployment();
    ~GradualDeployment();

    void init();

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __GRADUAL_DEPLOYMENT_H__
