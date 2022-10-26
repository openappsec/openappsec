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

#ifndef __GENERIC_RULEBASE_H__
#define __GENERIC_RULEBASE_H__

#include <memory>

#include "i_generic_rulebase.h"
#include "i_intelligence_is_v2.h"
#include "singleton.h"
#include "component.h"

class GenericRulebase
        :
    public Component,
    Singleton::Provide<I_GenericRulebase>,
    Singleton::Consume<I_Intelligence_IS_V2>
{
public:
    GenericRulebase();
    ~GenericRulebase();

    void preload();

    void init();
    void fini();

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __GENERIC_RULEBASE_H__
