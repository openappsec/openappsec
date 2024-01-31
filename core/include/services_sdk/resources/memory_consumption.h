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

#ifndef __MEMORY_CONSUMPTION_H__
#define __MEMORY_CONSUMPTION_H__

#include "i_mainloop.h"
#include "i_environment.h"
#include "debug.h"
#include "common.h"
#include "component.h"

class MemoryCalculator
        :
    public Component,
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_Environment>
{
public:
    MemoryCalculator();
    ~MemoryCalculator();

    void preload();

    void init();

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __MEMORY_CONSUMPTION_H__
