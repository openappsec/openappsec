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

#ifndef __INSTANCE_AWARENESS_H__
#define __INSTANCE_AWARENESS_H__

#include <string>
#include <memory>

#include "singleton.h"
#include "i_instance_awareness.h"
#include "component.h"

class InstanceAwareness : public Component, public Singleton::Provide<I_InstanceAwareness>
{
public:
    InstanceAwareness();
    ~InstanceAwareness();

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __INSTANCE_AWARENESS_H__
