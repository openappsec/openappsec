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

#ifndef __COMPONENT_H__
#define __COMPONENT_H__

#include <string>
#include <typeinfo>

class Component
{
public:
    Component(const std::string &component_name) : name(component_name) {}
    virtual ~Component() {}

// LCOV_EXCL_START Reason: This functions are tested in system tests
    virtual void preload() {}

    virtual void init() {}
    virtual void fini() {}
// LCOV_EXCL_STOP

    const std::string & getName() const { return name; }

private:
    std::string name;
};

#endif // __COMPONENT_H__
