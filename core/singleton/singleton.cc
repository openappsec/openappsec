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

#include "singleton.h"
#include "debug.h"

void
Singleton::registerSingleton(std::type_index type, void *ptr)
{
    singles[type].insert(ptr);
}

void
Singleton::unregisterSingleton(std::type_index type, void *ptr)
{
    singles[type].erase(ptr);
}

void *
Singleton::get(const std::type_index &type)
{
    dbgAssert(singles[type].size() == 1) << "There is no single element from type '" << type.name() << "', "
        "number of elements is " << singles[type].size();
    return *(singles[type].begin());
}

bool
Singleton::exists(const std::type_index &type)
{
    return singles[type].size() != 0;
}

std::map<std::type_index, std::set<void *>> Singleton::singles;
std::map<std::type_index, std::unique_ptr<Singleton::OwnedSingleton>> Singleton::owned_singles;
