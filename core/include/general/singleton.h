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

#ifndef __SINGLETON_H__
#define __SINGLETON_H__

#include <typeinfo>
#include <typeindex>
#include <map>
#include <set>
#include <memory>

#include "common.h"

class Singleton
{
public:
    template <class I_Face>
    class Provide;

    template <class I_Face>
    class Consume;

    template <typename T>
    static bool exists();

    // Dealing with owned singletons - see advanced topics.
    class OwnedSingleton;

    template <typename DerivedFromOwnedSingleton>
    static DerivedFromOwnedSingleton * getOwned();

    template <typename DerivedFromOwnedSingleton>
    static bool existsOwned();

    template <typename DerivedFromOwnedSingleton, typename ... BuildArgs>
    static void newOwned(BuildArgs ... args);

    template <typename DerivedFromOwnedSingleton>
    static void deleteOwned();

    template <typename DerivedFromOwnedSingleton>
    static void setOwned(std::unique_ptr<DerivedFromOwnedSingleton> &&ptr);

private:
    Singleton() {}

    template <typename I_Face>
    static I_Face * get();

    static void registerSingleton(std::type_index type, void *ptr);
    static void unregisterSingleton(std::type_index type, void *ptr);
    static void * get(const std::type_index &index);
    static bool exists(const std::type_index &index);

    static std::map<std::type_index, std::set<void *>> singles;
    static std::map<std::type_index, std::unique_ptr<OwnedSingleton>> owned_singles;
};

template <typename Component, typename Interface>
Interface * getInterface();

#include "impl/singleton.h"

#endif // __SINGLETON_H__
