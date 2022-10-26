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

#ifndef __COMPONENTS_LIST_H__
#define __COMPONENTS_LIST_H__

#include <string>

#include "component_is/components_list_impl.h"

template <typename ... Components>
class NodeComponents : public Infra::ComponentListCore<Components...>
{
public:
    int run(const std::string &nano_service_name, int argc, char **argv);
};

template <typename TableKey, typename ... Components>
class NodeComponentsWithTable : public NodeComponents<Table<TableKey>, Components...>
{
};

#include "component_is/node_components_impl.h"

#endif // __COMPONENTS_LIST_H__
