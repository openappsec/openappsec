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

#ifndef __OPAQUE_REPO_H__
#define __OPAQUE_REPO_H__

#include "table/opaque_basic.h"

#include "cereal/details/static_object.hpp"

class TableOpaqueRep
{
    using Gen = std::unique_ptr<TableOpaqueBase>(*)();

public:
    void addType(const std::string &name, const Gen &gen, const uint &curr, const uint &min);
    std::unique_ptr<TableOpaqueBase> getOpaqueByName(const std::string &name);

private:
    std::map<std::string, Gen> GenRep;
    std::map<std::string, uint> GenMinVer;
    std::map<std::string, uint> GenCurrVer;
};

template <typename Opaque>
class AddToTableOpaqueRepo
{
public:
    AddToTableOpaqueRepo();
};

template <typename Opaque>
AddToTableOpaqueRepo<Opaque>::AddToTableOpaqueRepo()
{
    auto &rep = ::cereal::detail::StaticObject<TableOpaqueRep>::getInstance();
    rep.addType(Opaque::name(), Opaque::prototype, Opaque::currVer(), Opaque::minVer());
}

#endif // __OPAQUE_REPO_H__
