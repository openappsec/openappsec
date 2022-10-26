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

#include "table/opaque_repo.h"

void
TableOpaqueRep::addType(const std::string &name, const Gen &gen, const uint &curr, const uint &min)
{
    GenRep[name] = gen;
    GenMinVer[name] = min;
    GenCurrVer[name] = curr;
}

std::unique_ptr<TableOpaqueBase>
TableOpaqueRep::getOpaqueByName(const std::string &name)
{
    auto iter = GenRep.find(name);
    if (iter == GenRep.end()) return nullptr;
    return (iter->second)();
}
