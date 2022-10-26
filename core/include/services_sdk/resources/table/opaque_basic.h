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

#ifndef __TABLE_OPAQUE_BASE_H__
#define __TABLE_OPAQUE_BASE_H__

#include <string>
#include <sys/types.h>

#include "cereal/types/common.hpp"
#include "cereal/types/string.hpp"
#include "cereal/types/vector.hpp"
#include "cereal/types/list.hpp"
#include "cereal/types/array.hpp"
#include "cereal/types/unordered_map.hpp"
#include "cereal/types/map.hpp"
#include "cereal/types/memory.hpp"
#include "cereal/types/chrono.hpp"

#include "cereal/archives/binary.hpp"

class TableOpaqueBase
{
public:
    TableOpaqueBase() {}
    virtual ~TableOpaqueBase() {}

    virtual void loadOpaque(cereal::BinaryInputArchive &, uint) = 0;
    virtual void saveOpaque(cereal::BinaryOutputArchive &, uint) = 0;

    virtual std::string nameOpaque() const = 0;

    virtual void uponEnteringContext() {}
    virtual void uponLeavingContext() {}
};

#endif // __TABLE_OPAQUE_BASE_H__
