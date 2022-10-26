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

#ifndef __TABLE_OPAQUE_H__
#define __TABLE_OPAQUE_H__

#include "table/opaque_reg.h"

template <typename Opaque>
class TableOpaqueSerialize : public TableOpaqueReg<Opaque>
{
public:
    TableOpaqueSerialize(Opaque *ptr) : TableOpaqueReg<Opaque>(ptr) {}

    void loadOpaque(cereal::BinaryInputArchive &ar,  uint ver) override { getOpaque()->serialize(ar, ver); }
    void saveOpaque(cereal::BinaryOutputArchive &ar, uint ver) override { getOpaque()->serialize(ar, ver); }

private:
    Opaque * getOpaque() { return TableOpaqueReg<Opaque>::getOpaque(); }
};

template <typename Opaque>
class TableOpaqueLoadSave : public TableOpaqueReg<Opaque>
{
public:
    TableOpaqueLoadSave(Opaque *ptr) : TableOpaqueReg<Opaque>(ptr) {}

    void loadOpaque(cereal::BinaryInputArchive &ar,  uint ver) override { getOpaque()->load(ar, ver); }
    void saveOpaque(cereal::BinaryOutputArchive &ar, uint ver) override { getOpaque()->save(ar, ver); }

private:
    Opaque * getOpaque() { return TableOpaqueReg<Opaque>::getOpaque(); }
};

#endif // __TABLE_OPAQUE_H__
