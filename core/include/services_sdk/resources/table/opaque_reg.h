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

#ifndef __TABLE_OPAQUE_REG_H__
#define __TABLE_OPAQUE_REG_H__

#include "table/opaque_basic.h"
#include "table/opaque_repo.h"

template <typename Opaque>
class TableOpaqueReg : public TableOpaqueBase
{
public:
    TableOpaqueReg(Opaque *ptr);

    Opaque * getOpaque();
    std::string nameOpaque() const override;

private:
    void regOpaque() const;

    Opaque *opq_ptr;
};

template <typename Opaque>
TableOpaqueReg<Opaque>::TableOpaqueReg(Opaque *ptr) : opq_ptr(ptr)
{
}

template <typename Opaque>
Opaque *
TableOpaqueReg<Opaque>::getOpaque()
{
    return opq_ptr;
}

template <typename Opaque>
std::string
TableOpaqueReg<Opaque>::nameOpaque() const
{
    regOpaque(); // reference ensures that static object is called.
    return Opaque::name();
}

template <typename Opaque>
void
TableOpaqueReg<Opaque>::regOpaque() const
{
    ::cereal::detail::StaticObject<AddToTableOpaqueRepo<Opaque>>::getInstance();
}

#endif // __TABLE_OPAQUE_REG_H__
