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

#include "buffer.h"

using namespace std;

Buffer::Segment::~Segment()
{
    if (type==Volatility::PRIMARY && !data_container.unique()) {
        // The segment is the PRIMARY holder of the memory, and there are SECONDARY ones of well.
        // Since the PRIMARY has reached its end-of-life, since the memory is only guaranteed to exist as long as the
        // primary is alive it needs to be copied so that the other instances could access it later.
        data_container->takeOwnership();
    }
}

Buffer::Segment::Segment(const Buffer::Segment &seg)
        :
    data_container(seg.data_container),
    offset(seg.offset),
    len(seg.len),
    ptr(seg.ptr)
{
    if (seg.type == Volatility::PRIMARY) {
        type = Volatility::SECONDARY;
        is_owned = data_container->checkOnwership();
    } else {
        type = seg.type;
        is_owned = seg.is_owned;
    }
}

Buffer::Segment::Segment(Segment &&seg)
        :
    data_container(move(seg.data_container)),
    offset(seg.offset),
    len(seg.len)
{
    if (seg.type == Volatility::PRIMARY) {
        // The PRIMARY is being moved, meaning it reached its end-of-life. For the current instance to have access to
        // the memory, the ownership over it must be taken.
        data_container->takeOwnership();
        type = Volatility::NONE;
        is_owned = nullptr;
    } else {
        type = seg.type;
        is_owned = seg.is_owned;
    }
    ptr = data_container->data() + offset;

    seg.offset = 0;
    seg.len = 0;
    seg.type = Volatility::NONE;
    seg.ptr = nullptr;
    seg.is_owned = nullptr;
}

Buffer::Segment &
Buffer::Segment::operator=(const Buffer::Segment &seg)
{
    // Copy-assingment is made of two parts:
    // 1. Destructor logic
    if (type==Volatility::PRIMARY && !data_container.unique()) {
        data_container->takeOwnership();
    }

    // 2. Copy-constructor logic
    data_container = seg.data_container;
    offset = seg.offset;
    len = seg.len;

    ptr = seg.ptr;
    if (seg.type == Volatility::PRIMARY) {
        type = Volatility::SECONDARY;
        is_owned = data_container->checkOnwership();
    } else {
        type = seg.type;
        is_owned = seg.is_owned;
    }

    return *this;
}

Buffer::Segment &
Buffer::Segment::operator=(Segment &&seg)
{
    // Move-assingment is made of two parts:
    // 1. Destructor logic
    if (type==Volatility::PRIMARY && !data_container.unique()) {
        data_container->takeOwnership();
    }

    // 2. Move-constructor logic
    data_container = move(seg.data_container);
    offset = seg.offset;
    seg.offset = 0;
    len = seg.len;
    seg.len = 0;

    if (seg.type == Volatility::PRIMARY) {
        data_container->takeOwnership();
        type = Volatility::NONE;
        is_owned = nullptr;
    } else {
        type = seg.type;
        is_owned = seg.is_owned;
    }
    seg.is_owned = nullptr;
    ptr = data_container->data() + offset;
    seg.ptr = nullptr;
    seg.type = Volatility::NONE;

    return *this;
}

Buffer::Segment::Segment(vector<u_char> &&_vec)
        :
    data_container(make_shared<DataContainer>(move(_vec))),
    offset(0),
    len(data_container->size()),
    is_owned(nullptr)
{
    type = Volatility::NONE;
    ptr = data_container->data();
}

Buffer::Segment::Segment(const u_char *_ptr, uint _len, Buffer::MemoryType _type)
        :
    data_container(make_shared<DataContainer>(_ptr, _len, _type)),
    offset(0),
    len(_len),
    is_owned(nullptr)
{
    type = _type==MemoryType::VOLATILE ? Volatility::PRIMARY : Volatility::NONE;
    ptr = data_container->data();
}

const u_char *
Buffer::Segment::data() const
{
    // Check if a copy-in of the memory happened, and if so - recalulate the short circuit.
    if (is_owned!=nullptr && *is_owned) {
        // The data has been moved (due to taking ownership), so `ptr` and other members need to be updated.
        // Since those changes need to happen in a `const` context, the dangerous `const_cast` is used.
        auto non_const_this = const_cast<Segment *>(this);
        non_const_this->ptr = data_container->data() + offset;
        non_const_this->type = Volatility::NONE;
        non_const_this->is_owned = nullptr;
    }
    return ptr;
}
