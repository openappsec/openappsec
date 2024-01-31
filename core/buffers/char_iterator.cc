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

void
Buffer::CharIterator::operator++()
{
    if (cur_seg == end_seg) return; // We don't progress past the last segment.
    offset++;
    if (offset < size) return;
    // We've reached the end of the segment, need to move to the next one
    cur_seg++;
    offset = 0;
    if (cur_seg != end_seg) {
        // New segment, read its values of easy access
        size = cur_seg->size();
        ptr  = cur_seg->data();
    } else {
        // We've reached the end of the buffer, set values accordingly
        size = 0;
        ptr  = nullptr;
    }
}

void
Buffer::CharIterator::operator+=(uint steps)
{
    while (offset + steps >= cur_seg->size()) { // What we look for is beyond this segment, move to the next one
        auto skip = cur_seg->size() - offset;
        steps -= skip;
        cur_seg++;
        offset = 0;
        if (cur_seg == end_seg) {
            // We've reached the end of the buffer, set values accordingly
            size = 0;
            ptr  = nullptr;
            return;
        }
    }
    offset += steps;
    size = cur_seg->size();
    ptr  = cur_seg->data();
}

Buffer::CharIterator
Buffer::CharIterator::operator+(uint steps) const
{
    Buffer::CharIterator res = *this;
    res += steps;
    return res;
}

bool
Buffer::CharIterator::operator==(const CharIterator &other) const
{
    return (cur_seg == other.cur_seg) && (offset == other.offset);
}

const u_char &
Buffer::CharIterator::operator*() const
{
    dbgAssert(ptr != nullptr) << "Buffer::CharIterator is not pointing to a real value";
    return ptr[offset];
}

Buffer::CharIterator::CharIterator(const SegIterator &_cur, const SegIterator &_end, uint _offset)
        :
    cur_seg(_cur),
    end_seg(_end),
    ptr(_cur->data()),
    offset(_offset),
    size(_cur->size())
{}

Buffer::CharIterator::CharIterator(const SegIterator &_end)
        :
    cur_seg(_end),
    end_seg(_end),
    ptr(nullptr),
    offset(0),
    size(0)
{}
