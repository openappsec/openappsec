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

#include <string.h>

using namespace std;

Buffer::Buffer(vector<u_char> &&vec)
        :
    len(vec.size())
{
    if (len != 0) {
        segs.push_back(Segment(move(vec)));
        evalFastPath();
    }
}

Buffer::Buffer(const vector<u_char> &vec)
        :
    Buffer(vec.data(), vec.size(), MemoryType::OWNED)
{}

Buffer::Buffer(const vector<char> &vec)
        :
    Buffer(reinterpret_cast<const u_char *>(vec.data()), vec.size(), MemoryType::OWNED)
{}

Buffer::Buffer(const string &str)
        :
    Buffer(reinterpret_cast<const u_char *>(str.data()), str.size(), MemoryType::OWNED)
{}

Buffer::Buffer(const u_char *_ptr, uint _len, MemoryType type)
        :
    len(_len)
{
    if (len != 0) {
        segs.emplace_back(_ptr, _len, type);
        evalFastPath();
    }
}

Buffer::Buffer(const char *_ptr, uint _len, MemoryType type)
        :
    Buffer(reinterpret_cast<const u_char *>(_ptr), _len, type)
{}

Buffer::Buffer(const Buffer &buf)
        :
    segs(buf.segs),
    len(buf.len)
{
    evalFastPath();
}

Buffer::Buffer(Buffer &&buf)
        :
    segs(move(buf.segs))
{
    len = buf.len;
    evalFastPath();

    buf.len = 0;
    buf.evalFastPath();
}

Buffer &
Buffer::operator=(const Buffer &buf)
{
    segs = buf.segs;
    len = buf.len;
    evalFastPath();

    return *this;
}

Buffer &
Buffer::operator=(Buffer &&buf)
{
    segs = move(buf.segs);
    len = buf.len;
    evalFastPath();

    buf.len = 0;
    buf.evalFastPath();

    return *this;
}

bool
Buffer::contains(char ch) const
{
    for (const auto &iter : *this) {
        if (iter == ch) return true;
    }
    return false;
}

uint
Buffer::segmentsNumber() const
{
    return segs.size();
}

void
Buffer::operator+=(const Buffer &other)
{
    if (other.len == 0) return;
    segs.insert(segs.end(), other.segs.begin(), other.segs.end());
    len += other.len;

    // If the buffer was originally empty (and had no segments), fast path needs to be evaluated.
    // This can be detected by the fact that the length of the buffer is equal to the length of `other`.
    if (len == other.len) evalFastPath();
}

Buffer
Buffer::operator+(const Buffer &other) const
{
    Buffer res;
    res.segs.reserve(segmentsNumber() + other.segmentsNumber());
    res.segs.insert(res.segs.end(), segs.begin(), segs.end());
    res.segs.insert(res.segs.end(), other.segs.begin(), other.segs.end());
    res.len = len + other.len;
    res.evalFastPath();

    return res;
}

Buffer
Buffer::getSubBuffer(uint start, uint end) const
{
    dbgAssert(start<=end && end<=len) << "Buffer::getSubBuffer() returned: Illegal scoping of buffer";
    if (start == end) return Buffer();

    Buffer res;
    uint offset = 0;
    for (const auto &seg : segs) {
        uint seg_end = offset + seg.size();
        if (seg_end <= start) {
            offset = seg_end;
            continue;
        }
        res.segs.push_back(seg);
        if (offset < start) {
            auto remove = start - offset;
            res.segs.back().len    -= remove;
            res.segs.back().offset += remove;
            res.segs.back().ptr    += remove;
        }
        if (seg_end > end) {
            auto remove = seg_end - end;
            res.segs.back().len -= remove;
        }
        if (seg_end >= end) break;
        offset = seg_end;
    }
    res.len = end - start;

    res.evalFastPath();
    return res;
}

Maybe<uint>
Buffer::findFirstOf(char ch, uint start) const
{
    dbgAssert(start <= len) << "Buffer::findFirstOf() returned: Cannot set a start point after buffer's end";

    for (; start < len; ++start) {
        if ((*this)[start] == ch) return start;
    }
    return genError("Not located");
}

Maybe<uint>
Buffer::findFirstOf(const Buffer &buf, uint start) const
{
    dbgAssert(start <= len) << "Buffer::findFirstOf() returned: Cannot set a start point after buffer's end";

    for (; start + buf.size() <= len; ++start) {
        auto sub_buffer = getSubBuffer(start, start + buf.size());
        if (sub_buffer == buf) return start;
    }
    return genError("Not located");
}

Maybe<uint>
Buffer::findFirstNotOf(char ch, uint start) const
{
    dbgAssert(start <= len) << "Buffer::findFirstNotOf() returned: Cannot set a start point after buffer's end";
    for (; start < len; ++start) {
        if ((*this)[start] != ch) return start;
    }
    return genError("Everything is the same ch");
}

Maybe<uint>
Buffer::findLastOf(char ch, uint start) const
{
    dbgAssert(start <= len) << "Buffer::findLastOf() returned: Cannot set a start point after buffer's end";
    for (; 0 < start; --start) {
        if ((*this)[start - 1] == ch) return start - 1;
    }
    return genError("Not located");
}

Maybe<uint>
Buffer::findLastNotOf(char ch, uint start) const
{
    dbgAssert(start <= len) << "Buffer::findLastNotOf() returned: Cannot set a start point after buffer's end";
    for (; 0 < start; --start) {
        if ((*this)[start - 1] != ch) return start - 1;
    }
    return genError("Everything is the same ch");
}

void
Buffer::truncateHead(uint size)
{
    dbgAssert(size <= len) << "Cannot set a new start of buffer after the buffer's end";
    if (size == 0) return;
    if (size == len) {
        clear();
        return;
    }

    while (segs.front().size() <= size) {
        size -= segs.front().size();
        len  -= segs.front().size();
        segs.erase(segs.begin());
    }

    if (size > 0) {
        len                 -= size;
        segs.front().offset += size;
        segs.front().len    -= size;
        segs.front().ptr    += size;
    }

    evalFastPath();
}

void
Buffer::truncateTail(uint size)
{
    dbgAssert(size <= len) << "Cannot set a new end of buffer after the buffer's end";
    if (size == 0) return;
    if (size == len) {
        clear();
        return;
    }

    while (segs.back().size() <= size) {
        size -= segs.back().size();
        len  -= segs.back().size();
        segs.pop_back();
    }

    if (size > 0) {
        len                -= size;
        segs.back().len    -= size;
    }

    // Special case in which fixing fast path is really easy (as the first segment didn't change)
    if (len < fast_path_len) fast_path_len = len;
}
void
Buffer::keepHead(uint size)
{
    dbgAssert(size <= len) << "Cannot set a new end of buffer before the buffer's start";
    truncateTail(len - size);
}

void
Buffer::keepTail(uint size)
{
    dbgAssert(size <= len) << "Cannot set a new start of buffer after the buffer's end";
    truncateHead(len - size);
}

void
Buffer::clear()
{
    segs.clear();
    len = 0;
    evalFastPath();
}

bool
Buffer::operator==(const Buffer &buf) const
{
    if (len != buf.len) return false;
    if (len == 0) return true;

    // Initializing the iteration over `this` segments
    // Since the segments of the buffer may be unaliagned, `l_ptr` and `l_size` hold the current place in the
    // current segment and the size left in the segment.
    auto l_iter = segs.begin();
    auto l_ptr  = l_iter->data();
    auto l_size = l_iter->size();
    // Same for `buf`
    auto r_iter = buf.segs.begin();
    auto r_ptr  = r_iter->data();
    auto r_size = r_iter->size();
    // `offset` is the current offset in both buffers and is used to track the progess of the loop.
    uint offset = 0;

    while (true) {
        uint curr_size = min(l_size, r_size); // Size to compare
        if (memcmp(l_ptr, r_ptr, curr_size) != 0) return false;
        offset += curr_size;

        if (offset >= len) break;

        if (l_size <= curr_size) { // Finished a segment of `this`
            l_iter++;
            l_ptr  = l_iter->data();
            l_size = l_iter->size();
        } else { // Progress within the segment
            l_size -= curr_size;
            l_ptr  += curr_size;
        }

        if (r_size <= curr_size) { // Finished a segment of `buf`
            r_iter++;
            r_ptr  = r_iter->data();
            r_size = r_iter->size();
        } else { // Progress within the segment
            r_size -= curr_size;
            r_ptr  += curr_size;
        }
    }

    return true;
}

bool
Buffer::isEqual(const u_char *ptr, uint size) const
{
    if (len != size) return false;
    for (const auto &seg : segs) {
        if (memcmp(ptr, seg.data(), seg.size()) != 0) return false;
        ptr += seg.size();
    }
    return true;
}

bool
Buffer::isEqualLowerCase(const Buffer &buf) const
{
    if (len != buf.size()) return false;
    for (uint i = 0; i < len; i++) {
        if (tolower((*this)[i]) != buf[i]) return false;
    }
    return true;
}

const u_char &
Buffer::operator[](uint offset) const
{
    if (offset < fast_path_len) {
        if (is_owned!=nullptr && *is_owned) {
            evalFastPath();
        }
        return fast_path_ptr[offset];
    }
    dbgAssert(offset < len) << "Buffer::operator returned: attempted an access outside the buffer";
    return *(begin() + offset);
}

Buffer::operator string() const
{
    serialize();
    return string(reinterpret_cast<const char *>(fast_path_ptr), fast_path_len);
}

Maybe<Buffer::InternalPtr<u_char>>
Buffer::getPtr(uint start, uint get_len) const
{
    auto end = start + get_len;
    if (end > len) return genError("Cannot get internal pointer beyond the buffer limits");
    if (start >= end) return genError("Invalid length ('start' is not smaller than 'end')");

    if (end <= fast_path_len) {
        if (is_owned!=nullptr && *is_owned) {
            evalFastPath();
        }
        return Buffer::InternalPtr<u_char>(fast_path_ptr + start, segs.front().data_container);
    }

    // Search the segments for the one that contains the requested data.
    uint offset = 0;
    for (auto &seg : segs) {
        uint seg_end = offset + seg.size();
        if (seg_end < start) { // We haven't reached the segment yet
            offset = seg_end;
            continue;
        }
        if (seg_end < end) break; // The data isn't contained entirely in one segment, serialization is needed.

        return Buffer::InternalPtr<u_char>(seg.ptr + start - offset, seg.data_container);
    }

    serialize();
    return Buffer::InternalPtr<u_char>(fast_path_ptr + start, segs.front().data_container);
}

void
Buffer::serialize() const
{
    if (segmentsNumber() < 2) {
        evalFastPath();
        return;
    }
    // While `serialize` doesn't change the content of the buffer, it does changes the way it is organized internally.
    // Since we want to allow accesors be `const`, and hide from the user the fact that they require changing the
    // internal structure of the buffer - `serialize` needs to be able to change a `const` buffer, hence the dangarous
    // `const_cast` on `this`.
    auto &segments = const_cast<Buffer *>(this)->segs;
    vector<u_char> vec;
    vec.reserve(len);
    for (auto iter : segments) {
        vec.insert(vec.end(), iter.data(), iter.data() + iter.size());
    }
    segments.clear();
    segments.push_back(Segment(move(vec)));
    evalFastPath();
}

Buffer::CharIterator
Buffer::begin() const
{
    return len == 0 ? CharIterator(segs.end()) : CharIterator(segs.begin(), segs.end(), 0);
}

Buffer::CharIterator
Buffer::end() const
{
    return CharIterator(segs.end());
}

Buffer::SegRange
Buffer::segRange() const
{
    return SegRange(segs.begin(), segs.end());
}

void
Buffer::evalFastPath() const
{
    // While `evalFastPath` doesn't change the content of the buffer, it does re-evaluate the fast path elements.
    // Since we can detect such change in a `const` method, `evalFastPath` needs to be able to change fast path
    // parameters of a `const` buffer - hence the dangarous `const_cast` on `this`.
    auto non_const_this = const_cast<Buffer *>(this);

    if (segs.size() != 0) {
        auto &seg = segs.front();
        non_const_this->fast_path_len = seg.size();
        non_const_this->fast_path_ptr = seg.data();
        non_const_this->type = seg.type;
        non_const_this->is_owned = seg.is_owned;
    } else {
        non_const_this->fast_path_len = 0;
        non_const_this->fast_path_ptr = nullptr;
        non_const_this->type = Volatility::NONE;
        non_const_this->is_owned = nullptr;
    }
}

bool
Buffer::operator<(const Buffer &buf) const
{
    if (len != buf.len) return len < buf.len;
    if (len == 0) return false;

    // Initializing the iteration over `this` segments
    // Since the segments of the buffer may be unaliagned, `l_ptr` and `l_size` hold the current place in the
    // current segment and the size left in the segment.
    auto l_iter = segs.begin();
    auto l_ptr = l_iter->data();
    auto l_size = l_iter->size();
    // Same for `buf`
    auto r_iter = buf.segs.begin();
    auto r_ptr = r_iter->data();
    auto r_size = r_iter->size();
    // `offset` is the current offset in both buffers and is used to track the progess of the loop.
    uint offset = 0;

    while (true) {
        uint curr_size = min(l_size, r_size); // Size to compare
        int compare_result = memcmp(l_ptr, r_ptr, curr_size);
        if (compare_result < 0) return true;
        if (compare_result > 0) return false;
        offset += curr_size;

        if (offset >= len) break;

        if (l_size <= curr_size) { // Finished a segment of `this`
            l_iter++;
            l_ptr = l_iter->data();
            l_size = l_iter->size();
        } else { // Progress within the segment
            l_size -= curr_size;
            l_ptr += curr_size;
        }

        if (r_size <= curr_size) { // Finished a segment of `buf`
            r_iter++;
            r_ptr = r_iter->data();
            r_size = r_iter->size();
        } else { // Progress within the segment
            r_size -= curr_size;
            r_ptr += curr_size;
        }
    }

    return false;
}
