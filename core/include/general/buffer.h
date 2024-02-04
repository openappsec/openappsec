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

#ifndef __BUFFER_H__
#define __BUFFER_H__

#include <vector>
#include <string>
#include <memory>

#include "cereal/types/vector.hpp"
#include "cereal/types/memory.hpp"

#include "maybe_res.h"
#include "debug.h"

class Buffer final
{
public:
    // Indication of the type of memory that is held by the system:
    // OWNED - The system allocated the memory and is resposible for releasing it.
    // STATIC - The memory is such that is always availabe and doesn't require releasing.
    // VOLATILE - The memory was allocated outside of the system and is only availabe for the duration of the
    //            instance. This memory may require the system to later duplicate (and does change it to OWNED
    //            memeory).
    enum class MemoryType
    {
        OWNED, STATIC, VOLATILE
    };

private:
    // Indication of the volatility of the memory.
    // OWNED and STATIC type of memory are not volatile, and are marked NONE.
    // The initial VOLATILE instance is guaranteed to have the volatile memory available while that instance exists,
    // and is marked PRIMARY.
    // Instances that are created based on an existing VOLATILE instance are marked as SECONDARY. They are guaranteed
    // to have the memory available to thme only as long as the PRIMARY instance exists. If such SECONDARY instance
    // continues to exists at the time when the PRIMARY instance is destoryed, then a copy of the memory (of which the
    // I/S will be the owner) needs to be made turning the instance from VOLATILE to OWNED.
    enum class Volatility
    {
        NONE, PRIMARY, SECONDARY
    };

    // The "DataContainer" class represent a shared piece of memory - so if two idifferent buffers buffers
    // can both reference the same memory segement without copying it.
    class DataContainer;

public:
    // The "Segment" class represent a countinuous part of the buffer. Unlike the "DataContainer" class, it is not
    // shared between diffrent buffers. It can be thought of as shared pointer to the "DataContainer" class - but it
    // also has additional capabilities of scoping, compairson, and handling copying-in of the memory.
    class Segment;

    // The "SegIterator" class allow iterating over the different segments of the buffer (for specifc part of the code
    // that require very high performance). The "SegRange" class is used for the `for ( : )` syntax.
    using SegIterator = std::vector<Segment>::const_iterator;
    class SegRange final
    {
    public:
        SegIterator begin() { return b; }
        SegIterator end() { return e; }

    private:
        friend class Buffer;
        SegRange(const SegIterator &_b, const SegIterator &_e) : b(_b), e(_e) {}
        SegIterator b, e;
    };

    // The "CharIterator" class is used to access the buffer, and may become invalid if the buffer changes.
    // The "InternalPtr" class is used to read from the buffer through a structure, and is garantied to hold its
    // original value even after the buffer changes or deleted.
    class CharIterator;
    template <typename T> class InternalPtr;

public:
    using value_type = u_char;
    using const_iterator = CharIterator;

    Buffer() {}
    Buffer(std::vector<u_char> &&vec);
    Buffer(const std::vector<u_char> &vec);
    Buffer(const std::vector<char> &vec);
    Buffer(const std::string &str);
    Buffer(const u_char *_ptr, uint _len, MemoryType type);
    Buffer(const char *_ptr, uint _len, MemoryType type);

    Buffer(const Buffer &);
    Buffer(Buffer &&);
    Buffer & operator=(const Buffer &);
    Buffer & operator=(Buffer &&);

    static void preload(); // Adds buffer evaluators
    static void init() {}
    static void fini() {}

    static std::string getName() { return "Buffer"; }

    uint size() const { return len; }
    bool isEmpty() const { return len==0; }
    bool contains(char ch) const;
    uint segmentsNumber() const;
    void operator+=(const Buffer &);
    Buffer operator+(const Buffer &) const;
    Buffer getSubBuffer(uint start, uint end) const;

    Maybe<uint> findFirstOf(char ch, uint start = 0) const;
    Maybe<uint> findFirstOf(const Buffer &buf, uint start = 0) const;
    Maybe<uint> findFirstNotOf(char ch, uint start = 0) const;
    Maybe<uint> findLastOf(char ch) const { return findLastOf(ch, len); }
    Maybe<uint> findLastOf(char ch, uint start) const;
    Maybe<uint> findLastNotOf(char ch) const { return findLastNotOf(ch, len); }
    Maybe<uint> findLastNotOf(char ch, uint start) const;
    
    void truncateHead(uint size);
    void truncateTail(uint size);
    void keepHead(uint size);
    void keepTail(uint size);
    void clear();

    bool operator==(const Buffer &buf) const;
    bool operator!=(const Buffer &buf) const { return !((*this)==buf); }
    bool isEqual(const u_char *ptr, uint size) const;
    bool isEqual(const char *ptr, uint size) const { return isEqual(reinterpret_cast<const u_char *>(ptr), size); }
    bool isEqualLowerCase(const Buffer &buf) const;
    bool operator<(const Buffer &buf) const;
    bool operator<=(const Buffer &buf) const { return !(buf < *this); }
    bool operator>(const Buffer& buf) const { return (buf < *this); }
    bool operator>=(const Buffer &buf) const { return !(*this < buf); }

    const u_char * data() const { serialize(); return fast_path_ptr; }
    Maybe<InternalPtr<u_char>> getPtr(uint start, uint len) const;
    template <typename T> Maybe<InternalPtr<T>> getTypePtr(uint start) const;
    const u_char & operator[](uint offset) const;
    operator std::string() const;

    CharIterator begin() const;
    CharIterator end() const;
    SegRange segRange() const;

    void serialize() const;

    template<class Archive> void save(Archive &ar, uint32_t) const;
    template<class Archive> void load(Archive &ar, uint32_t);

private:
    void evalFastPath() const;
    std::vector<Segment> segs;
    uint len = 0;
    // The "fast_path_ptr" and "fast_path_len" are used to allow a direct fast access to the beginning of the buffer
    // (the first segment), which is the typical case.
    uint fast_path_len = 0;
    const u_char *fast_path_ptr = nullptr;
    // The "type" and "is_owned" are used to make sure that the "fast_path_ptr" is up-to-date (regarding copying-in).
    Volatility type = Volatility::NONE;
    bool *is_owned = nullptr;
};

#include "buffer/data_container.h"
#include "buffer/segment.h"
#include "buffer/char_iterator.h"
#include "buffer/internal_ptr.h"

template<typename T>
Maybe<Buffer::InternalPtr<T>>
Buffer::getTypePtr(uint start) const
{
    auto ptr = getPtr(start, sizeof(T));
    if (!ptr.ok()) return ptr.passErr();
    return InternalPtr<T>(ptr.unpackMove());
}

template<class Archive>
void
Buffer::save(Archive &ar, uint32_t) const
{
    ar(segs, len);
}

template<class Archive>
void
Buffer::load(Archive &ar, uint32_t)
{
    ar(segs, len);
    evalFastPath();
}

#include "buffer/helper_functions.h"

#endif // __BUFFER_H__
