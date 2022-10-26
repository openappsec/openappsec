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

#ifndef __ENUM_ARRAY_H__
#define __ENUM_ARRAY_H__

#include <array>

#include "enum_range.h"

template <typename Index, typename Val, size_t N = static_cast<size_t>(EnumCount<Index>::getSize())>
class EnumArray
{
public:
    EnumArray() {}
    template <typename... Args>
    explicit EnumArray(const Args&... args) : data{args...} {}

    class Fill {};
    EnumArray(Fill, const Val &val) { data.fill(val); }

    Val &       operator[] (const Index &key)       { return data[static_cast<int>(key)]; }
    const Val & operator[] (const Index &key) const { return data[static_cast<int>(key)]; }

    // Iteration
    using Iter      = typename std::array<Val, N>::iterator;
    using ConstIter = typename std::array<Val, N>::const_iterator;
    Iter      begin()       { return data.begin(); }
    Iter      end()         { return data.end();   }
    ConstIter begin() const { return data.begin(); }
    ConstIter end()   const { return data.end();   }

    void fill(const Val &val) { data.fill(val); }

    // Capacity
    constexpr bool empty()      const { return N == 0; }
    constexpr size_t size()     const { return N; }
    constexpr size_t max_size() const { return N; }

    template <class Archive>
    void serialize(Archive &ar, uint32_t) { ar(data); }

private:
    std::array<Val, N> data;
};

#endif // __ENUM_ARRAY_H__
