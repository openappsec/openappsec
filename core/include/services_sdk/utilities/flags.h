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

#ifndef __FLAGS_H__
#define __FLAGS_H__

#include <bitset>

#include "cereal/types/bitset.hpp"

template <typename EnumClass, uint NumberOfValues = static_cast<uint>(EnumClass::COUNT) + 1>
class Flags
{
    static_assert(NumberOfValues > 0, "Number of possible Flags must be positive");

public:
    void setAll() { flags.set(); }
    void reset() { flags.reset(); }

    void setFlag(EnumClass flag) { flags.set(getIndex(flag)); }
    void unsetFlag(EnumClass flag) { flags.reset(getIndex(flag)); }
    bool isSet(EnumClass flag) const { return flags.test(getIndex(flag)); }
    bool isUnset(EnumClass flag) const { return !isSet(flag); }
    bool operator==(const Flags<EnumClass, NumberOfValues> &other) const { return flags == other.flags; };

    bool empty() const { return flags.none(); }

    template <class Archive>
    void serialize(Archive &ar, uint32_t) { ar(flags); }

private:
    uint getIndex(const EnumClass &flag) const { return static_cast<uint>(flag); }

    std::bitset<NumberOfValues> flags;
};

#endif // __FLAGS_H__
