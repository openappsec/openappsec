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

#ifndef __ENUM_RANGE_H__
#define __ENUM_RANGE_H__

#include <type_traits>
#include "maybe_res.h"

// A templated class used to allow simple specialization of EnumCount, like this:
//     enum class CDir = { C2S, S2C };
//     template <>
//     EnumCount<CDir> : public EnumCountSpecialization<CDir, 2> {};
template <typename T, typename std::underlying_type<T>::type num>
class EnumCountSpecialization
{
    using IndexType = typename std::underlying_type<T>::type;
public:
    static constexpr IndexType getSize() { return num; }
};

// A templated class used to get the size of the enum, provided that it has a `COUNT` element at the end.
// A specialization of this template can be made in case the enum doesn't have a `COUNT` element.
template <typename T>
class EnumCount : public EnumCountSpecialization<T, static_cast<typename std::underlying_type<T>::type>(T::COUNT)> {};

namespace NGEN
{

// A templated class to allow easy iteration over a range of values (using the `for ( : )` notation), such as enums.
// The values should be in a strict ascending order, like this:
//     enum class ConnModuleId { PASSIVE_STREAMING, HTTP_PARSER, CMI };
// And not like this:
//     enum class IPVersions { IPV4 = 4, IPV6 = 6 };
template <typename T>
class Range
{
    // A templated class, whose specializations will provide the correct type to work with - that is either the
    // underlying type of the enum (in case of an enum), or the type itself (in case of an int, char, etc.).
    template <typename S, bool E>
    class UnderlyingType {};

    template <typename S>
    class UnderlyingType<S, true>
    {
    public:
        using IndexType = typename std::underlying_type<S>::type;
    };

    template <typename S>
    class UnderlyingType<S, false>
    {
    public:
        using IndexType = S;
    };

    using IndexType = typename UnderlyingType<T, std::is_enum<T>::value>::IndexType;

public:
    class Iterator
    {
    public:
        T operator*() { return static_cast<T>(index); }
        void operator++() { ++index; }
        void operator++(int) { index++; }
        bool operator==(const Iterator &other) { return index == other.index; }
        bool operator!=(const Iterator &other) { return index != other.index; }

    private:
        friend class Range;
        Iterator(IndexType _index) : index(_index) {}
        IndexType index;
    };

    // Iterate over the range [_start_index, _end_index] - inclusive.
    Range(T _start_index, T _end_index)
            :
        start_index(static_cast<IndexType>(_start_index)),
        end_index(static_cast<IndexType>(_end_index))
    {}

    // Iterate over the range [0, _end_index] - inclusive.
    Range(T _end_index)
            :
        start_index(static_cast<IndexType>(0)),
        end_index(static_cast<IndexType>(_end_index))
    {}

    // Iterate over all the values up in an enum. It uses EnumCount template to know how many values there are.
    // For this to work the enum need to either have a dummy value `COUNT` at the end, or have a specialization of
    // the EnumCount template.
    // This version is not intended to used with natual types such as `int`.
    Range()
            :
        start_index(static_cast<IndexType>(0)),
        end_index(EnumCount<T>::getSize() - 1)
    {}

    Iterator begin() const { return Iterator(start_index); }
    Iterator end() const { return Iterator(end_index + 1); }

    // Definiions for Google Mock
    using value_type = T;
    using const_iterator = Iterator;

private:
    IndexType start_index, end_index;
};

} // namespace NGEN

// Templates makeRange functions - these are wrappers for creating Range elements. They allow for automatic deduction
// for the type of Range based on the parameters. They are also available from the global namespace.
template <typename T>
NGEN::Range<T>
makeRange(T v1, T v2)
{
    return NGEN::Range<T>(v1, v2);
}

template <typename T>
NGEN::Range<T>
makeRange(T v1)
{
    return NGEN::Range<T>(v1);
}

template <typename T>
NGEN::Range<T>
makeRange()
{
    return NGEN::Range<T>();
}

// Should be used only for continuous enum
template <typename T>
Maybe<T>
convertToEnum(typename std::underlying_type<T>::type enum_value)
{
    if (enum_value >= EnumCount<T>::getSize()) {
        return genError("Failed to convert number into enum");
    }
    return static_cast<T>(enum_value);
}

#endif // __ENUM_RANGE_H__
