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

#ifndef __COMMON_H__
#define __COMMON_H__

#define CP_LIKELY(cond)    __builtin_expect((bool)(cond), 1)
#define CP_UNLIKELY(cond)  __builtin_expect((bool)(cond), 0)
#define CP_UNUSED          __attribute__((unused))
#define CP_NO_RETURN       __attribute__((noreturn))

#if defined(__GNUC__) && __GNUC__ >= 7
#define CP_FALL_THROUGH __attribute__ ((fallthrough))
#else
#define CP_FALL_THROUGH ((void)0)
#endif //  __GNUC__ >= 7

#include <memory>
#include <string>
#include <sstream>
#include <iomanip>
#include <sys/types.h>

namespace std
{

#if __cplusplus < 201402L
// make_unique isn't part of C++11 - but pretty useful, so we'll define it in such cases

template<typename ConstructedType, typename... Args>
unique_ptr<ConstructedType>
make_unique(Args&&... args)
{
    return unique_ptr<ConstructedType>(new ConstructedType(forward<Args>(args)...));
}

#endif // __cplusplus < 201402L

// Not part of the C++11 standard, but is useful imitation of Python's `join`
template <typename Iterable>
string
makeSeparatedStr(const Iterable &data, const string &separator)
{
    ostringstream os;
    bool not_first = false;
    for (const auto &element : data) {
        if (not_first) os << separator;
        os << element;
        not_first = true;
    }
    return os.str();
}

template <typename Char>
string
dumpHexChar(const Char &ch)
{
    ostringstream stream;
    if (isprint(ch) && (!isspace(ch) || ch==' ')) {
        stream << "'" << ch << "'";
    } else {
        stream << "\\x" << setw(2) << setfill('0') << hex << static_cast<int>(ch);
    }
    return stream.str();
}

// Produce a hex string from some container of charecters.
// The container must be iterable.
template <typename CharIterable>
string
dumpHex(const CharIterable &arg)
{
    ostringstream stream;
    stream << hex;
    for (uint8_t ch : arg) {
        if (isprint(ch) && (!isspace(ch) || ch==' ')) {
            // Printable characters, except for whitespaces which aren't space.
            if (ch == '\\') stream << '\\';
            stream << ch;
        } else {
            stream << "\\x" << setw(2) << setfill('0') << static_cast<int>(ch);
        }
    }
    return stream.str();
}

template <typename CharIterable>
string
dumpRealHex(const CharIterable &arg)
{
    ostringstream stream;
    stream << hex;
    for (uint8_t ch : arg) {
        stream << " " << setw(2) << setfill('0') << static_cast<int>(ch);
    }
    return stream.str();
}

template <typename T, typename Helper = void>
struct IsPrintable : false_type
{
};

template <typename T>
struct IsPrintable<T, decltype(static_cast<void>(declval<ostream &>() << declval<T>()))> : true_type
{
};

template <typename CanPrint>
ostream &
operator<<(ostream &os, const decltype(declval<CanPrint>().print(declval<ostream &>()), declval<CanPrint>()) &obj)
{
    obj.print(os);
    return os;
}

template <typename First, typename Second>
ostream&
operator<<(ostream &os, const pair<const First, Second> &printable_pair)
{
    os << "{" << printable_pair.first << "," << printable_pair.second << "}";
    return os;
}

} // namespace std

#endif // __COMMON_H__

