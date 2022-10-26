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

#ifndef __VIRTUAL_MODIFIERS_H__
#define __VIRTUAL_MODIFIERS_H__

#include "virtual_container.h"
#include "common.h"

template <int ch>
class CharRemover
{
public:
    template <typename CharIterator>
    static std::pair<typename CharIterator::value_type, CharIterator>
    getValueAndNextIter(const CharIterator &next, const CharIterator &end)
    {
        for (auto real_next = next; real_next != end; ++real_next) {
            if (*real_next != ch) {
                auto value = *real_next;
                ++real_next;
                return std::make_pair(value, real_next);
            }
        }
        throw EndVirtualContainer();
    }
};

// `ch` will be used as the character indicating a hex value.
// So is `ch` is '%' the substring "%32" will be interpreted as the character '2'.
// If `ch` is -1, the entire string will be interpreted as hex value.
template <int ch>
class HexDecoder
{
    class DecodingError {};
public:
    template <typename CharIterator>
    static std::pair<typename CharIterator::value_type, CharIterator>
    getValueAndNextIter(const CharIterator &next, const CharIterator &end)
    {
        try {
            auto iter = next;
            if (*next == ch) {
                ++iter;
                if (iter == end) throw DecodingError();
            }
            if (*next == ch || ch == -1) {
                typename CharIterator::value_type res = getNible(iter) << 4;
                ++iter;
                if (iter == end) throw DecodingError();
                res |= getNible(iter);
                ++iter;
                return std::make_pair(res, iter);
            }
        } catch(const DecodingError &) {
        }

        auto res = *next;
        auto iter = next;
        return std::make_pair(res, ++iter);
    }

private:
    template <typename CharIterator>
    static uint8_t
    getNible(const CharIterator &curr_nible)
    {
        auto nible = *curr_nible;
        if ('0' <= nible && nible <= '9') return nible - '0';
        if ('a' <= nible && nible <= 'f') return nible - 'a' + 10;
        if ('A' <= nible && nible <= 'F') return nible - 'A' + 10;
        throw DecodingError();
    }
};

template <int orig_char, int new_char>
class ReplaceChar
{
public:
    template <typename CharIterator>
    static std::pair<typename CharIterator::value_type, CharIterator>
    getValueAndNextIter(const CharIterator &next, const CharIterator &)
    {
        auto res = *next;
        if (res == orig_char) res = new_char;
        auto iter = next;
        return std::make_pair(res, ++iter);
    }
};

template <typename Continer>
class ReplaceSubContiners
{
public:
    void
    init(const Continer *src, const Continer *dst)
    {
        orig_data = src;
        new_data = dst;
        curr_iter = new_data->end();
    }

    template <typename CharIterator>
    std::pair<typename CharIterator::value_type, CharIterator>
    getValueAndNextIter(const CharIterator &next, const CharIterator &end)
    {
        if (curr_iter != new_data->end()) {
            return getNextInternalValue(next);
        }

        auto iter = next;
        for (auto curr_elem = orig_data->begin(); curr_elem != orig_data->end(); ++curr_elem, ++iter) {
            if (iter == end || *iter != *curr_elem) {
                iter = next;
                auto res = *iter;
                return std::make_pair(res, ++iter);
            }
        }

        curr_iter = new_data->begin();
        return getNextInternalValue(next);
    }

    bool operator==(const ReplaceSubContiners &other) const { return offset == other.offset; }

private:
    template <typename CharIterator>
    std::pair<typename CharIterator::value_type, CharIterator>
    getNextInternalValue(const CharIterator &next)
    {
        auto return_value = *curr_iter;
        ++curr_iter;
        ++offset;
        if (curr_iter != new_data->end()) return std::make_pair(return_value, next);
        offset = 0;
        auto iter = next;
        for (auto curr_elem = orig_data->begin(); curr_elem != orig_data->end(); ++curr_elem, ++iter) {}
        return std::make_pair(return_value, iter);
    }

    const Continer *orig_data = nullptr;
    const Continer *new_data = nullptr;
    typename Continer::const_iterator curr_iter;
    uint offset = 0;
};

#endif // __VIRTUAL_MODIFIERS_H__
