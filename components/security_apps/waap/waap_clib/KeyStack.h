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

#ifndef __KEYSTACK_H__0a8039e6
#define __KEYSTACK_H__0a8039e6

#include <stddef.h>
#include <string>
#include <vector>

// Represent string (key) that is concatenation of  substrings (subkeys) separated by '.' character.
// Mostly emulates API of C++ std::string class, with addition of push() and pop() methods
// that append individual subkey and delete last subkey from the string efficiently.
// Uses fixed buffer for performance with fallback to dynamic string for long keys.
class KeyStack {
public:
    KeyStack(const char *name);
    void push(const char *subkey, size_t subkeySize, bool countDepth=true);
    void pop(const char* log, bool countDepth=true);
    bool empty() const { return m_using_buffer ? m_positions.empty() : m_fallback_key.empty(); }
    void clear();
    void print(std::ostream &os) const;
    size_t depth() const { return m_nameDepth; }
    size_t size() const;
    const char *c_str() const;
    const std::string str() const;
    const std::string first() const;

private:
    static const size_t MAX_KEY_SIZE = 1024;

    const char *m_name;
    int m_nameDepth;

    // Fixed buffer approach for common case (fast path)
    char m_buffer[MAX_KEY_SIZE];
    std::vector<size_t> m_positions;    // Start positions of each subkey in buffer
    std::vector<size_t> m_lengths;      // Length of each subkey
    size_t m_total_length;
    bool m_using_buffer;

    // Fallback to dynamic approach for long keys (slow path)
    std::string m_fallback_key;
    std::vector<size_t> m_fallback_stack;

    // Caching for frequently accessed methods
    mutable std::string m_cached_str;
    mutable std::string m_cached_first;
    mutable bool m_str_cache_valid;
    mutable bool m_first_cache_valid;

    // Helper methods
    void switch_to_fallback();
    void rebuild_buffer_from_fallback();
    bool can_fit_in_buffer(size_t additional_size) const;
    void invalidate_cache();
};

#endif // __KEYSTACK_H__0a8039e6
