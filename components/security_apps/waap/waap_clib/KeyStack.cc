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

// #define WAF2_LOGGING_ENABLE
#include "debug.h"
#include "KeyStack.h"
#include <string.h>
#include "assert.h"

USE_DEBUG_FLAG(D_WAAP);

KeyStack::KeyStack(const char* name)
    :m_name(name), m_nameDepth(0), m_total_length(0), m_using_buffer(true),
    m_str_cache_valid(false), m_first_cache_valid(false) {
    m_buffer[0] = '\0';
    m_positions.reserve(16);  // Reserve reasonable capacity
    m_lengths.reserve(16);
    m_fallback_stack.reserve(16);
}

void
KeyStack::push(const char *subkey, size_t subkeySize, bool countDepth)
{
    bool dot_needed = !m_positions.empty() && subkey != nullptr && subkeySize > 0;
    if (m_using_buffer) {
        // Calculate space needed: subkey + dot (if not first) + null terminator
        size_t dot_size = dot_needed ? 1 : 0;
        size_t needed_space = subkeySize + dot_size + 1; // +1 for null terminator

        if (can_fit_in_buffer(needed_space)) {
            // Fast path: use fixed buffer
            if (dot_needed) {
                m_buffer[m_total_length] = '.';
                m_total_length++;
            }

            m_positions.push_back(m_total_length);
            m_lengths.push_back(subkeySize);

            memcpy(m_buffer + m_total_length, subkey, subkeySize);
            m_total_length += subkeySize;
            m_buffer[m_total_length] = '\0';
        } else {
            // Switch to fallback mode
            switch_to_fallback();
            // Continue with fallback logic below
        }
    }

    if (!m_using_buffer) {
        // Slow path: use dynamic string
        m_fallback_stack.push_back(m_fallback_key.size());

        if (dot_needed) {
            m_fallback_key.append(1, '.');
        }
        m_fallback_key.append(subkey, subkeySize);
    }

    if (countDepth) {
        m_nameDepth++;
    }

    // Invalidate cache since key structure changed
    invalidate_cache();

    dbgTrace(D_WAAP)
        << "KeyStack("
        << m_name
        << ")::push(): '"
        << std::string(subkey, subkeySize)
        << "' => full_key='"
        << c_str()
        << "'";
}

void KeyStack::pop(const char* log, bool countDepth) {
    if (m_using_buffer) {
        if (m_positions.empty()) {
            dbgDebug(D_WAAP)
                << "KeyStack("
                << m_name
                << ")::pop(): [ERROR] ATTEMPT TO POP FROM EMPTY KEY STACK! "
                << log;
            return;
        }

        // Remove last subkey from buffer
        m_total_length = m_positions.back();
        // Only remove dot if:
        // 1. There are multiple elements (not the first)
        // 2. The element being popped had content (length > 0, meaning a dot was added)
        // 3. The character before current position is actually a dot (safety check)
        if (m_positions.size() > 1 && m_lengths.back() > 0) {
            if (m_total_length > 0 && m_buffer[m_total_length - 1] == '.') {
                m_total_length -= 1; // Remove the dot
            }
        } else if (m_positions.size() == 1) {
            m_total_length = 0; // First element, no dot to remove
        }

        m_positions.pop_back();
        m_lengths.pop_back();
        m_buffer[m_total_length] = '\0';
    } else {
        // Fallback mode
        if (m_fallback_key.empty() || m_fallback_stack.empty()) {
            dbgDebug(D_WAAP)
                << "KeyStack("
                << m_name
                << ")::pop(): [ERROR] ATTEMPT TO POP FROM EMPTY KEY STACK! "
                << log;
            return;
        }

        // Remove last subkey
        m_fallback_key.erase(m_fallback_stack.back());
        m_fallback_stack.pop_back();

        // Try to switch back to buffer if possible
        if (m_fallback_key.size() + 1 < MAX_KEY_SIZE) {
            rebuild_buffer_from_fallback();
        }
    }

    if (countDepth) {
        m_nameDepth--;
    }

    // Invalidate cache since key structure changed
    invalidate_cache();

    dbgTrace(D_WAAP)
        << "KeyStack("
        << m_name
        << ")::pop(): full_key='"
        << c_str()
        << "': pop_key="
        << log
        << "'";
}

void KeyStack::print(std::ostream &os) const
{
    os
        << "KeyStack("
        << m_name
        << ")::show(): full_key='"
        << c_str()
        << "'";
}

void KeyStack::clear() {
    if (m_using_buffer) {
        m_positions.clear();
        m_lengths.clear();
        m_total_length = 0;
        m_buffer[0] = '\0';
    } else {
        m_fallback_key.clear();
        m_fallback_stack.clear();
        m_using_buffer = true;
        m_total_length = 0;
        m_buffer[0] = '\0';
    }
    m_nameDepth = 0;
    invalidate_cache();
}

size_t KeyStack::size() const {
    if (m_using_buffer) {
        if (m_positions.size() <= 1 || m_positions[1] >= m_total_length) {
            // No second element or second element has no content
            return 0;
        }
        // Return size from second subkey onwards
        return m_total_length - m_positions[1];
    } else {
        // Fallback mode
        if (m_fallback_stack.size() <= 1) {
            return 0;
        }
        // m_fallback_stack[1] points to the dot preceding the 2nd subkey.
        // Exclude the dot itself from the reported size.
        if (m_fallback_stack[1] + 1 >= m_fallback_key.size()) {
            return 0; // Defensive: nothing after the dot
        }
        return m_fallback_key.size() - (m_fallback_stack[1] + 1);
    }
}

const char* KeyStack::c_str() const {
    if (m_using_buffer) {
        if (m_positions.size() <= 1 || m_positions[1] >= m_total_length) {
            // No second element or second element has no content
            return "";
        }
        // Return pointer to second subkey (skip first + dot)
        return m_buffer + m_positions[1];
    } else {
        // Fallback mode
        if (m_fallback_stack.size() <= 1) {
            return "";
        }
        // m_fallback_stack[1] points to the dot. Skip it for consistency with buffer mode.
        static thread_local std::string temp_result;
        size_t start = m_fallback_stack[1] + 1;
        if (start >= m_fallback_key.size()) {
            temp_result.clear();
        } else {
            temp_result = m_fallback_key.substr(start);
        }
        return temp_result.c_str();
    }
}

const std::string KeyStack::str() const {
    if (m_str_cache_valid) {
        return m_cached_str;
    }

    if (m_using_buffer) {
        if (m_positions.size() <= 1 || m_positions[1] >= m_total_length) {
            // No second element or second element has no content
            m_cached_str = std::string();
        } else {
            // Return string from second subkey onwards
            m_cached_str = std::string(m_buffer + m_positions[1], m_total_length - m_positions[1]);
        }
    } else {
        // Fallback mode
        if (m_fallback_stack.size() <= 1) {
            m_cached_str = std::string();
        } else {
            size_t start = m_fallback_stack[1] + 1; // Skip the dot
            if (start >= m_fallback_key.size()) {
                m_cached_str.clear();
            } else {
                m_cached_str = m_fallback_key.substr(start);
            }
        }
    }

    m_str_cache_valid = true;
    return m_cached_str;
}

const std::string KeyStack::first() const {
    if (m_first_cache_valid) {
        return m_cached_first;
    }

    if (m_using_buffer) {
        if (m_positions.empty()) {
            m_cached_first = std::string();
        } else if (m_positions.size() == 1) {
            // Only one subkey, return the whole buffer content
            m_cached_first = std::string(m_buffer, m_lengths[0]);
        } else {
            // Multiple subkeys, return first one
            m_cached_first = std::string(m_buffer + m_positions[0], m_lengths[0]);
        }
    } else {
        // Fallback mode
        if (m_fallback_stack.empty()) {
            m_cached_first = std::string();
        } else if (m_fallback_stack.size() == 1) {
            m_cached_first = m_fallback_key;
        } else {
            // m_fallback_stack[1] points to the dot; substring up to dot (exclude it)
            size_t dot_pos = m_fallback_stack[1];
            if (dot_pos == 0 || dot_pos > m_fallback_key.size()) {
                m_cached_first.clear();
            } else {
                m_cached_first = m_fallback_key.substr(0, dot_pos);
            }
        }
    }

    m_first_cache_valid = true;
    return m_cached_first;
}

bool KeyStack::can_fit_in_buffer(size_t additional_size) const {
    return (m_total_length + additional_size) < MAX_KEY_SIZE;
}

void KeyStack::switch_to_fallback() {
    // Copy buffer content to fallback string
    m_fallback_key.assign(m_buffer, m_total_length);

    // Convert positions to stack format used by fallback
    m_fallback_stack.clear();
    for (size_t i = 0; i < m_positions.size(); ++i) {
        if (i == 0) {
            m_fallback_stack.push_back(0);
        } else {
            // Position after dot
            m_fallback_stack.push_back(m_positions[i] - 1);
        }
    }

    m_using_buffer = false;
    invalidate_cache();
}void KeyStack::rebuild_buffer_from_fallback() {
    if (m_fallback_key.size() + 1 >= MAX_KEY_SIZE) {
        return; // Still too big for buffer
    }

    // Copy fallback content back to buffer
    memcpy(m_buffer, m_fallback_key.c_str(), m_fallback_key.size());
    m_total_length = m_fallback_key.size();
    m_buffer[m_total_length] = '\0';

    // Rebuild positions and lengths by parsing the buffer
    m_positions.clear();
    m_lengths.clear();

    size_t pos = 0;
    while (pos < m_total_length) {
        m_positions.push_back(pos);

        // Find length of current subkey
        size_t start = pos;
        while (pos < m_total_length && m_buffer[pos] != '.') {
            pos++;
        }
        m_lengths.push_back(pos - start);

        if (pos < m_total_length) {
            pos++; // Skip the dot
        }
    }

    // Clear fallback data
    m_fallback_key.clear();
    m_fallback_stack.clear();
    m_using_buffer = true;
    invalidate_cache();
}

void KeyStack::invalidate_cache() {
    m_str_cache_valid = false;
    m_first_cache_valid = false;
}
