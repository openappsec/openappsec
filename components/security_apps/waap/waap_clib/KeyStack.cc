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
    :m_name(name), m_nameDepth(0) {
}

void KeyStack::push(const char* subkey, size_t subkeySize, bool countDepth) {
    m_stack.push_back(m_key.size());

    // Prefix all subkeys (except the first) with '.'
    if (!m_key.empty()) {
        m_key += '.';
    }

    m_key += std::string(subkey, subkeySize);

    if (countDepth) {
        m_nameDepth++;
    }

    dbgTrace(D_WAAP) << "KeyStack(" << m_name << ")::push(): '" << std::string(subkey, subkeySize) <<
        "' => full_key='" << std::string(m_key.data(), m_key.size()) << "'";
}

void KeyStack::pop(const char* log, bool countDepth) {
    // Keep depth balanced even if m_key[] buffer is full
    if (m_key.empty() || m_stack.empty()) {
        dbgDebug(D_WAAP) << "KeyStack(" << m_name << ")::pop(): [ERROR] ATTEMPT TO POP FROM EMPTY KEY STACK! " << log;
        return;
    }

    if (countDepth) {
        m_nameDepth--;
    }

    // Remove last subkey.
    m_key.erase(m_stack.back());
    m_stack.pop_back();
    dbgTrace(D_WAAP) << "KeyStack(" << m_name << ")::pop(): full_key='" <<
        std::string(m_key.data(), (int)m_key.size()) << "': pop_key=" << log << "'";
}
