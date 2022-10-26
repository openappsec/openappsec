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
class KeyStack {
public:
    KeyStack(const char *name);
    void push(const char *subkey, size_t subkeySize, bool countDepth=true);
    void pop(const char* log, bool countDepth=true);
    bool empty() const { return m_key.empty(); }
    void clear() { m_key.clear(); m_stack.clear(); }
    size_t depth() const { return m_nameDepth; }
    size_t size() const {
        return str().size();
    }
    const char *c_str() const {
        // If pushed none - return empty string.
        // If pushed once - still return empty string (the once-pushed subkey will only be returned
        //                  by the first() method.
        // If pushed twice or more - return all subkeys starting from the second one.
        // Also, even if pushed 2 or more times, but pushed empty strings as subkeys,
        // then it could happen that m_key is still empty, in which case we should still return empty string.
        if (m_stack.size() <= 1 || m_stack[1] + 1 >= m_key.size()) {
            return "";
        }

        return m_key.c_str() + m_stack[1] + 1;
    }
    const std::string str() const {
        // If pushed none - return empty string.
        // If pushed once - still return empty string (the once-pushed subkey will only be returned
        //                  by the first() method.
        // If pushed twice or more - return all subkeys starting from the second one.
        // Also, even if pushed 2 or more times, but pushed empty strings as subkeys,
        // then it could happen that m_key is still empty, in which case we should still return empty string.
        if (m_stack.size() <= 1 || m_stack[1] + 1 >= m_key.size()) {
            return "";
        }

        return m_key.substr(m_stack[1] + 1);
    }
    const std::string first() const {
        if (m_stack.size() == 0) {
            return "";
        }
        else if (m_stack.size() == 1) {
            return m_key;
        }
        else {
            // m_stack.size() > 1, so m_stack[1] is valid
            return m_key.substr(0, m_stack[1]);
        }
    }
private:
    const char *m_name;
    std::string m_key;
    std::vector<size_t> m_stack;    // position of individual key name starts in m_key,
                                    // used to backtrack 1 key at a time.
    int m_nameDepth;
};

#endif // __KEYSTACK_H__0a8039e6
