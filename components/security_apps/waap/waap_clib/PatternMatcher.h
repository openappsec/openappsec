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

#ifndef __PATTERN_MATCHER_H__9baf179a
#define __PATTERN_MATCHER_H__9baf179a

#include "Waf2Regex.h"
#include <vector>
#include <string>
#include <memory>

class PatternMatcherBase {
public:
    virtual bool match(const std::string &value) const =0;
};

class PatternMatcherWildcard : public PatternMatcherBase {
public:
    PatternMatcherWildcard(const std::string &pattern);
    virtual bool match(const std::string &value) const;
private:
    std::string m_pattern;
};

class PatternMatcherRegex : public PatternMatcherBase {
public:
    PatternMatcherRegex(const std::string &pattern);
    virtual bool match(const std::string &value) const;
private:
    std::string m_pattern;
    bool m_regexError;
    Regex m_regex;
};

typedef std::shared_ptr<PatternMatcherBase> PatternMatcherBasePtr;

#endif // __PATTERN_MATCHER_H__9baf179a
