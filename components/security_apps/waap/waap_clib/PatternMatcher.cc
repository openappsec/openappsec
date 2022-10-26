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
#include "PatternMatcher.h"
#include "Waf2Regex.h"
#include <string>
#include <boost/algorithm/string.hpp>
#include <fnmatch.h>
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP);

// PatternMatcherWildcard implementation
PatternMatcherWildcard::PatternMatcherWildcard(const std::string &pattern)
:m_pattern(pattern) {
    dbgTrace(D_WAAP) << "Compiled pattern: '" << m_pattern.c_str() << "'\n";
}

bool PatternMatcherWildcard::match(const std::string &value) const {
    // Use unix filename (glob) string pattern matcher.
    // The Unix fnmatch() function only returns 0 in case of a succesful match.
    // In case no-match it returns FNM_NOMATCH constant.
    // In case of error it returns other non-zero return values.
    // However, in our usage here error is considered a "no-match".
    return ::fnmatch(m_pattern.c_str(), value.c_str(), 0) == 0;
}

// PatternMatcherRegex implementation
PatternMatcherRegex::PatternMatcherRegex(const std::string &pattern)
:m_pattern(pattern), m_regexError(false), m_regex(pattern, m_regexError, "patternMatcherRegex_" + pattern) {
    if (m_regexError) {
        dbgWarning(D_WAAP) << "Failed compiling regex pattern: '" << m_pattern.c_str() << "'\n";
    }
}

bool PatternMatcherRegex::match(const std::string &value) const {
    if (m_regexError) {
        return false;
    }

    return m_regex.hasMatch(value);
}
