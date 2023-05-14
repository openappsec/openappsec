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

#ifndef __WAF2_REGEX_H__c31bc34a
#define __WAF2_REGEX_H__c31bc34a

// Note: good usage reference found here: http://codegists.com/snippet/c/pcre2_matchcpp_neurobin_c
// and also here https://svn.apache.org/repos/asf/httpd/httpd/trunk/server/util_pcre.c

#define PCRE2_CODE_UNIT_WIDTH 8
#include "Waf2Util.h"
#include "WaapRegexPreconditions.h"
#include <pcre2.h>
#include <string>
#include <vector>
#include <boost/noncopyable.hpp>

struct RegexMatch {
    struct MatchGroup {
        uint16_t index;
        std::string name;
        std::string value;

        MatchGroup(uint16_t index, const std::string &name, const std::string &value)
        :index(index), name(name), value(value) {
        }
    };

    std::vector<MatchGroup> groups;
};

struct RegexMatchRange {
    PCRE2_SIZE start;
    PCRE2_SIZE end;
// LCOV_EXCL_START Reason: coverage upgrade
    RegexMatchRange() {}
// LCOV_EXCL_STOP
    RegexMatchRange(PCRE2_SIZE start, PCRE2_SIZE end):start(start), end(end) {}
};

class SingleRegex : public boost::noncopyable {
friend class Regex;
public:
    SingleRegex(const std::string &pattern, bool &error, const std::string &regexName, bool bNoRegex=false,
        const std::string &regexMatchName="", const std::string &regexMatchValue="");
    ~SingleRegex();
    bool hasMatch(const std::string &s) const;
    size_t findAllMatches(const std::string &s, std::vector<RegexMatch> &matches,
            size_t max_matches = std::string::npos) const;
    size_t findMatchRanges(const std::string &s, std::vector<RegexMatchRange> &matchRanges) const;
    const std::string &getName() const;
private:
    pcre2_code *m_re;
    pcre2_match_data *m_matchData;
    uint32_t m_captureGroupsCount;
    std::vector<std::string> m_captureNames; // capture index => name translation (unnamed items are empty strings)
    std::string m_regexName;
    bool m_noRegex;
    std::string m_regexMatchName;
    std::string m_regexMatchValue;
};

class Regex : public boost::noncopyable {
public:
    Regex(const std::string &pattern, bool &error, const std::string &regexName);
    Regex(const std::vector<std::string> &patterns, bool &error, const std::string &regexName,
        std::shared_ptr<Waap::RegexPreconditions> regexPreconditions);
    ~Regex();
    bool hasMatch(const std::string &s) const;
    size_t findAllMatches(const std::string &v, std::vector<RegexMatch> &matches,
        const Waap::RegexPreconditions::PmWordSet *pmWordSet=nullptr, size_t max_matches = std::string::npos) const;
    std::string sub(const std::string &s, const std::string &repl="") const;
    // Run regex search, and for each found match - run callback.
    // The callback can cancel replacement of the match (leave source match "as-is"), provide a replacement string,
    // or delete the match (replace with empty string).
    // The "decodedCount" counts match replacement events and the "deletedCount" counts match deletion events.
    void sub(
        const std::string &s,
        Waap::Util::RegexSubCallback_f cb,
        int &decodedCount,
        int &deletedCount,
        std::string &outStr) const;
    const std::string &getName() const;
private:
    std::vector<SingleRegex*> m_sre;
    std::string m_regexName;
    std::shared_ptr<Waap::RegexPreconditions> m_regexPreconditions;
    std::unordered_map<Waap::RegexPreconditions::WordIndex, std::vector<size_t>> m_wordToRegexIndices;
};

#endif // __WAF2_REGEX_H__c31bc34a
