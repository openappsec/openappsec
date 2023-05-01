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

#ifndef __WAAP_REGEX_PRECONDITIONS_H__
#define __WAAP_REGEX_PRECONDITIONS_H__

#include "picojson.h"
#include "pm_hook.h"
#include "i_pm_scan.h"
#include <map>
#include <set>
#include <stdint.h>
#include <string>

namespace Waap {
    class RegexPreconditions
    {
    public:
        typedef size_t WordIndex;
        static const WordIndex emptyWordIndex; // special word index used to index the "impossible" empty word
    private:
        // Maps regex pattern string to Aho-Coraick pattern matcher word
        typedef std::unordered_map<std::string, WordIndex> RegexToWordMap;
        // Maps Aho-Corasick pattern word to list of "prefixes" (special tags used to implement OR and AND semantics)
        typedef std::unordered_map<WordIndex, std::vector<WordIndex>> WordToPrefixSet;
        typedef std::unordered_map<WordIndex, std::vector<std::pair<WordIndex, size_t>>> WordToPrefixGroup;
    public:
        typedef std::unordered_set<WordIndex> PmWordSet;

        // The constructor builds internal data from Json object. Once built - the object becomes read-only.
        RegexPreconditions(const picojson::value::object &jsObj, bool &error);
        bool isNoRegexPattern(const std::string &pattern) const;
        const std::string &getWordStrByWordIndex(WordIndex wordIndex) const;
        Waap::RegexPreconditions::WordIndex getWordByRegex(const std::string &pattern) const;
        // Run aho-corasick scan on a sample followed by "set" and "and_condition" rules. Returns set of words
        // that can be used to speed up following calls to Regex::findAllMatches() on the same sample.
        void pmScan(Buffer &&buffer, RegexPreconditions::PmWordSet &allSets) const;

    private:
        void processWord(RegexPreconditions::PmWordSet &wordsSet, WordIndex wordIndex) const;
        void pass1(RegexPreconditions::PmWordSet &wordsSet, Buffer &&buffer) const;
        void pass2(RegexPreconditions::PmWordSet &wordsSet) const;

        RegexToWordMap m_regexToWordMap;
        // For each aho-corasick word - hold a list of "prefixes" which are in OR relationship between them (at least
        // one must match in order to trigger a condition on a prefix)
        WordToPrefixSet m_wordToPrefixSet;
        // For each aho-corasick word - hold a list of "prefixes" which are in AND relationship between them (all must
        // be detected in order to trigger a condition on a prefix)
        WordToPrefixGroup m_wordToPrefixGroup;
        // Aho-Corasick pattern matcher object
        PMHook m_pmHook;

        struct WordInfo {
            WordIndex napostNapreWordIndex;
            WordIndex napostWordIndex;
            WordIndex napreWordIndex;
            WordIndex baseWordIndex;
            std::string wordStr;
            bool      noRegex;

            WordInfo()
            :
            napostNapreWordIndex(emptyWordIndex),
            napostWordIndex(emptyWordIndex),
            napreWordIndex(emptyWordIndex),
            baseWordIndex(0),
            wordStr(),
            noRegex(false)
            {
            }
        };

        WordIndex registerWord(const std::string &wordStr);
        std::vector<WordInfo> m_pmWordInfo;
        std::map<std::string, WordIndex> m_wordStrToIndex; // TODO:: remove this into throwaway object, no need to keep
        std::set<std::string> m_noRegexPatterns; // patterns that require no regex matching (Aho Corasick is enough)
    };
}

#endif // __WAAP_REGEX_PRECONDITIONS_H__
