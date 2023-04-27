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

#include "WaapRegexPreconditions.h"
#include "Waf2Util.h"
#include "debug.h"
#include <boost/algorithm/string/predicate.hpp>

USE_DEBUG_FLAG(D_WAAP_REGEX);

namespace Waap {
    const RegexPreconditions::WordIndex RegexPreconditions::emptyWordIndex = 0;

    RegexPreconditions::RegexPreconditions(const picojson::value::object &jsObj, bool &error)
    {
        // Register empty string work under known index
        registerWord("");

        // The key should always be there unless data file is corrupted (but there's a unit test that tests exactly
        // that!)
        if (jsObj.find("preconditions") == jsObj.end()) {
            dbgError(D_WAAP_REGEX) << "Error loading regex preconditions (signatures data file corrupt?)...";
            error = true;
            return;
        }

        if (jsObj.find("precondition_keys") == jsObj.end()) {
            dbgError(D_WAAP_REGEX) << "Error loading regex precondition sets (signatures data file corrupt?)...";
            error = true;
            return;
        }

        auto preconditions = jsObj.at("preconditions").get<picojson::value::object>();

        // Loop over pre-conditions (rules) and load them
        dbgTrace(D_WAAP_REGEX) << "Loading regex preconditions...";

        for (const auto &precondition : preconditions)
        {
            // Each precondition consists of an aho-corasick pattern matcher word as a key and list of actions
            // (for that word) - as a value.
            const std::string wordStr = precondition.first;

            // Information from the "empty string"" word is not required by the engine to operate
            if (wordStr.empty()) {
                continue;
            }

            WordIndex wordIndex = registerWord(wordStr);

            if (boost::algorithm::ends_with(wordStr, "_napost_napre")) {
                WordIndex baseWordIndex = registerWord(wordStr.substr(0, wordStr.size() - strlen("_napost_napre")));
                m_pmWordInfo[baseWordIndex].napostNapreWordIndex = wordIndex;
                m_pmWordInfo[wordIndex].baseWordIndex = baseWordIndex;
            }
            else if (boost::algorithm::ends_with(wordStr, "_napost")) {
                WordIndex baseWordIndex = registerWord(wordStr.substr(0, wordStr.size() - strlen("_napost")));
                m_pmWordInfo[baseWordIndex].napostWordIndex = wordIndex;
                m_pmWordInfo[wordIndex].baseWordIndex = baseWordIndex;
            }
            else if (boost::algorithm::ends_with(wordStr, "_napre")) {
                WordIndex baseWordIndex = registerWord(wordStr.substr(0, wordStr.size() - strlen("_napre")));
                m_pmWordInfo[baseWordIndex].napreWordIndex = wordIndex;
                m_pmWordInfo[wordIndex].baseWordIndex = baseWordIndex;
            }

            // Load actions
            const auto &jsActionsList = precondition.second.get<picojson::value::array>();

            for (const auto &jsAction : jsActionsList) {
                const auto &action = jsAction.get<picojson::value::array>();

                if (action.empty()) {
                    continue;
                }

                // The first item in the Action json object (it's a tuple of 1 or more items) is an action type string.
                const std::string actionType = action[0].get<std::string>();

                // There are currently three action types:
                //  1. "regex" - allow specific regex to be scanned when the Aho-Corasick word is detected
                //  2. "set" - specify another "prefix" (string) to be enabled when the Aho-Corasick word is detected.
                //             if at least one prefix is enabled - it will trigger one or more other regexes.
                //  3. "and_condition" - specify (comma-separated) sorted list of "prefixes" (in one string).
                //             all of these prefixes should come together in order to complete a set to match a
                //             condition and enable one or more other regexes.
                if (actionType == "regex" && action.size() >= 3) {
                    const std::string regexPattern = action[1].get<std::string>();
                    if (m_regexToWordMap.find(regexPattern) != m_regexToWordMap.end() &&
                            m_regexToWordMap[regexPattern] != wordIndex)
                    {
                        dbgError(D_WAAP_REGEX) << "ERROR: trying to overwrite m_regexToWordMap. pattern='" <<
                            regexPattern << "'. Old wordIndex='" << m_regexToWordMap[regexPattern] << "' new word='"
                            << wordStr << "' (wordIndex=" << wordIndex << ")";
                        error = true;
                        return;
                    }

                    std::string flags = action[2].get<std::string>();

                    if (flags == "_noregex") {
                        // Add regex pattern to set of "noRegex" patterns
                        m_noRegexPatterns.insert(regexPattern);
                        m_pmWordInfo[wordIndex].noRegex = true;
                    }

                    m_regexToWordMap[regexPattern] = wordIndex;
                }
                else if (actionType == "set" && action.size() >= 2) {
                    const std::string setValueStr = action[1].get<std::string>();
                    WordIndex setValueIndex = registerWord(setValueStr);
                    std::vector<WordIndex> &prefixSet = m_wordToPrefixSet[wordIndex];
                    if (std::find(prefixSet.begin(), prefixSet.end(),
                            setValueIndex) == prefixSet.end()) {
                        prefixSet.push_back(setValueIndex);
                    }
                }
                else if (actionType == "and_condition" && action.size() >= 2) {
                    const std::string groupValueStr = action[1].get<std::string>();
                    WordIndex groupValueIndex = registerWord(groupValueStr);
                    size_t expectedCount = static_cast<size_t>(std::stoi(groupValueStr));
                    auto value(std::make_pair(groupValueIndex, expectedCount));
                    std::vector<std::pair<WordIndex, size_t>> &prefixGroup = m_wordToPrefixGroup[wordIndex];
                    if (std::find(prefixGroup.begin(), prefixGroup.end(),
                            value) == prefixGroup.end()) {
                        prefixGroup.push_back(value);
                    }
                }
            }
        }

        // Build full list of words to load into aho-corasick pattern matcher
        dbgTrace(D_WAAP_REGEX) << "Loading regex precondition_keys into Aho-Corasick pattern matcher...";

        auto preconditionKeys = jsObj.at("precondition_keys").get<picojson::value::array>();
        std::set<PMPattern> pmPatterns;

        for (const auto &preconditionKey : preconditionKeys) {
            std::string wordStr(preconditionKey.get<std::string>());

            // Do not load the "empty" word into Aho-Corasick. It's meaningless and Aho prepare() call would fail.
            if (wordStr.empty()) {
                continue;
            }

            WordIndex wordIndex = registerWord(wordStr);
            WordIndex napreWordIndex = m_pmWordInfo[wordIndex].napreWordIndex;
            WordIndex napostWordIndex = m_pmWordInfo[wordIndex].napostWordIndex;
            WordIndex napostNapreWordIndex = m_pmWordInfo[wordIndex].napostNapreWordIndex;

            bool noRegex = ((napreWordIndex != emptyWordIndex) && m_pmWordInfo[napreWordIndex].noRegex) ||
                    ((napostWordIndex != emptyWordIndex) && m_pmWordInfo[napostWordIndex].noRegex) ||
                    ((napostNapreWordIndex != emptyWordIndex) && m_pmWordInfo[napostNapreWordIndex].noRegex);

            pmPatterns.insert(PMPattern(wordStr, false, false, wordIndex, noRegex));
        }

        // Initialize the aho-corasick pattern matcher with the patterns
        Maybe<void> pmHookStatus = m_pmHook.prepare(pmPatterns);

        if (!pmHookStatus.ok()) {
            dbgError(D_WAAP_REGEX) << "Aho-Corasick engine failed to load!";
            error = true;
            return;
        }

        dbgTrace(D_WAAP_REGEX) << "Aho-Corasick engine loaded.";

        dbgTrace(D_WAAP_REGEX) << "Aho-corasick pattern matching engine initialized!";
    }

    bool Waap::RegexPreconditions::isNoRegexPattern(const std::string &pattern) const
    {
        return m_noRegexPatterns.find(pattern) != m_noRegexPatterns.end();
    }

    const std::string &Waap::RegexPreconditions::getWordStrByWordIndex(WordIndex wordIndex) const
    {
        WordIndex baseWordIndex = m_pmWordInfo[wordIndex].baseWordIndex;

        if (baseWordIndex != Waap::RegexPreconditions::emptyWordIndex) {
            return m_pmWordInfo[baseWordIndex].wordStr;
        }

        return m_pmWordInfo[wordIndex].wordStr;
    }

    // Check that the regex pattern (string) is known to be related to an Aho-Corasick word/prefix
    // Returns empty string if not found, or the Aho-Corasick/prefix string otherwise.
    // This function is called during each Regex object creation and helps to pre-compute data required for a fast
    // lookup later during traffic processing.
    Waap::RegexPreconditions::WordIndex RegexPreconditions::getWordByRegex(const std::string &regexPattern) const
    {
        const auto &found = m_regexToWordMap.find(regexPattern);

        if (found != m_regexToWordMap.end()) {
            return found->second;
        }

        return Waap::RegexPreconditions::emptyWordIndex;
    }

    void RegexPreconditions::processWord(RegexPreconditions::PmWordSet &wordsSet, WordIndex wordIndex) const
    {
        const auto &found = m_wordToPrefixSet.find(wordIndex);

        if (found != m_wordToPrefixSet.end()) {
            for (const auto &prefixIndex : found->second) {
                // One of the items in the "OR" condition - add the OR prefix to the wordsSet
                wordsSet.insert(prefixIndex);
            }
        }

        // Add words from the Aho Corasick scanner
        wordsSet.insert(wordIndex);
    }

    inline bool isRegexWordChar(u_char c) {
        return Waap::Util::isAlphaAsciiFast(c) || isdigit(c) || '_' == c;
    }

    void RegexPreconditions::pass1(RegexPreconditions::PmWordSet &wordsSet, Buffer &&buffer) const
    {
        dbgTrace(D_WAAP_REGEX) << "Rules pass #1: collect OR sets";

        m_pmHook.scanBufWithOffsetLambda(buffer, [this, &wordsSet, &buffer]
            (u_int endMatchOffset, const PMPattern &pmPattern, bool matchAll)
        {
            uint offset = endMatchOffset + 1 - pmPattern.size(); // reported offset points to last character of a match

            // Extract the word index from the PMPattern object (we do not need the string part of it)
            WordIndex wordIndex = pmPattern.getIndex();

            bool regexWordBefore = !matchAll && (offset != 0) &&
                    (isRegexWordChar(buffer.data()[offset - 1]));
            bool regexWordAfter = !matchAll && (offset + pmPattern.size() < buffer.size()) &&
                    (isRegexWordChar(buffer.data()[offset + pmPattern.size()]));

            processWord(wordsSet, wordIndex);

            // Compute additional constraints ([!\w] before, [!\w] after, [!\w] aroung the match ...)
            WordIndex napreWordIndex = m_pmWordInfo[wordIndex].napreWordIndex;
            WordIndex napostWordIndex = m_pmWordInfo[wordIndex].napostWordIndex;
            WordIndex napostNapreWordIndex = m_pmWordInfo[wordIndex].napostNapreWordIndex;

            if (!regexWordBefore && regexWordAfter) {
                if (napreWordIndex != emptyWordIndex) {
                    processWord(wordsSet, napreWordIndex);
                }
            }
            else if (regexWordBefore && !regexWordAfter) {
                if (napostWordIndex != emptyWordIndex) {
                    processWord(wordsSet, napostWordIndex);
                }
            }
            else if (!regexWordBefore && !regexWordAfter) {
                if (napreWordIndex != emptyWordIndex) {
                    processWord(wordsSet, napreWordIndex);
                }

                if (napostWordIndex != emptyWordIndex) {
                    processWord(wordsSet, napostWordIndex);
                }

                if (napostNapreWordIndex != emptyWordIndex) {
                    processWord(wordsSet, napostNapreWordIndex);
                }
            }
        });
    }

    void RegexPreconditions::pass2(RegexPreconditions::PmWordSet &wordsSet) const
    {
        dbgTrace(D_WAAP_REGEX) << "Rules pass #2: collect AND groups";

        std::unordered_map<WordIndex, std::set<WordIndex>> allGroups;
        std::vector<WordIndex> prefixes;

        for (WordIndex wordIndex : wordsSet) {
            // find in wordToPrefixGroup map
            const auto &found = m_wordToPrefixGroup.find(wordIndex);

            if (found != m_wordToPrefixGroup.end()) {
                for (const auto &prefixCountPair : found->second) {
                    WordIndex prefixIndex = prefixCountPair.first;
                    size_t expectedCount = prefixCountPair.second;

                    auto found = allGroups.find(prefixIndex);
                    size_t actualWordCount = 1;

                    if (found == allGroups.end()) {
                        allGroups.emplace(prefixIndex, std::set<WordIndex>{wordIndex});
                    }
                    else {
                        found->second.insert(wordIndex);
                        actualWordCount = found->second.size();
                    }

                    if (actualWordCount == expectedCount) {
                        // Full "AND" condition collected succesfully - add the AND prefixCountPair to the wordsSet
                        prefixes.push_back(prefixIndex);
                    }
                }
            }
        }

        for (const auto &prefixIndex : prefixes) {
            wordsSet.insert(prefixIndex);
        }
    }

    // This function scans the buffer with Aho-Corasick scanner and adds all the words found into wordsSet
    // It then continues and runs two pass algorithm to compute OR and AND conditions over a prefixes data.
    // The prefix strings are also added to the wordsSet and are looked up in the same database.
    void RegexPreconditions::pmScan(Buffer &&buffer, RegexPreconditions::PmWordSet &wordsSet) const
    {
        wordsSet.clear();
        pass1(wordsSet, std::move(buffer));
        pass2(wordsSet);
        // The empty string key contains all regexes that should always be scanned
        wordsSet.insert(Waap::RegexPreconditions::emptyWordIndex);
    }

    // Get known wordIndex by wordStr, or allocate a new wordIndex for words yet unknown
    Waap::RegexPreconditions::WordIndex RegexPreconditions::registerWord(const std::string &wordStr)
    {
        const auto &found = m_wordStrToIndex.find(wordStr);
        if (found != m_wordStrToIndex.end()) {
            return found->second;
        }
        else {
            WordIndex wordIndex = m_pmWordInfo.size();
            m_wordStrToIndex[wordStr] = wordIndex; // index of the new element that will be added below...
            WordInfo wordInfo;
            wordInfo.wordStr = wordStr;
            m_pmWordInfo.push_back(wordInfo);
            return wordIndex;
        }
    }
}
