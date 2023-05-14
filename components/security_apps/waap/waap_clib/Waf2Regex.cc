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

#include "Waf2Regex.h"
#include "debug.h"
#include <vector>
#include <algorithm>

USE_DEBUG_FLAG(D_WAAP_REGEX);

// SingleRegex

SingleRegex::SingleRegex(
    const std::string& pattern,
    bool& error,
    const std::string& regexName,
    bool bNoRegex,
    const std::string &regexMatchName,
    const std::string &regexMatchValue)
    :
    m_re(NULL),
    m_matchData(NULL),
    m_regexName(regexName),
    m_noRegex(bNoRegex),
    m_regexMatchName(regexMatchName),
    m_regexMatchValue(regexMatchValue)
    {
    dbgTrace(D_WAAP_REGEX) << "Create SingleRegex '" << m_regexName << "' PATTERN: '" <<
        std::string(pattern.data(), pattern.size()) << "'";

    if (error) {
        // Skip initialization if already in error condition
        dbgError(D_WAAP_REGEX) << "Skip compiling regex: " << m_regexName << " (single) due to previous error";
        return;
    }

    int errorCode;
    size_t errorOffset;
    m_re = pcre2_compile(
        reinterpret_cast<PCRE2_SPTR>(pattern.data()),
        pattern.size(),
        0,
        &errorCode,
        &errorOffset,
        NULL
    );

    if (pcre2_jit_compile(m_re, PCRE2_JIT_COMPLETE) < 0) {
        dbgError(D_WAAP_REGEX) << "pcre2_jit_compile failed for regex: " << m_regexName << " (single)";
        error = true;
    }

    if (m_re == NULL) {
        PCRE2_UCHAR errMessage[4096];
        pcre2_get_error_message(errorCode, errMessage, sizeof(errMessage));
        dbgError(D_WAAP_REGEX) << "pcre2_compile failed: error (" << errorCode << "), " << errMessage <<
            ", at offset " << errorOffset << " in pattern (single) of regex " << m_regexName << ".";
        dbgError(D_WAAP_REGEX) << "pattern: '" << pattern.c_str() << "'";
        error = true;
        return;
    }

    // Create matchData object that is ready to receive any possible match from m_re
    m_matchData = pcre2_match_data_create_from_pattern(m_re, NULL);

    if (m_matchData == NULL) {
        dbgError(D_WAAP_REGEX) << "pcre2_compile failed to allocate matchData. pattern: '" <<
            std::string(pattern.data(), pattern.size()) << "'";
        pcre2_code_free(m_re);
        m_re = NULL;
        return;
    }

    // Get info about compiled pattern
    pcre2_pattern_info(m_re, PCRE2_INFO_CAPTURECOUNT, &m_captureGroupsCount);
    PCRE2_SPTR nameTable;
    uint32_t nameCount;
    uint32_t nameEntrySize;
    pcre2_pattern_info(m_re, PCRE2_INFO_NAMECOUNT, &nameCount);
    pcre2_pattern_info(m_re, PCRE2_INFO_NAMEENTRYSIZE, &nameEntrySize);
    pcre2_pattern_info(m_re, PCRE2_INFO_NAMETABLE, &nameTable);

    // Allocate enough items for group names to be indexed by capture group index
    // Note that number capture groups are numbered starting from 1. Group "0" is for the "whole match"
    m_captureNames.resize(m_captureGroupsCount + 1);

    for (uint32_t i = 0; i < nameCount; i++) {
        PCRE2_SPTR nameTableEntry = nameTable + i * nameEntrySize;
        // According to pcre2 docs, each entry struct starts with 16-bit capture index (big-endian). Consume it.
        uint16_t captureIndex = (nameTableEntry[0] << 8) + nameTableEntry[1];
        // Note that capture group indices are numbered starting from 1. Group "0" is for the "whole match"
        nameTableEntry += sizeof(uint16_t);
        // After the index comes zero-terminated capture name. Consume it too.
        m_captureNames[captureIndex] = (char*)nameTableEntry;
    }
}

SingleRegex::~SingleRegex() {
    if (m_matchData) {
        pcre2_match_data_free(m_matchData);
    }

    if (m_re) {
        pcre2_code_free(m_re);
    }
}

bool SingleRegex::hasMatch(const std::string& s) const {
    int rc = pcre2_match(
        m_re, // code
        reinterpret_cast<PCRE2_SPTR>(s.data()), s.size(), // subject/subject length
        0, // start offset
        0, // options
        m_matchData,
        NULL // match_context
    );

    if (rc <= 0) {
        if (rc != PCRE2_ERROR_NOMATCH) {
            PCRE2_UCHAR errmsg[4096];
            pcre2_get_error_message(rc, errmsg, sizeof(errmsg) - 1);
            dbgDebug(D_WAAP_REGEX) << "SingleRegex['" << m_regexName << "']::hasMatch " <<
                "failed with error code: " << rc << " ('" << errmsg << "')";
        }
        return false;
    }

    return true;
}

size_t SingleRegex::findAllMatches(const std::string& s, std::vector<RegexMatch>& matches, size_t maxMatches) const {
    size_t matchesCount = 0;

    // Optimized regex that always immediately reports a "simulated" match without spending time to do a scan
    if (m_noRegex) {
        RegexMatch match;
        // Group 0 is "whole match" must always be present and have no name
        match.groups.push_back(
            RegexMatch::MatchGroup(
                1,
                "",
                m_regexMatchValue
            )
        );
        // Group 1 is "specific match" must be present and have a name
        match.groups.push_back(
            RegexMatch::MatchGroup(
                2,
                m_regexMatchName,
                m_regexMatchValue
            )
        );
        matches.push_back(match);
        matchesCount++;
        return matchesCount;
    }

    PCRE2_SIZE startOffset = 0;

    do {
        int rc = pcre2_match(
            m_re, // code
            reinterpret_cast<PCRE2_SPTR>(s.data()), s.size(), // subject/subject length
            startOffset, // start offset
            0, // options
            m_matchData,
            NULL // match_context
        );

        if (rc <= 0) {
            if (rc != PCRE2_ERROR_NOMATCH) {
                PCRE2_UCHAR errmsg[4096];
                pcre2_get_error_message(rc, errmsg, sizeof(errmsg) - 1);
                dbgDebug(D_WAAP_REGEX) << "SingleRegex['" << m_regexName << "']::findAllMatches " <<
                    "failed with error code: " << rc << " ('" << errmsg << "')";
            }
            break;
        }

        int highestMatchedGroupIndex = rc;

        // Get pointer to array of offsets into s, and its size
        uint32_t ovCount = pcre2_get_ovector_count(m_matchData);
        PCRE2_SIZE* ov = pcre2_get_ovector_pointer(m_matchData);

        RegexMatch match;
        match.groups.reserve(ovCount);

        dbgTrace(D_WAAP_REGEX) << "regex '" << m_regexName << "', captureGroupsCount = " <<
            m_captureGroupsCount << ". ovCount = " << ovCount << "; highestMatchedGroupIndex = " <<
            highestMatchedGroupIndex;

        // ov is vector of ovCount pairs of PCRE2_SIZE values.
        // First entry in pair is offset of start of the match (in s),
        // second entry is offset of character one after end of the match.
        // Walk over all matches and fill them here (-1 because first one isn't included in ovCount).
        for (int groupIndex = 1; groupIndex < highestMatchedGroupIndex; ++groupIndex) {
            PCRE2_SIZE rangeStart = ov[groupIndex * 2];
            PCRE2_SIZE rangeEnd = ov[groupIndex * 2 + 1];

            // Skip matches that are not set
            if (rangeStart == PCRE2_UNSET || rangeEnd == PCRE2_UNSET) {
                continue;
            }

            dbgTrace(D_WAAP_REGEX) << "groupIndex=" << groupIndex << " ['" << m_captureNames[groupIndex] <<
                "']: range " << rangeStart << " -> " << rangeEnd;
            match.groups.push_back(
                RegexMatch::MatchGroup(
                    groupIndex,
                    m_captureNames[groupIndex],
                    s.substr(rangeStart, rangeEnd - rangeStart)
                )
            );
        }

        matches.push_back(match);

        // Count matches found in this SingleRegex
        matchesCount++;

        // continue searching for next match starting from end of this match
        // (first two entries in ov[] are start and end offsets of current full match)
        startOffset = ov[1];
    } while (matchesCount < maxMatches);

    return matchesCount;
}

const std::string &SingleRegex::getName() const
{
    return m_regexName;
}

size_t SingleRegex::findMatchRanges(const std::string& s, std::vector<RegexMatchRange>& matchRanges) const {
    PCRE2_SIZE startOffset = 0;

    do {
        int rc = pcre2_match(
            m_re, // code
            reinterpret_cast<PCRE2_SPTR>(s.data()), s.size(), // subject/subject length
            startOffset, // start offset
            0, // options
            m_matchData,
            NULL // match_context
        );

        // Note: PCRE2_ERROR_NOMATCH is the normal situation here, but there could be other errors.
        // However, whichever error occurred, the loop is stopped.
        if (rc <= 0) {
            if (rc != PCRE2_ERROR_NOMATCH) {
                PCRE2_UCHAR errmsg[4096];
                pcre2_get_error_message(rc, errmsg, sizeof(errmsg) - 1);
                dbgDebug(D_WAAP_REGEX) << "SingleRegex['" << m_regexName << "']::findMatchRanges " <<
                    "failed with error code: " << rc << " ('" << errmsg << "')";
            }
            break;
        }

        // Get pointer to array of offsets into s
        PCRE2_SIZE* ov = pcre2_get_ovector_pointer(m_matchData);

        // start searching for next match starting from end of this match
        // (first two entries in ov[] are start and end offsets of current full match)
        startOffset = ov[1];

        matchRanges.push_back(RegexMatchRange(ov[0], ov[1]));
    } while (true);

    return matchRanges.size();
}

// Regex

Regex::Regex(const std::string& pattern, bool &error, const std::string& regexName)
:
m_regexName(regexName),
m_regexPreconditions(nullptr) // no need for preconditions for single regex mode
{
    if (error) {
        // Skip initialization if already in error condition
        dbgError(D_WAAP_REGEX) << "Skip compiling regex: " << m_regexName << " (single) due to previous error";
        return;
    }

    m_sre.push_back(new SingleRegex(pattern, error, m_regexName));
}

// Divide regexp patterns longer than the limit (imposed by pcre2 library!) into multiple regexes.
#define REGEX_PATT_MAX_SIZE 0

Regex::Regex(
    const std::vector<std::string> & patterns,
    bool &error,
    const std::string & regexName,
    std::shared_ptr<Waap::RegexPreconditions> regexPreconditions)
:
m_regexName(regexName),
m_regexPreconditions(regexPreconditions)
{
    if (error) {
        // Skip initialization if already in error condition
        dbgError(D_WAAP_REGEX) << "Skip compiling regex: " << m_regexName << " due to previous error";
        return;
    }

    // This regex helps to parse out group names from regex patterns
    SingleRegex patternParseRegex("^\\(\\?P<(.*?)>(.*?)\\)$", error, "patternParseRegex");

    std::string acc;

    for (std::vector<std::string>::const_iterator pPattern = patterns.begin();
        pPattern != patterns.end();
        ++pPattern) {
        const std::string& pattern = *pPattern;
        if ((acc.size() + pattern.size()) > REGEX_PATT_MAX_SIZE) {
            if (!acc.empty()) {
                assert(false); // this should never happen
                m_sre.push_back(new SingleRegex(acc + ")", error, m_regexName));
                acc = "(" + pattern;
            }
            else
            {
                bool bNoRegex = false;
                std::string regexMatchName;
                std::string regexMatchValue;

                // This is the only place where patterns are loaded (one-by-one)
                if (m_regexPreconditions) {
                    // If preconditions are enabled on this Regex instance - build list of indices of SingleRegex
                    // that should be triggered (executed) for each related word found by aho-corasick pattern scan.
                    Waap::RegexPreconditions::WordIndex wordIndex =
                        m_regexPreconditions->getWordByRegex(pattern);

                    // Extract group name from the regex pattern string
                    if (m_regexPreconditions->isNoRegexPattern(pattern)) {
                        // This word should not be scanned with regex. Instead, it should directly return a match
                        std::vector <RegexMatch> parsedMatches;
                        patternParseRegex.findAllMatches(pattern, parsedMatches);
                        bNoRegex = true;
                        regexMatchName = parsedMatches[0].groups[0].value;
                        regexMatchValue = m_regexPreconditions->getWordStrByWordIndex(wordIndex);
                    }

                    // For each word - build list of SingleRegex indices to be scanned if that word is detected
                    // Note that if aho-corasick word for this regex is not yet defined it will enter the [""] entry
                    // and will always be executed. This is less efficient but ensures correct attack detection.
                    m_wordToRegexIndices[wordIndex].push_back(m_sre.size());
                }
                else {
                    // If preconditions are not enabled on this Regex instance - all SingleRegexes in it will always
                    // be executed.
                    m_wordToRegexIndices[Waap::RegexPreconditions::emptyWordIndex].push_back(m_sre.size());
                }

                m_sre.push_back(new SingleRegex("(" + pattern+ ")", error, m_regexName + "/" + pattern, bNoRegex,
                    regexMatchName, regexMatchValue));
            }
        }
        else {
            assert(false); // this should never happen anymore.
            // Add | character between individual patterns, but not before the very first one!
            if (acc.empty()) {
                // first group
                acc = "(" + pattern;
            }
            else {
                // non-first group
                acc += "|" + pattern;
            }
        }
    }

    if (acc.size() > 0) {
        assert(false); // this should never happen anymore.
        m_sre.push_back(new SingleRegex(acc + ")", error, m_regexName));
    }
}

Regex::~Regex() {
    for (std::vector<SingleRegex*>::iterator ppSingleRegex = m_sre.begin();
        ppSingleRegex != m_sre.end();
        ++ppSingleRegex) {
        SingleRegex* pSingleRegex = *ppSingleRegex;

        if (pSingleRegex) {
            delete pSingleRegex;
        }
    }
}

bool Regex::hasMatch(const std::string& s) const {
    for (std::vector<SingleRegex*>::const_iterator ppSingleRegex = m_sre.begin();
        ppSingleRegex != m_sre.end();
        ++ppSingleRegex) {
        SingleRegex* pSingleRegex = *ppSingleRegex;

        if (pSingleRegex->hasMatch(s)) {
            dbgTrace(D_WAAP_REGEX) << "Regex['" << m_regexName << "']['" << pSingleRegex->getName() <<
                "']::hasMatch() found!";
            return true;
        }
    }

    return false;
}

size_t Regex::findAllMatches(const std::string& s, std::vector<RegexMatch>& matches,
    const Waap::RegexPreconditions::PmWordSet *pmWordSet, size_t maxMatches) const {
    matches.clear();

    if (m_regexPreconditions && pmWordSet) {
        // If preconditions are enabled on this regex - execute them to make scanning more efficient
        std::unordered_set<size_t> dupIndices;

        for (Waap::RegexPreconditions::WordIndex wordIndex : *pmWordSet) {
            const auto &found = m_wordToRegexIndices.find(wordIndex);

            // Check that the wordIndex is related to this instance of Regex object
            if (found == m_wordToRegexIndices.end()) {
                continue;
            }

            const std::vector<size_t> &regexIndicesList = found->second;

            for (size_t regexIndex : regexIndicesList) {
                if (dupIndices.find(regexIndex) != dupIndices.end()) {
                    // Avoid scanning the same regex index twice (in case it is registered for more than one wordIndex)
                    continue;
                }

                // Scan only regexes that are enabled by aho-corasick scan
                m_sre[regexIndex]->findAllMatches(s, matches, maxMatches);
                dbgTrace(D_WAAP_REGEX) << "Regex['" << m_sre[regexIndex]->getName() <<
                    "',index=" << regexIndex << "]::findAllMatches(): " << matches.size() << " matches found (so far)";

                dupIndices.insert(regexIndex);
            }
        }
    }
    else {
        // When optimization is disabled - scan all regexes
        for (SingleRegex* pSingleRegex : m_sre) {
            pSingleRegex->findAllMatches(s, matches, maxMatches);
            dbgTrace(D_WAAP_REGEX) << "Regex['" << m_regexName << "']['" << pSingleRegex->getName() <<
                "']::findAllMatches(): " << matches.size() << " matches found (so far)";
        }
    }

    dbgTrace(D_WAAP_REGEX) << "Regex['" << m_regexName << "']::findAllMatches(): total " <<
        matches.size() << " matches found.";
    return matches.size();
}

inline bool consolidateMatchRangesSortFunc(const RegexMatchRange& a, const RegexMatchRange& b) {
    return a.start > b.start;
}

// Consolidate ranges in-place (algorithm adapted from this solution:
// http://www.geeksforgeeks.org/merging-intervals)
static void consolidateMatchRanges(std::vector<RegexMatchRange>& matchRanges) {
    // Sort ranges in decreasing order of their start offsets (O(logN) time)
    std::sort(matchRanges.begin(), matchRanges.end(), consolidateMatchRangesSortFunc);
    int lastIndex = 0; // index of last range in matchRanges vector (up to this range everything is merged)

    // Traverse all ranges and merge where necessary
    for (size_t i = 0; i < matchRanges.size(); ++i) {
        // If this is not first range and it overlaps with the previous range
        if (lastIndex != 0 && matchRanges[lastIndex - 1].start < matchRanges[i].end) {
            while (lastIndex != 0 && matchRanges[lastIndex - 1].start < matchRanges[i].end) {
                // merge previous and current ranges
                matchRanges[lastIndex - 1].end = std::max(matchRanges[lastIndex - 1].end, matchRanges[i].end);
                matchRanges[lastIndex - 1].start = std::min(matchRanges[lastIndex - 1].start, matchRanges[i].start);
                lastIndex--;
            }
        }
        else {
            // Doesn't overlap with previous (or no previous because this is first range),
            // add the range as-is
            matchRanges[lastIndex] = matchRanges[i];
        }

        lastIndex++;
    }

    // Keep only merged ranges. Erase extra ranges that are not used anymore
    matchRanges.resize(lastIndex);
}

std::string Regex::sub(const std::string& s, const std::string& repl) const {
    std::vector<RegexMatchRange> matchRanges;

    // Find all ranges of all matches
    for (std::vector<SingleRegex*>::const_iterator ppSingleRegex = m_sre.begin();
        ppSingleRegex != m_sre.end();
        ++ppSingleRegex) {
        SingleRegex* pSingleRegex = *ppSingleRegex;
        pSingleRegex->findMatchRanges(s, matchRanges);
#ifdef WAF2_LOGGING_ENABLE
        dbgTrace(D_WAAP_REGEX) << "Regex['" << m_regexName << "']['" << pSingleRegex->getName() <<
            "']::sub(): " << matchRanges.size() << " match ranges found (so far):";
        for (size_t i = 0; i < matchRanges.size(); ++i) {
            dbgTrace(D_WAAP_REGEX) << "Range [" << i << "]: " << matchRanges[i].start << " -> " << matchRanges[i].end;
        }
#endif
    }

    // No matches - nothing to replace.
    if (matchRanges.empty()) {
        return s;
    }

    // Match ranges collected from multiple single regexps could overlap and be out of order
    // This function sorts the ranges in place (in decreasing order) and also consolidates overlapping
    // ranges so they do not overlap.
    consolidateMatchRanges(matchRanges);

#ifdef WAF2_LOGGING_ENABLE
    dbgTrace(D_WAAP_REGEX) << "Regex['" << m_regexName << "']::sub(): " <<
        matchRanges.size() << " match ranges (after consolidation):";
    for (size_t i = 0; i < matchRanges.size(); ++i) {
        dbgTrace(D_WAAP_REGEX) << "Range [" << i << "]: " << matchRanges[i].start << " -> " << matchRanges[i].end;
    }
#endif

    // Now walk over (consolidated) ranges (that are now guaranteed not to overlap), and copy everything around them
    // Note that ranges are still sorted in decreasing order, so we traverse the list backwards to see them in
    // increasing order
    PCRE2_SIZE startOffset = 0;
    std::string outStr;

    for (std::vector<RegexMatchRange>::const_reverse_iterator pMatchRange = matchRanges.rbegin();
        pMatchRange != matchRanges.rend();
        ++pMatchRange) {
        // Add everything since startOffset until start of current range
        outStr += s.substr(startOffset, pMatchRange->start - startOffset);

        // Add replacement
        if (!repl.empty()) {
            outStr += repl;
        }
        // Keep copying only after end of current range
        startOffset = pMatchRange->end;
    }

    // Add remainder of string after last range
    outStr += s.substr(startOffset);
    return outStr;
}

// TODO:: refactor out with C++ functor instead of C-style pointer-callback!
void
Regex::sub(
    const std::string& s,
    Waap::Util::RegexSubCallback_f cb,
    int& decodedCount,
    int& deletedCount,
    std::string& outStr) const
{
    decodedCount = 0;
    deletedCount = 0;

    // Clear outStr, it will be filled with output string (with changes, if applicable)
    outStr.clear();

    std::vector<RegexMatchRange> matchRanges;

    // Find all ranges of all matches
    for (std::vector<SingleRegex*>::const_iterator ppSingleRegex = m_sre.begin();
        ppSingleRegex != m_sre.end();
        ++ppSingleRegex) {
        SingleRegex* pSingleRegex = *ppSingleRegex;
        pSingleRegex->findMatchRanges(s, matchRanges);
#ifdef WAF2_LOGGING_ENABLE
        dbgTrace(D_WAAP_REGEX) << "Regex['" << m_regexName << "']['" << pSingleRegex->getName()
            << "']::sub(): " << matchRanges.size() << " match ranges found (so far):";
        for (size_t i = 0; i < matchRanges.size(); ++i) {
            dbgTrace(D_WAAP_REGEX) << "Range [" << i << "]: " << matchRanges[i].start << " -> " << matchRanges[i].end;
        }
#endif
    }

    // No matches - nothing to replace.
    if (matchRanges.empty()) {
        outStr = s;
        return;
    }

    // Match ranges collected from multiple single regexps could overlap and be out of order
    // This function sorts the ranges in place (in decreasing order) and also consolidates
    // overlapping ranges so they do not overlap.
    consolidateMatchRanges(matchRanges);

#ifdef WAF2_LOGGING_ENABLE
    dbgTrace(D_WAAP_REGEX) << "Regex['" << m_regexName << "']::sub(): " <<
        matchRanges.size() << " match ranges (after consolidation):";
    for (size_t i = 0; i < matchRanges.size(); ++i) {
        dbgTrace(D_WAAP_REGEX) << "Range [" << i << "]: " << matchRanges[i].start << " -> " << matchRanges[i].end;
    }
#endif

    // Now walk over (consolidated) ranges (that are now guaranteed not to overlap), and copy everything around them
    // Note that ranges are still sorted in decreasing order, so we traverse the list backwards to see them in
    // increasing order
    PCRE2_SIZE startOffset = 0;

    for (std::vector<RegexMatchRange>::const_reverse_iterator pMatchRange = matchRanges.rbegin();
        pMatchRange != matchRanges.rend();
        ++pMatchRange) {
        // Add everything since startOffset until start of current range
        outStr += s.substr(startOffset, pMatchRange->start - startOffset);

        // Compute replacement
        std::string repl;
        if (cb(s, s.begin() + pMatchRange->start, s.begin() + pMatchRange->end, repl)) {
            if (!repl.empty()) {
                outStr += repl;
                decodedCount++;
            }
            else {
                deletedCount++;
            }
        }
        else {
            // if callback told us the chunk was not processed - put original text inside
            outStr += s.substr(pMatchRange->start, pMatchRange->end - pMatchRange->start);
        }

        // Keep copying only after end of current range
        startOffset = pMatchRange->end;
    }

    // Add remainder of string after last range
    outStr += s.substr(startOffset);
    return;
}

const std::string &Regex::getName() const
{
    return m_regexName;
}
