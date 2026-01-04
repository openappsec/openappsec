// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "WaapHyperscanEngine.h"
#include "Signatures.h"
#include "ScanResult.h"
#include "WaapSampleValue.h"
#include "Waf2Regex.h"
#include "Waf2Util.h"
#include "debug.h"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <regex>

#ifdef USE_HYPERSCAN
#include "hs.h"
#endif

USE_DEBUG_FLAG(D_WAAP_SAMPLE_SCAN);
USE_DEBUG_FLAG(D_WAAP_HYPERSCAN);

#ifdef USE_HYPERSCAN
static const unsigned int HS_STANDARD_FLAGS = HS_FLAG_CASELESS | HS_FLAG_SOM_LEFTMOST;
#endif // USE_HYPERSCAN
static const bool matchOriginalPattern = true;
static const size_t maxRegexValidationMatches = 10;

class WaapHyperscanEngine::Impl {
public:
    struct PatternInfo {
        std::string originalPattern;
        std::string hyperscanPattern;
        std::string groupName;
        std::string category; // "keywords", "specific_accuracy", "patterns"
        bool isFastReg;
        bool isEvasion;
        std::string regexSource; // "specific_acuracy_keywords_regex", "words_regex", "pattern_regex"
        Signatures::AssertionFlags assertionFlags; // Zero-length assertion flags
        std::unique_ptr<SingleRegex> originalRegex; // Precompiled original pattern for validation

        PatternInfo() : isFastReg(false), isEvasion(false) {}
    };

    struct MatchContext {
        const WaapHyperscanEngine::Impl* engine;
        const std::string* sampleText;
        std::vector<std::string>* keyword_matches;
        std::vector<std::string>* regex_matches;
        Waap::Util::map_of_stringlists_t* found_patterns;
        bool longTextFound;
        bool binaryDataFound;
        bool includePatternRegex;
        bool includeKeywordRegex;

        // Per-signature tracking of last match end (pattern id => last end offset)
        std::unordered_map<unsigned int, size_t> lastMatchEndPerSignature;
    };

    Impl();
    ~Impl();

    bool initialize(const std::shared_ptr<Signatures>& signatures);
    void scanSample(const SampleValue& sample,
        Waf2ScanResult& res,
        bool longTextFound,
        bool binaryDataFound,
        bool includeKeywordRegex,
        bool includePatternRegex) const;
    bool isInitialized() const { return m_isInitialized; }
    size_t getPatternCount() const { return m_patternInfos.size(); }
    size_t getCompiledPatternCount() const { return m_compiledPatternCount; }
    size_t getFailedPatternCount() const { return m_failedPatternCount; }

private:
#ifdef USE_HYPERSCAN
    hs_database_t* m_keywordDatabase;
    hs_database_t* m_patternDatabase;
    hs_scratch_t* m_keywordScratch;
    hs_scratch_t* m_patternScratch;
#endif

    std::shared_ptr<Signatures> m_Signatures;
    std::vector<PatternInfo> m_patternInfos;
    bool m_isInitialized;
    size_t m_compiledPatternCount;
    size_t m_failedPatternCount;

    // Helper methods
    bool compileHyperscanDatabases(const std::shared_ptr<Signatures>& signatures);
    void loadPrecompiledPatterns(const std::shared_ptr<Signatures>& signatures);

    // use an ordered set to keep PCRE2-validated matches sorted and unique in input order
    // LCOV_EXCL_START Reason: Trivial
    struct Match {
        size_t from;
        size_t to;
        Match(size_t from, size_t to) : from(from), to(to) {}
        bool operator<(const Match& other) const {
            return (from < other.from) || (from == other.from && to < other.to);
        }
    };

    // LCOV_EXCL_STOP

    // Assertion validation helpers
    bool validateAssertions(const std::string& sampleText,
        size_t matchStart,
        size_t matchEnd,
        const PatternInfo& patternInfo,
        std::set<Match> &foundMatches,
        size_t maxMatches) const;
    static bool isWordChar(char c);
    static bool isNonWordSpecialChar(char c);

#ifdef USE_HYPERSCAN
    // Hyperscan callback function
    static int onMatch(unsigned int id,
        unsigned long long from,
        unsigned long long to,
        unsigned int flags,
        void* context);

    void processMatch(unsigned int id,
        unsigned long long from,
        unsigned long long to,
        MatchContext* context) const;

    void identifyFailingPatterns(const std::vector<std::string>& patterns,
                                const std::vector<PatternInfo>& hsPatterns,
                                const std::string& logPrefix) {
        for (size_t i = 0; i < patterns.size(); ++i) {
            const char *single_pattern = patterns[i].c_str();
            unsigned int single_flag = HS_STANDARD_FLAGS;
            unsigned int single_id = static_cast<unsigned int>(i);
            hs_database_t *test_db = nullptr;
            hs_compile_error_t *single_err = nullptr;
            hs_error_t single_result = hs_compile_multi(&single_pattern,
                &single_flag,
                &single_id,
                1,
                HS_MODE_BLOCK,
                nullptr,
                &test_db,
                &single_err);
            if (single_result != HS_SUCCESS) {
                std::string additional_info = "";
                if (i < hsPatterns.size()) {
                    const auto &hsPattern = hsPatterns[i];
                    additional_info = " | Category: " + hsPattern.category +
                        " | Group: " + hsPattern.groupName +
                        " | Source: " + hsPattern.regexSource;
                    if (!hsPattern.originalPattern.empty() &&
                        hsPattern.originalPattern != hsPattern.hyperscanPattern) {
                        additional_info += " | Original: '" + hsPattern.originalPattern + "'";
                    }
                }
                dbgWarning(D_WAAP_HYPERSCAN)
                    << logPrefix << " [" << i << "]: '" << patterns[i]
                    << "' - Error: " << (single_err ? single_err->message : "unknown") << additional_info;
                if (single_err) {
                    hs_free_compile_error(single_err);
                    single_err = nullptr;
                }
            } else {
                if (test_db) {
                    hs_free_database(test_db);
                    test_db = nullptr;
                }
            }
            if (single_err) {
                hs_free_compile_error(single_err);
                single_err = nullptr;
            }
        }
    }
#endif // USE_HYPERSCAN
};

WaapHyperscanEngine::Impl::Impl()
    :
#ifdef USE_HYPERSCAN
    m_keywordDatabase(nullptr), m_patternDatabase(nullptr), m_keywordScratch(nullptr), m_patternScratch(nullptr),
#endif // USE_HYPERSCAN
    m_isInitialized(false), m_compiledPatternCount(0), m_failedPatternCount(0)
{
}

WaapHyperscanEngine::Impl::~Impl()
{
#ifdef USE_HYPERSCAN
    if (m_keywordScratch) hs_free_scratch(m_keywordScratch);
    if (m_patternScratch) hs_free_scratch(m_patternScratch);
    if (m_keywordDatabase) hs_free_database(m_keywordDatabase);
    if (m_patternDatabase) hs_free_database(m_patternDatabase);
#endif
}

bool WaapHyperscanEngine::Impl::initialize(const std::shared_ptr<Signatures> &signatures)
{
    if (!signatures) {
        dbgWarning(D_WAAP_HYPERSCAN) << "WaapHyperscanEngine::initialize: null signatures";
        return false;
    }
    m_Signatures = signatures;

#ifdef USE_HYPERSCAN
    m_isInitialized = compileHyperscanDatabases(signatures);
    if (m_isInitialized) {
        dbgInfo(D_WAAP_HYPERSCAN) << "WaapHyperscanEngine initialized successfully. "
            << "Compiled: " << m_compiledPatternCount << ", Failed: " << m_failedPatternCount;
    } else {
        dbgWarning(D_WAAP_HYPERSCAN) << "WaapHyperscanEngine initialization failed";
    }
    return m_isInitialized;
#else
    dbgInfo(D_WAAP_HYPERSCAN) << "WaapHyperscanEngine: Hyperscan not available on this platform";
    return false;
#endif
}

bool WaapHyperscanEngine::Impl::compileHyperscanDatabases(const std::shared_ptr<Signatures> &signatures)
{
#ifdef USE_HYPERSCAN
    // Load precompiled patterns from signatures instead of extracting at runtime
    loadPrecompiledPatterns(signatures);

    std::vector<std::string> keywordPatterns;
    std::vector<std::string> patternRegexPatterns;

    // Collect keyword patterns (from specific_accuracy and keywords categories)
    auto keywordAssertionFlags = signatures->getKeywordAssertionFlags();
    for (size_t i = 0; i < signatures->getKeywordHyperscanPatterns().size(); ++i) {
        const auto &hsPattern = signatures->getKeywordHyperscanPatterns()[i];
        keywordPatterns.push_back(hsPattern.hyperscanPattern);

        PatternInfo info;
        info.originalPattern = hsPattern.originalPattern;
        info.hyperscanPattern = hsPattern.hyperscanPattern;
        info.category = hsPattern.category;
        info.regexSource = hsPattern.regexSource;
        info.groupName = hsPattern.groupName;
        info.isFastReg = hsPattern.isFastReg;
        info.isEvasion = hsPattern.isEvasion;

        // Set assertion flags if available
        if (i < keywordAssertionFlags.size()) {
            info.assertionFlags = keywordAssertionFlags[i];
        }

        // Compile original regex pattern for validation only when matchOriginal flag is set
        if (!info.originalPattern.empty() && matchOriginalPattern) {
            bool regexError = false;
            info.originalRegex = std::make_unique<SingleRegex>(
                info.originalPattern, regexError, "ValidationRegex_" + info.groupName + "_" + std::to_string(i));
            if (regexError) {
                dbgWarning(D_WAAP_HYPERSCAN)
                    << "Failed to compile original regex for pattern: " << info.originalPattern
                    << " (group: " << info.groupName << ")";
                info.originalRegex.reset(); // Clear failed regex
            }
        }

        m_patternInfos.push_back(std::move(info));
    }

    // Collect pattern regex patterns (from patterns category)
    auto patternAssertionFlags = signatures->getPatternAssertionFlags();
    for (size_t i = 0; i < signatures->getPatternHyperscanPatterns().size(); ++i) {
        const auto &hsPattern = signatures->getPatternHyperscanPatterns()[i];
        patternRegexPatterns.push_back(hsPattern.hyperscanPattern);

        PatternInfo info;
        info.originalPattern = hsPattern.originalPattern;
        info.hyperscanPattern = hsPattern.hyperscanPattern;
        info.category = hsPattern.category;
        info.regexSource = hsPattern.regexSource;
        info.groupName = hsPattern.groupName;
        info.isFastReg = hsPattern.isFastReg;
        info.isEvasion = hsPattern.isEvasion;

        // Set assertion flags if available
        if (i < patternAssertionFlags.size()) {
            info.assertionFlags = patternAssertionFlags[i];
        }

        // Compile original regex pattern for validation only when matchOriginal flag is set
        if (!info.originalPattern.empty() && matchOriginalPattern) {
            bool regexError = false;
            size_t patternIndex = keywordPatterns.size() + i; // Offset by keyword patterns count
            info.originalRegex = std::make_unique<SingleRegex>(info.originalPattern, regexError,
                "ValidationRegex_" + info.groupName + "_" + std::to_string(patternIndex));
            if (regexError) {
                dbgWarning(D_WAAP_HYPERSCAN)
                    << "Failed to compile original regex for pattern: " << info.originalPattern
                    << " (group: " << info.groupName << ")";
                info.originalRegex.reset(); // Clear failed regex
            }
        }

        m_patternInfos.push_back(std::move(info));
    }

    dbgInfo(D_WAAP_HYPERSCAN) << "Using precompiled patterns: "
        << "keywords=" << keywordPatterns.size()
        << ", patterns=" << patternRegexPatterns.size();

    // Compile keyword database (specific_acuracy_keywords_regex + words_regex)
    size_t total_ids = 0;
    if (!keywordPatterns.empty()) {
        std::vector<const char *> c_patterns;
        std::vector<unsigned int> flags;
        std::vector<unsigned int> ids;

        for (size_t i = 0; i < keywordPatterns.size(); ++i) {
            c_patterns.push_back(keywordPatterns[i].c_str());
            flags.push_back(HS_STANDARD_FLAGS);
            ids.push_back(static_cast<unsigned int>(total_ids++));
        }

        // Defensive checks before calling hs_compile_multi
        if (c_patterns.size() != flags.size() || c_patterns.size() != ids.size()) {
            dbgWarning(D_WAAP_HYPERSCAN) << "Pattern, flag, and id arrays are not the same size!";
            return false;
        }
        if (c_patterns.empty()) {
            dbgWarning(D_WAAP_HYPERSCAN) << "No patterns to compile!";
            return false;
        }
        dbgInfo(D_WAAP_HYPERSCAN) << "Compiling " << c_patterns.size()
                            << " keyword patterns with hs_compile_multi. First pattern: '"
                            << keywordPatterns[0] << "'";

        hs_compile_error_t *compile_err = nullptr;
        hs_error_t result =
            hs_compile_multi(c_patterns.data(),
                flags.data(),
                ids.data(),
                static_cast<unsigned int>(c_patterns.size()),
                HS_MODE_BLOCK,
                nullptr,
                &m_keywordDatabase,
                &compile_err);

        if (result != HS_SUCCESS) {
            std::string error_msg = compile_err ? compile_err->message : "unknown error";
            dbgWarning(D_WAAP_HYPERSCAN) << "Failed to compile keyword database: " << error_msg;

            // Try to identify the specific failing pattern(s)
            if (compile_err) {
                dbgWarning(D_WAAP_HYPERSCAN) << "Attempting to identify failing keyword pattern(s)...";
                auto keywordHsPatterns = signatures->getKeywordHyperscanPatterns();
                std::vector<PatternInfo> keywordPatternInfos;
                keywordPatternInfos.reserve(keywordHsPatterns.size());
                for (const auto& hsPattern : keywordHsPatterns) {
                    keywordPatternInfos.emplace_back();
                    PatternInfo& info = keywordPatternInfos.back();
                    info.originalPattern = hsPattern.originalPattern;
                    info.hyperscanPattern = hsPattern.hyperscanPattern;
                    info.category = hsPattern.category;
                    info.regexSource = hsPattern.regexSource;
                    info.groupName = hsPattern.groupName;
                    info.isFastReg = hsPattern.isFastReg;
                    info.isEvasion = hsPattern.isEvasion;
                }
                identifyFailingPatterns(keywordPatterns, keywordPatternInfos, "Failing keyword pattern");
            }
            if (compile_err) {
                hs_free_compile_error(compile_err);
                compile_err = nullptr;
            }
            return false;
        }

        if (hs_alloc_scratch(m_keywordDatabase, &m_keywordScratch) != HS_SUCCESS) {
            dbgWarning(D_WAAP_HYPERSCAN) << "Failed to allocate keyword scratch space";
            return false;
        }

        m_compiledPatternCount += keywordPatterns.size();
    }

    // Compile pattern database (pattern_regex)
    if (!patternRegexPatterns.empty()) {
        std::vector<const char *> c_patterns;
        std::vector<unsigned int> flags;
        std::vector<unsigned int> ids;

        for (size_t i = 0; i < patternRegexPatterns.size(); ++i) {
            c_patterns.push_back(patternRegexPatterns[i].c_str());
            flags.push_back(HS_STANDARD_FLAGS);
            ids.push_back(static_cast<unsigned int>(total_ids++));
        }

        // Defensive checks before calling hs_compile_multi
        if (c_patterns.size() != flags.size() || c_patterns.size() != ids.size()) {
            dbgWarning(D_WAAP_HYPERSCAN)
                << "Pattern, flag, and id arrays are not the same size! (patternRegexPatterns)";
            return false;
        }
        if (c_patterns.empty()) {
            dbgWarning(D_WAAP_HYPERSCAN) << "No pattern regex patterns to compile!";
            return false;
        }
        dbgInfo(D_WAAP_HYPERSCAN) << "Compiling " << c_patterns.size()
                                << " pattern regex patterns with hs_compile_multi. First pattern: '"
                                << patternRegexPatterns[0] << "'";

        hs_compile_error_t *compile_err = nullptr;
        hs_error_t result =
            hs_compile_multi(c_patterns.data(),
                flags.data(),
                ids.data(),
                static_cast<unsigned int>(c_patterns.size()),
                HS_MODE_BLOCK,
                nullptr,
                &m_patternDatabase,
                &compile_err);

        if (result != HS_SUCCESS) {
            std::string error_msg = compile_err ? compile_err->message : "unknown error";
            dbgWarning(D_WAAP_HYPERSCAN) << "Failed to compile pattern database: " << error_msg;

            // Try to identify the specific failing pattern(s)
            if (compile_err) {
                dbgWarning(D_WAAP_HYPERSCAN) << "Attempting to identify failing pattern regex pattern(s)...";
                auto patternHsPatterns = signatures->getPatternHyperscanPatterns();
                std::vector<PatternInfo> patternPatternInfos;
                patternPatternInfos.reserve(patternHsPatterns.size());
                for (const auto& hsPattern : patternHsPatterns) {
                    patternPatternInfos.emplace_back();
                    PatternInfo& info = patternPatternInfos.back();
                    info.originalPattern = hsPattern.originalPattern;
                    info.hyperscanPattern = hsPattern.hyperscanPattern;
                    info.category = hsPattern.category;
                    info.regexSource = hsPattern.regexSource;
                    info.groupName = hsPattern.groupName;
                    info.isFastReg = hsPattern.isFastReg;
                    info.isEvasion = hsPattern.isEvasion;
                }
                identifyFailingPatterns(patternRegexPatterns, patternPatternInfos, "Failing pattern regex");
            }
            if (compile_err) {
                hs_free_compile_error(compile_err);
                compile_err = nullptr;
            }
            return false;
        }

        if (hs_alloc_scratch(m_patternDatabase, &m_patternScratch) != HS_SUCCESS) {
            dbgWarning(D_WAAP_HYPERSCAN) << "Failed to allocate pattern scratch space";
            return false;
        }

        m_compiledPatternCount += patternRegexPatterns.size();
    }

    return true;
#else // USE_HYPERSCAN
    return false;
#endif // USE_HYPERSCAN
}

void WaapHyperscanEngine::Impl::loadPrecompiledPatterns(const std::shared_ptr<Signatures> &signatures)
{
    // This method is called to initialize any additional pattern processing if needed
    // For now, the patterns are directly accessed from the signatures object
    dbgTrace(D_WAAP_HYPERSCAN) << "Loading precompiled patterns from Signatures";
    m_Signatures = signatures;
}

#ifdef USE_HYPERSCAN
int WaapHyperscanEngine::Impl::onMatch(unsigned int id,
    unsigned long long from,
    unsigned long long to,
    unsigned int flags,
    void *context)
{
    MatchContext *ctx = static_cast<MatchContext *>(context);
    ctx->engine->processMatch(id, from, to, ctx);
    return 0; // Continue scanning
}

void WaapHyperscanEngine::Impl::processMatch(unsigned int id,
    unsigned long long from,
    unsigned long long to,
    MatchContext *context) const
{
    if (id >= m_patternInfos.size()) {
        dbgWarning(D_WAAP_HYPERSCAN) << "Invalid pattern ID: " << id;
        return;
    }

    const PatternInfo &info = m_patternInfos[id];
    const std::string &sampleText = *context->sampleText;
    size_t start = static_cast<size_t>(from);
    size_t end = static_cast<size_t>(to);

    if (end > sampleText.length()) end = sampleText.length();
    if (start >= end) return;

    // skip overlaps for this pattern
    size_t &lastEnd = context->lastMatchEndPerSignature[id];
    if (start < lastEnd) {
        dbgTrace(D_WAAP_HYPERSCAN) << "Skipping overlapping match for pattern id=" << id << " start=" << start
            << " lastEnd=" << lastEnd << ", match: '" << sampleText.substr(start, end - start)
            << "'";
        return;
    }

    std::set<Match> foundMatches;
    if (!validateAssertions(sampleText, start, end, info, foundMatches, maxRegexValidationMatches)) return;

    for (const auto &match : foundMatches) {
        std::string matchedText = sampleText.substr(match.from, match.to - match.from);
        std::string word = matchedText;

        dbgTrace(D_WAAP_HYPERSCAN) << " match='" << word << "' id='" << id << "' group='" << info.groupName
            << "' category=" << info.category;

        if (context->binaryDataFound && word.size() <= 2) {
            dbgTrace(D_WAAP_HYPERSCAN)
                << "Will not add a short keyword '" << word << "' because binaryData was found";
            continue;
        }

        if (context->includeKeywordRegex && (info.category == "keywords" || info.category == "specific_accuracy")) {
            m_Signatures->processRegexMatch(info.groupName, matchedText, word, *context->keyword_matches,
                                            *context->found_patterns, context->longTextFound,
                                            context->binaryDataFound);
        } else if (context->includePatternRegex && info.category == "patterns") {
            m_Signatures->processRegexMatch(info.groupName, matchedText, word, *context->regex_matches,
                                            *context->found_patterns, context->longTextFound,
                                            context->binaryDataFound);
        }
        lastEnd = std::max(lastEnd, match.to);
    }
}
#endif // USE_HYPERSCAN

void WaapHyperscanEngine::Impl::scanSample(const SampleValue &sample, Waf2ScanResult &res, bool longTextFound,
                                    bool binaryDataFound, bool includeKeywordRegex, bool includePatternRegex) const
{
#ifdef USE_HYPERSCAN
    if (!m_isInitialized) {
        dbgTrace(D_WAAP_HYPERSCAN) << "WaapHyperscanEngine: not initialized, skipping scan";
        return;
    }

    const std::string &sampleText = sample.getSampleString();

    MatchContext context;
    context.engine = this;
    context.sampleText = &sampleText;
    context.keyword_matches = &res.keyword_matches;
    context.regex_matches = &res.regex_matches;
    context.found_patterns = &res.found_patterns;
    context.longTextFound = longTextFound;
    context.binaryDataFound = binaryDataFound;
    context.includePatternRegex = includePatternRegex;
    context.includeKeywordRegex = includeKeywordRegex;

    context.lastMatchEndPerSignature.clear();
    dbgTrace(D_WAAP_HYPERSCAN) << "WaapHyperscanEngine::scanSample: scanning '" << sampleText
        << "' longTextFound=" << longTextFound << " binaryDataFound=" << binaryDataFound
        << " includeKeywordRegex=" << includeKeywordRegex
        << " includePatternRegex=" << includePatternRegex;

    if (includeKeywordRegex && m_keywordDatabase && m_keywordScratch) {
        hs_error_t result =
            hs_scan(m_keywordDatabase, sampleText.c_str(), static_cast<unsigned int>(sampleText.length()), 0,
                    m_keywordScratch, onMatch, &context);

        if (result != HS_SUCCESS) {
            dbgWarning(D_WAAP_HYPERSCAN) << "Keyword database scan failed: " << result;
        }
    }

    if (includePatternRegex && m_patternDatabase && m_patternScratch) {
        hs_error_t result =
            hs_scan(m_patternDatabase, sampleText.c_str(), static_cast<unsigned int>(sampleText.length()), 0,
                    m_patternScratch, onMatch, &context);

        if (result != HS_SUCCESS) {
            dbgWarning(D_WAAP_HYPERSCAN) << "Pattern database scan failed: " << result;
        }
    }

    dbgTrace(D_WAAP_HYPERSCAN) << "WaapHyperscanEngine::scanSample: found " << res.keyword_matches.size()
        << " keyword matches, " << res.regex_matches.size() << " regex matches";
#else
    dbgWarning(D_WAAP_HYPERSCAN) << "WaapHyperscanEngine::scanSample called but Hyperscan not available";
#endif
}

bool WaapHyperscanEngine::Impl::validateAssertions(const std::string &sampleText, size_t matchStart, size_t matchEnd,
                                            const PatternInfo &patternInfo, std::set<Match> &foundMatches,
                                            size_t maxMatches) const
{
    foundMatches.clear();

    // If we don't have an original regex compiled, fall back to the assertion flags validation
    if (!patternInfo.originalRegex) {
        dbgTrace(D_WAAP_HYPERSCAN) << "No original regex available for validation, "
                                << "falling back to assertion flags check";
        foundMatches.emplace(matchStart, matchEnd);
        // If no assertion flags are set, the match is valid
        if (patternInfo.assertionFlags.empty()) {
            return true;
        }

        if (
            patternInfo.assertionFlags.isSet(Signatures::AssertionFlag::END_NON_WORD_AHEAD) &&
            matchEnd < sampleText.length() &&
            isWordChar(sampleText[matchEnd])) {
            // (?!\w) - requires NO word character after the match
            return false;
        }

        if (patternInfo.assertionFlags.isSet(Signatures::AssertionFlag::START_NON_WORD_BEHIND) && matchStart > 0 &&
            isWordChar(sampleText[matchStart - 1])) {
            // (?<!\w) - requires NO word character before the match
            return false;
        }

        // Check start assertions
        if (patternInfo.assertionFlags.isSet(Signatures::AssertionFlag::START_WORD_BEHIND) &&
            (matchStart == 0 || !isWordChar(sampleText[matchStart - 1]))) {
            // (?<=\w) - requires a word character before the match
            return false;
        }

        // Check end assertions
        if (patternInfo.assertionFlags.isSet(Signatures::AssertionFlag::END_WORD_AHEAD) &&
            (matchEnd >= sampleText.length() || !isWordChar(sampleText[matchEnd]))) {
            // (?=\w) - requires a word character after the match
            return false;
        }

        if (patternInfo.assertionFlags.isSet(Signatures::AssertionFlag::END_NON_WORD_SPECIAL)) {
            // (?=[^\w?<>:=]|$) - requires a non-word character (excluding ?<>:=) or end of string after the match
            if (matchEnd < sampleText.length()) {
                char nextChar = sampleText[matchEnd];
                if (isWordChar(nextChar) || nextChar == '?' || nextChar == '<' || nextChar == '>' || nextChar == ':' ||
                    nextChar == '=') {
                    return false;
                }
            }
            // If we're at the end of string, this condition is satisfied
        }

        return true;
    }

    if (patternInfo.assertionFlags.isSet(Signatures::AssertionFlag::WILDCARD_EVASION)) {
        // skip if the match does not contain either type of slash, and not a question mark
        bool hasSlash = false;
        bool hasQuestionMark = false;

        for (size_t i = matchStart; i < matchEnd && !(hasSlash && hasQuestionMark); ++i) {
            if (sampleText[i] == '\\' || sampleText[i] == '/') {
                hasSlash = true;
            }
            if (sampleText[i] == '?') {
                hasQuestionMark = true;
            }
        }
        dbgTrace(D_WAAP_HYPERSCAN) << "Testing for wildcard evasion: '"
                                << " hasSlash=" << hasSlash << " hasQuestionMark=" << hasQuestionMark;
        if (!hasSlash || !hasQuestionMark) {
            return false;
        }
    }

    // Use the original compiled regex to find matches within the specified range
    std::vector<RegexMatchRange> matchRanges;

    // look behind to cover possible assertions, look ahead much further to cover lazy hyperscan match end
    static const size_t lookbehind_range = 4, lookahead_range = 32;
    size_t searchStart = (matchStart > lookbehind_range) ? (matchStart - lookbehind_range) : 0UL;
    size_t searchEnd = ((matchEnd + lookahead_range) < matchEnd || (matchEnd + lookahead_range) > sampleText.length())
        ? sampleText.length()           // overflow
        : (matchEnd + lookahead_range); // within bounds

    std::vector<RegexMatchRange> regex_matches;
    patternInfo.originalRegex->findMatchRanges(sampleText, regex_matches, maxMatches, searchStart, searchEnd);

    for (const auto &match : regex_matches) {
        foundMatches.emplace(match.start, match.end);
        if (isDebugRequired(TRACE, D_WAAP_HYPERSCAN)) {
            dbgTrace(D_WAAP_HYPERSCAN) << "Match for: '" << patternInfo.originalPattern << "' matched in range ["
                << match.start << "," << match.end << "] "
                << "matched text: '"
                << sampleText.substr(match.start, match.end - match.start)
                << "'";
        }
    }

    if (foundMatches.empty()) {
        if (isDebugRequired(TRACE, D_WAAP_HYPERSCAN)) {
            dbgTrace(D_WAAP_HYPERSCAN) << "No match for: '" << patternInfo.originalPattern
                << "' did not match in range [" << matchStart << "," << matchEnd << "] "
                << "matched text: '" << sampleText.substr(matchStart, matchEnd - matchStart)
                << "'";
        }
        return false;
    }
    return true;
}

// LCOV_EXCL_START Reason: Not in use currently, but kept for future reference
bool WaapHyperscanEngine::Impl::isWordChar(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

bool WaapHyperscanEngine::Impl::isNonWordSpecialChar(char c)
{
    return c == '?' || c == '<' || c == '>' || c == ':' || c == '=';
}
// LCOV_EXCL_STOP

// WaapHyperscanEngine public interface - delegates to Impl
WaapHyperscanEngine::WaapHyperscanEngine() : pimpl(std::make_unique<Impl>())
{
}

WaapHyperscanEngine::~WaapHyperscanEngine() = default;

bool WaapHyperscanEngine::initialize(const std::shared_ptr<Signatures>& signatures)
{
    return pimpl->initialize(signatures);
}

void WaapHyperscanEngine::scanSample(const SampleValue& sample, Waf2ScanResult& res, bool longTextFound,
                                    bool binaryDataFound, bool includeKeywordRegex, bool includePatternRegex) const
{
    pimpl->scanSample(sample, res, longTextFound, binaryDataFound, includeKeywordRegex, includePatternRegex);
}

bool WaapHyperscanEngine::isInitialized() const
{
    return pimpl->isInitialized();
}

size_t WaapHyperscanEngine::getPatternCount() const
{
    return pimpl->getPatternCount();
}

size_t WaapHyperscanEngine::getCompiledPatternCount() const
{
    return pimpl->getCompiledPatternCount();
}

size_t WaapHyperscanEngine::getFailedPatternCount() const
{
    return pimpl->getFailedPatternCount();
}
