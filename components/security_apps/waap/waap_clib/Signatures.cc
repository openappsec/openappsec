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

#include "Signatures.h"
#include "AssertionRegexes.h"
#include "agent_core_utilities.h"
#include "debug.h"
#include "waap.h"
#include <cstdlib> // for getenv
#include <cstring> // for strcmp
#include <fstream>

USE_DEBUG_FLAG(D_WAAP);
USE_DEBUG_FLAG(D_WAAP_SAMPLE_SCAN);
USE_DEBUG_FLAG(D_WAAP_HYPERSCAN);

typedef picojson::value::object JsObj;
typedef picojson::value JsVal;
typedef picojson::value::array JsArr;
typedef std::map<std::string, std::vector<std::string>> filtered_parameters_t;

static std::vector<std::string> to_strvec(const picojson::value::array &jsV)
{
    std::vector<std::string> r;

    for (auto it = jsV.begin(); it != jsV.end(); ++it) {
        r.push_back(it->get<std::string>());
    }

    return r;
}

static std::set<std::string> to_strset(const picojson::value::array &jsA)
{
    std::set<std::string> r;

    for (auto it = jsA.begin(); it != jsA.end(); ++it) {
        r.insert(it->get<std::string>());
    }

    return r;
}

static std::map<std::string, Regex *> to_regexmap(const picojson::value::object &jsO, bool &error)
{
    std::map<std::string, Regex *> r;

    for (auto it = jsO.begin(); it != jsO.end(); ++it) {
        const std::string &n = it->first;
        // convert name to lowercase now (so we don't need to do it at runtime every time).
        std::string n_lower;
        for (std::string::const_iterator pCh = n.begin(); pCh != n.end(); ++pCh) {
            n_lower += std::tolower(*pCh);
        }
        const picojson::value &v = it->second;

        if (error) {
            // stop loading regexes if there's previous error...
            break;
        }

        // Pointers to Regex instances are stored instead of instances themselves to avoid
        // the need to make the Regex objects copyable.
        // However, these pointers must be freed by the holder of the returned map!
        // note: in our case this freeing is happening in the destructor of the WaapAssetState class.
        r[n] = new Regex(v.get<std::string>(), error, n_lower);
    }

    return r;
}

static filtered_parameters_t to_filtermap(const picojson::value::object &JsObj)
{
    filtered_parameters_t result;
    for (auto it = JsObj.begin(); it != JsObj.end(); ++it) {
        const std::string parameter = it->first;
        const picojson::value::array &arr = it->second.get<picojson::value::array>();
        result[parameter] = to_strvec(arr);
    }
    return result;
}

Signatures::Signatures(const std::string& filepath) :
    sigsSource(loadSource(filepath)),
    error(false),
    m_regexPreconditions(std::make_shared<Waap::RegexPreconditions>(sigsSource, error)),
    words_regex(
        to_strvec(sigsSource["words_regex_list"].get<picojson::value::array>()),
        error,
        "words_regex_list",
        m_regexPreconditions
    ),
    specific_acuracy_keywords_regex(
        to_strvec(sigsSource["specific_acuracy_keywords_regex_list"].get<picojson::value::array>()),
        error,
        "specific_acuracy_keywords_regex_list",
        m_regexPreconditions
    ),
    pattern_regex(
        to_strvec(sigsSource["pattern_regex_list"].get<picojson::value::array>()),
        error,
        "pattern_regex_list",
        m_regexPreconditions
    ),
    un_escape_pattern(sigsSource["un_escape_pattern"].get<std::string>(), error, "un_escape_pattern"),
    quotes_ev_pattern(sigsSource["quotes_ev_pattern"].get<std::string>(), error, "quotes_ev_pattern"),
    comment_ev_pattern(sigsSource["comment_ev_pattern"].get<std::string>(), error, "comment_ev_pattern"),
    quotes_space_ev_pattern(
        sigsSource["quotes_space_ev_fast_reg"].get<std::string>(), error,
        "quotes_space_ev_fast_reg"
    ),
    allowed_text_re(sigsSource["allowed_text_re"].get<std::string>(), error, "allowed_text_re"),
    pipe_split_re(
        "([^|]*)\\||([^|]+)|\\|()",
        error,
        "pipe_decode"),
    semicolon_split_re("([\\w\\=\\-\\_\\.\\,\\(\\)\\%]+?);|([\\w\\=\\-\\_\\.\\,\\(\\)\\%]+)|;()", error, "sem_decode"),
    longtext_re(sigsSource["longtext_re"].get<std::string>(), error, "longtext_re"),
    nospaces_long_value_re("^[^\\s]{16,}$", error, "nospaces_long_value_re"),
    good_header_name_re(sigsSource["good_header_name_re"].get<std::string>(), error, "good_header_name"),
    good_header_value_re(sigsSource["good_header_value_re"].get<std::string>(), error, "good_header_value"),
    ignored_for_nospace_long_value(
        to_strset(sigsSource["ignored_for_nospace_long_value"].get<picojson::value::array>())),
    global_ignored_keywords(
        to_strset(
            sigsSource["global_ignored"].get<picojson::value::object>()["keys"].get<picojson::value::array>()
        )
    ),
    global_ignored_patterns(
        to_strset(
            sigsSource["global_ignored"].get<picojson::value::object>()["patterns"].get<picojson::value::array>()
        )
    ),
    url_ignored_keywords(
        to_strset(
            sigsSource["ignored_for_url"].get<picojson::value::object>()["keys"].get<picojson::value::array>()
        )
    ),
    url_ignored_patterns(
        to_strset(
            sigsSource["ignored_for_url"].get<picojson::value::object>()["patterns"].get<picojson::value::array>()
        )
    ),
    url_ignored_re(
        sigsSource["ignored_for_url"].get<picojson::value::object>()["regex"].get<std::string>(),
        error,
        "url_ignored"
    ),
    header_ignored_keywords(
        to_strset(
            sigsSource["ignored_for_headers"].get<picojson::value::object>()["keys"].get<picojson::value::array>()
        )
    ),
    header_ignored_patterns(
        to_strset(
            sigsSource["ignored_for_headers"].get<picojson::value::object>()
            ["patterns"].get<picojson::value::array>()
        )
    ),
    header_ignored_re(
        sigsSource["ignored_for_headers"].get<picojson::value::object>()["regex"].get<std::string>(),
        error,
        "header_ignored"
    ),
    filter_parameters(
        to_filtermap(
            sigsSource["filter_parameters"].get<picojson::object>()
        )
    ),
    m_attack_types(
        to_filtermap(
            sigsSource["attack_types_map"].get<picojson::object>()
        )
    ),
    // Removed by Pavel's request. Leaving here in case he'll want to add this back...
#if 0
    cookie_ignored_keywords(
        to_strset(
            sigsSource["ignored_for_cookies"].get<picojson::value::object>()["keys"].get<picojson::value::array>()
        )
    ),
    cookie_ignored_patterns(
        to_strset(
            sigsSource["ignored_for_cookies"].get<picojson::value::object>()
            ["patterns"].get<picojson::value::array>()
        )
    ),
    cookie_ignored_re(
        sigsSource["ignored_for_cookies"].get<picojson::value::object>()["regex"].get<std::string>(),
        error,
        "cookie_ignored"
    ),
#endif
    php_serialize_identifier("^(N;)|^([ibdsOoCcRra]:\\d+)", error, "php_serialize_identifier"),
    html_regex("(<(?>body|head)\\b.*>(?>.|[\\r\\n]){0,400}){2}|<html", error, "htmlRegex"),
    uri_parser_regex("(http|https)://([^/ :]+):?([^/ ]*)(/?[^ #?]*)", error, "uriParserRegex"),
    confluence_macro_re("{[^\"]+:(?>.+\\|)+.+}"),
    headers_re(to_regexmap(sigsSource["headers_re"].get<JsObj>(), error)),
    format_magic_binary_re(sigsSource["format_magic_binary_re"].get<std::string>(), error, "format_magic_binary_re"),
    params_type_re(to_regexmap(sigsSource["format_types_regex_list"].get<JsObj>(), error)),
    resp_hdr_pattern_regex_list(to_strvec(sigsSource["resp_hdr_pattern_regex_list"].get<JsArr>()),
        error, "resp_hdr_pattern_regex_list", nullptr),
    resp_hdr_words_regex_list(to_strvec(sigsSource["resp_hdr_words_regex_list"].get<JsArr>()),
        error, "resp_hdr_words_regex_list", nullptr),
    resp_body_pattern_regex_list(to_strvec(sigsSource["resp_body_pattern_regex_list"].get<JsArr>()),
        error, "resp_body_pattern_regex_list", nullptr),
    resp_body_words_regex_list(to_strvec(sigsSource["resp_body_words_regex_list"].get<JsArr>()),
        error, "resp_body_words_regex_list", nullptr),
    remove_keywords_always(
        to_strset(sigsSource["remove_keywords_always"].get<JsArr>())),
    user_agent_prefix_re(sigsSource["user_agent_prefix_re"].get<std::string>()),
    binary_data_kw_filter(sigsSource["binary_data_kw_filter"].get<std::string>()),
    wbxml_data_kw_filter(sigsSource["wbxml_data_kw_filter"].get<std::string>()),
    m_hyperscanInitialized(false)
{
    // Only preprocess hyperscan patterns if hyperscan is enabled
    bool should_use_hyperscan = Signatures::shouldUseHyperscan();
    if (should_use_hyperscan) {
        preprocessHyperscanPatterns();
    }
}

Signatures::~Signatures()
{
}

bool Signatures::fail()
{
    return error;
}

// Static helper to process assertion flags for a pattern (for testing and internal use)
std::string
Signatures::processAssertions(const std::string &groupName, const std::string &pattern, AssertionFlags &flags)
{
    std::string processed = pattern;

    // Use regexes from AssertionRegexes namespace to detect assertions at start/end of the pattern string
    using namespace Waap::AssertionRegexes;
    boost::smatch match;

    // Start assertions - only a single '(' can precede
    if (boost::regex_search(processed, match, reStartNonWordBehind) && match.position() >= 0) {
        flags.setFlag(AssertionFlag::START_NON_WORD_BEHIND);
        processed = boost::regex_replace(processed, reStartNonWordBehind, std::string(""));
    }

    // Path traversal start assertion
    if (boost::regex_search(processed, match, rePathTraversalStart) && match.position() >= 0) {
        flags.setFlag(AssertionFlag::PATH_TRAVERSAL_START);
        processed = boost::regex_replace(processed, rePathTraversalStart, std::string(""));
    }

    // End assertions - only a single ')' can follow
    if (boost::regex_search(processed, match, reEndNonWordAhead) && match.position() >= 0) {
        flags.setFlag(AssertionFlag::END_NON_WORD_AHEAD);
        processed = boost::regex_replace(processed, reEndNonWordAhead, std::string(""));
    } else if (boost::regex_search(processed, match, reEndNonWordSpecial) && match.position() >= 0) {
        flags.setFlag(AssertionFlag::END_NON_WORD_SPECIAL);
        processed = boost::regex_replace(processed, reEndNonWordSpecial, std::string(""));
    }

    // Path traversal end assertion
    if (boost::regex_search(processed, match, rePathTraversalEnd) && match.position() >= 0) {
        flags.setFlag(AssertionFlag::PATH_TRAVERSAL_END);
        processed = boost::regex_replace(processed, rePathTraversalEnd, std::string(""));
    }

    // wildcard evasion regex group name starts with evasion_wildcard_regex
    if (groupName.find("evasion_wildcard_regex") == 0) {
        flags.setFlag(AssertionFlag::WILDCARD_EVASION);
    }

    return processed;
}

// Extracts the group name from a regex pattern string (e.g., (?P<groupName>...))
std::string Signatures::extractGroupName(const std::string &pattern) {
    boost::regex namedGroupRegex(R"(\(\?P<([^>]+)>)");
    boost::smatch match;
    if (boost::regex_search(pattern, match, namedGroupRegex)) {
        return match[1].str();
    }
    return "";
}

void Signatures::preprocessHyperscanPatterns()
{
    std::map<std::string, size_t> categoryCount;

    // Helper function to check if a pattern is hyperscan compatible
    auto isHyperscanCompatible = [&categoryCount](const std::string &pattern) -> bool {
        // Hyperscan doesn't support certain regex features that we can't easily convert
        static const std::vector<std::string> incompatibleFeatures = {
            R"((?!\w)", R"((?<!\w)", R"((?=\w)", R"((?<=\w)", // Lookahead/lookbehind assertions for \w
            R"((?!)",   R"((?<!)",   R"((?=)",   R"((?<=)",   // Lookahead/lookbehind assertions
            R"((?>)",   R"((?&)",    R"((?|)",   R"((?P<)",   // Atomic groups, named groups, and branching
            R"((?R)"                                          // Recursion
        };

        for (const auto &feature : incompatibleFeatures) {
            if (pattern.find(feature) != std::string::npos) {
                dbgInfo(D_WAAP_HYPERSCAN) << "Incompatible feature found: " << feature << " in pattern: " << pattern;
                categoryCount[feature]++;
                return false;
            }
        }

        boost::regex backrefRegex(R"(\(\\\d+\))");
        if (boost::regex_search(pattern, backrefRegex)) {
            dbgInfo(D_WAAP_HYPERSCAN) << "Incompatible backreference found: " << pattern;
            categoryCount["backreference"]++;
            return false;
        }
        return true;
    };

    // Helper function to convert regex pattern to hyperscan-compatible format
    auto convertToHyperscanPattern = [](const std::string &originalPattern) -> std::string {
        std::string converted = originalPattern;

        // Remove named group syntax - convert (?P<name>...) to ...
        boost::regex namedGroupRegex(R"(\(\?P<[^>]+>)");
        if (boost::regex_search(converted, namedGroupRegex)) {
            std::string end_str = ")";
            if (converted.back() == ')') {
                converted.pop_back(); // Remove the trailing ')'
                end_str = "";
            }
            converted = boost::regex_replace(converted, namedGroupRegex, end_str);
        }

        // Handle atomic groups first (before removing word boundaries)
        // Hyperscan doesn't support atomic groups, so we need to convert them

        // Convert (?>\b) to nothing (remove word boundary atomic groups)
        converted = boost::regex_replace(converted, boost::regex(R"(\(\?\>\\b\))"), std::string(""));
        // Convert (?>\B) to nothing (remove non-word boundary atomic groups)
        converted = boost::regex_replace(converted, boost::regex(R"(\(\?\>\\B\))"), std::string(""));
        // Convert empty atomic groups (?>) to nothing
        converted = boost::regex_replace(converted, boost::regex(R"(\(\?\>\))"), std::string(""));

        // // Now remove remaining word boundaries (not supported by Hyperscan)
        // // At this point, any \b or \B that was inside atomic groups has been handled above
        // converted = boost::regex_replace(converted, boost::regex(R"(\\b)"), std::string(""));
        // converted = boost::regex_replace(converted, boost::regex(R"(\\B)"), std::string(""));

        return converted;
    };

    // Helper function to get patterns from sigsSource for each category
    auto getCommonPatternsForCategory = [this](const std::string &category,
                                        const std::string &regexSource) -> std::vector<std::string> {
        std::vector<std::string> patterns;

        // Map regexSource/category to the JSON key in sigsSource
        std::string key;
        if (regexSource == "specific_acuracy_keywords_regex" || category == "specific_accuracy") {
            key = "specific_acuracy_keywords_regex_list";
        } else if (regexSource == "words_regex" || category == "keywords") {
            key = "words_regex_list";
        } else if (regexSource == "pattern_regex" || category == "patterns") {
            key = "pattern_regex_list";
        } else {
            // Fallback: allow passing the exact key name
            key = regexSource;
            dbgDebug(D_WAAP_HYPERSCAN) << "Unknown category/regexSource: " << category << "/" << regexSource
                << ". Using regexSource as key.";
        }

        // Fetch patterns directly from sigsSource if available
        auto it = sigsSource.find(key);
        if (it != sigsSource.end()) {
            try {
                patterns = to_strvec(it->second.get<JsArr>());
            } catch (...) {
                // If the type is unexpected, return empty and continue gracefully
                patterns.clear();
                dbgWarning(D_WAAP_HYPERSCAN) << "Unexpected type for key: " << key;
            }
        }

        return patterns;
    };

    // Process specific_acuracy_keywords_regex patterns
    std::vector<std::string> incompatiblePatterns;
    {
        auto patterns = getCommonPatternsForCategory("specific_accuracy", "specific_acuracy_keywords_regex");
        for (const auto &pattern : patterns) {
            AssertionFlags flags;
            std::string groupName = extractGroupName(pattern);
            std::string processedPattern = convertToHyperscanPattern(pattern);
            std::string hyperscanPattern = processAssertions(groupName, processedPattern, flags);

            if (hyperscanPattern != pattern) {
                dbgTrace(D_WAAP_HYPERSCAN) << pattern << " -> " << hyperscanPattern;
            }

            if (isHyperscanCompatible(hyperscanPattern)) {
                HyperscanPattern hsPattern;
                hsPattern.originalPattern = pattern;
                hsPattern.hyperscanPattern = hyperscanPattern;
                hsPattern.category = "specific_accuracy";
                hsPattern.regexSource = "specific_acuracy_keywords_regex";
                hsPattern.groupName = groupName;
                if (hsPattern.groupName.empty()) {
                    hsPattern.groupName = "specific_accuracy_match";
                }
                hsPattern.isFastReg = (hsPattern.groupName.find("fast_reg") != std::string::npos);
                hsPattern.isEvasion = (hsPattern.groupName.find("evasion") != std::string::npos);

                m_keywordHyperscanPatterns.push_back(hsPattern);
                m_keywordAssertionFlags.push_back(flags);
            } else {
                incompatiblePatterns.push_back(pattern);
            }
        }
    }

    // Process words_regex patterns
    {
        auto patterns = getCommonPatternsForCategory("keywords", "words_regex");
        for (const auto &pattern : patterns) {
            AssertionFlags flags;
            std::string groupName = extractGroupName(pattern);
            std::string processedPattern = convertToHyperscanPattern(pattern);
            std::string hyperscanPattern = processAssertions(groupName, processedPattern, flags);

            if (hyperscanPattern != pattern) {
                dbgTrace(D_WAAP_HYPERSCAN) << pattern << " -> " << hyperscanPattern;
            }

            if (isHyperscanCompatible(hyperscanPattern)) {
                HyperscanPattern hsPattern;
                hsPattern.originalPattern = pattern;
                hsPattern.hyperscanPattern = hyperscanPattern;
                hsPattern.category = "keywords";
                hsPattern.regexSource = "words_regex";
                hsPattern.groupName = groupName;
                if (hsPattern.groupName.empty()) {
                    hsPattern.groupName = "keywords_match";
                }
                hsPattern.isFastReg = (hsPattern.groupName.find("fast_reg") != std::string::npos);
                hsPattern.isEvasion = (hsPattern.groupName.find("evasion") != std::string::npos);

                m_keywordHyperscanPatterns.push_back(hsPattern);
                m_keywordAssertionFlags.push_back(flags);
            } else {
                incompatiblePatterns.push_back(pattern);
            }
        }
    }

    // Process pattern_regex patterns
    {
        auto patterns = getCommonPatternsForCategory("patterns", "pattern_regex");
        for (const auto &pattern : patterns) {
            AssertionFlags flags;
            std::string groupName = extractGroupName(pattern);
            std::string processedPattern = convertToHyperscanPattern(pattern);
            std::string hyperscanPattern = processAssertions(groupName, processedPattern, flags);

            if (hyperscanPattern != pattern) {
                dbgTrace(D_WAAP_HYPERSCAN) << pattern << " -> " << hyperscanPattern;
            }

            if (isHyperscanCompatible(hyperscanPattern)) {
                HyperscanPattern hsPattern;
                hsPattern.originalPattern = pattern;
                hsPattern.hyperscanPattern = hyperscanPattern;
                hsPattern.category = "patterns";
                hsPattern.regexSource = "pattern_regex";
                hsPattern.groupName = groupName;
                if (hsPattern.groupName.empty()) {
                    hsPattern.groupName = "patterns_match";
                }
                hsPattern.isFastReg = (hsPattern.groupName.find("fast_reg") != std::string::npos);
                hsPattern.isEvasion = (hsPattern.groupName.find("evasion") != std::string::npos);

                m_patternHyperscanPatterns.push_back(hsPattern);
                m_patternAssertionFlags.push_back(flags);
            } else {
                incompatiblePatterns.push_back(pattern);
            }
        }
    }

    dbgInfo(D_WAAP_HYPERSCAN) << "Preprocessed Hyperscan patterns: "
        << "keywords=" << m_keywordHyperscanPatterns.size()
        << ", patterns=" << m_patternHyperscanPatterns.size()
        << ", incompatible=" << incompatiblePatterns.size();
    for (const auto &it : categoryCount) {
        dbgInfo(D_WAAP_HYPERSCAN) << "Feature: " << it.first << ", Count: " << it.second;
    }

    // Convert incompatible patterns to PmWordSet for traditional regex processing
    if (m_regexPreconditions && !incompatiblePatterns.empty()) {
        for (const auto &pattern : incompatiblePatterns) {
            Waap::RegexPreconditions::WordIndex wordIndex = m_regexPreconditions->getWordByRegex(pattern);
            if (wordIndex != Waap::RegexPreconditions::emptyWordIndex) {
                m_incompatiblePatternsPmWordSet.insert(wordIndex);
            }
        }
        dbgInfo(D_WAAP_HYPERSCAN) << "Created PmWordSet for " << m_incompatiblePatternsPmWordSet.size()
            << " incompatible patterns (from " << incompatiblePatterns.size() << " total)";
    }
}

picojson::value::object Signatures::loadSource(const std::string &waapDataFileName)
{
    picojson::value doc;
    std::ifstream f(waapDataFileName);

    if (f.fail()) {
        dbgError(D_WAAP) << "Failed to open json data file '" << waapDataFileName << "'!";
        error = true; // flag an error
        return picojson::value::object();
    }

    int length;
    f.seekg(0, std::ios::end);       // go to the end
    length = f.tellg();              // report location (this is the length)
    char *buffer = new char[length]; // allocate memory for a buffer of appropriate dimension
    f.seekg(0, std::ios::beg);       // go back to the beginning
    f.read(buffer, length);          // read the whole file into the buffer
    f.close();

    std::string dataObfuscated(buffer, length);

    delete[] buffer;


    std::stringstream ss(dataObfuscated);

    ss >> doc;

    if (!picojson::get_last_error().empty()) {
        dbgError(D_WAAP) << "WaapAssetState::loadSource('" << waapDataFileName << "') failed (parse error: '"
                        << picojson::get_last_error() << "').";
        error = true; // flag an error
        return picojson::value::object();
    }

    return doc.get<picojson::value::object>()["waap_signatures"].get<picojson::value::object>();
}

const std::vector<Signatures::HyperscanPattern> &Signatures::getKeywordHyperscanPatterns() const
{
    return m_keywordHyperscanPatterns;
}

const std::vector<Signatures::HyperscanPattern> &Signatures::getPatternHyperscanPatterns() const
{
    return m_patternHyperscanPatterns;
}

const std::vector<Signatures::AssertionFlags> &Signatures::getKeywordAssertionFlags() const
{
    return m_keywordAssertionFlags;
}

const std::vector<Signatures::AssertionFlags> &Signatures::getPatternAssertionFlags() const
{
    return m_patternAssertionFlags;
}

const Waap::RegexPreconditions::PmWordSet &Signatures::getIncompatiblePatternsPmWordSet() const
{
    return m_incompatiblePatternsPmWordSet;
}

void Signatures::processRegexMatch(const std::string &groupName, const std::string &groupValue, std::string &word,
                                std::vector<std::string> &keyword_matches,
                                Waap::Util::map_of_stringlists_t &found_patterns, bool longTextFound,
                                bool binaryDataFound) const
{
    std::string group = groupName;

    if (group == "") {
        return; // skip unnamed group
    }

    const std::string &value = groupValue;
    dbgTrace(D_WAAP_SAMPLE_SCAN) << "checkRegex: group name='" << group << "' value='" << value << "', word='" << word
                                << "':";

    if (group.find("fast_reg") != std::string::npos) {
        dbgTrace(D_WAAP_SAMPLE_SCAN) << "checkRegex: found '*fast_reg*' in group name";
        if (group.find("evasion") != std::string::npos) {
            dbgTrace(D_WAAP_SAMPLE_SCAN) << "checkRegex: found both 'fast_reg' and 'evasion' in group name.";
            word = "encoded_" + repr_uniq(value);
            if (word == "encoded_") {
                dbgTrace(D_WAAP_SAMPLE_SCAN)
                    << "checkRegex: empty word after repr_uniq: resetting word to 'character_encoding'"
                    " and group to 'evasion'.";
                word = "character_encoding";
            } else if (Waap::Util::str_isalnum(word)) {
                dbgTrace(D_WAAP_SAMPLE_SCAN)
                    << "checkRegex: isalnum word after repr_uniq: resetting group to 'evasion'.";
                // If the found match is alphanumeric (we've seen strings like "640x480" match)
                // we still should assume evasion but it doesn't need to include "fast_reg",
                // which would cause unconditional report to stage2 and hit performance...
                // This is why we remove the word "fast_reg" from the group name.
                group = "evasion";
            }

            if (longTextFound) {
                dbgTrace(D_WAAP_SAMPLE_SCAN) << "checkRegex: longTextFound so resetting group name to 'longtext'";
                group = "longtext";
            }
        } else {
            word = group;
        }
    }
    // In sequences detected as "longTextFound" or "longBinaryFound", do not add words in the
    // "keyword_matches" list that:
    //  - starts with "encoded_"
    //  - or startswith("\")
    //  - or equal to "character_encoding"
    if ((longTextFound || binaryDataFound) &&
        (word == "character_encoding" || word.substr(0, 1) == "\\" || word.substr(0, 8) == "encoded_")) {
        // For now, do not skip
        // TODO - check if skipping improves detection
        dbgTrace(D_WAAP_SAMPLE_SCAN) << "longText/binaryData found with character_encoding";
    } else if (binaryDataFound && (isShortWord(word) || isShortHtmlTag(word) ||
                NGEN::Regex::regexMatch(__FILE__, __LINE__, group, binary_data_kw_filter))) {
        dbgTrace(D_WAAP_SAMPLE_SCAN) << "Not adding group='" << group << "', word='" << word
                                    << "' - due to binary data";
        return;
    } else if ((std::find(keyword_matches.begin(), keyword_matches.end(), word) == keyword_matches.end())) {
        // python: if (word not in current_matches): current_matches.append(word)
        keyword_matches.push_back(word);
        dbgTrace(D_WAAP_SAMPLE_SCAN) << "added keyword match for group='" << group << "', value='" << value
                                    << "', word='" << word << "'";
    }

    // python:
    // if group not in found_patterns:
    //    found_patterns[group]=[]
    if (found_patterns.find(group) == found_patterns.end()) {
        found_patterns[group] = std::vector<std::string>();
    }

    // python:
    // if value not in found_patterns[group]:
    //    found_patterns[group].append(value)
    if (std::find(found_patterns[group].begin(), found_patterns[group].end(), value) == found_patterns[group].end()) {
        found_patterns[group].push_back(value);
        dbgTrace(D_WAAP_SAMPLE_SCAN) << "added pattern match for group='" << group << "', value='" << value
                                    << "', word='" << word << "'";
    }
}

bool Signatures::isHyperscanInitialized() const
{
    return m_hyperscanInitialized;
}

void Signatures::setHyperscanInitialized(bool initialized)
{
    m_hyperscanInitialized = initialized;
}

bool Signatures::shouldUseHyperscan(bool force)
{
    // This can be controlled by environment variable or configuration
    static bool useHyperscan = false;

#ifdef USE_HYPERSCAN
    static bool checked = false;
    if (!checked || force) {
        // Check environment variable first
        const char *env = getenv("WAAP_USE_HYPERSCAN");
        if (env) {
            useHyperscan = (strcmp(env, "1") == 0 || strcasecmp(env, "true") == 0);
            dbgDebug(D_WAAP_SAMPLE_SCAN) << "Hyperscan usage set by environment: " << useHyperscan;
        } else {
            // Default to false to maintain backward compatibility - Hyperscan is opt-in
            useHyperscan = false;
            dbgDebug(D_WAAP_SAMPLE_SCAN) << "Hyperscan usage default (disabled): " << useHyperscan;
        }
        checked = true;
    }
#endif // USE_HYPERSCAN

    return useHyperscan;
}
