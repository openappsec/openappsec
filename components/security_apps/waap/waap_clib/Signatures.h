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

#ifndef __SIGNATURES_H__
#define __SIGNATURES_H__

#include "Waf2Regex.h"
#include "picojson.h"
#include "flags.h"
#include <boost/regex.hpp>

class Signatures {
public:
    // Enum for zero-length assertion flags
    enum class AssertionFlag {
        START_WORD_BEHIND = 0,    // (?<=\w)
        START_NON_WORD_BEHIND,    // (?<!\w)
        END_WORD_AHEAD,           // (?=\w)
        END_NON_WORD_AHEAD,       // (?!\w)
        END_NON_WORD_SPECIAL,     // (?=[^\w?<>:=]|$)
        PATH_TRAVERSAL_START,     // (?<![\.,:])
        PATH_TRAVERSAL_END,       // (?![\.,:])
        WILDCARD_EVASION,         // (slashes and question mark must be present)
        COUNT                     // Must be last for Flags template
    };

    // Use the Flags template from utilities/flags.h for assertion flags
    using AssertionFlags = Flags<AssertionFlag>;

    static std::string extractGroupName(const std::string &pattern);

    static std::string processAssertions(const std::string &groupName,
        const std::string &pattern,
        AssertionFlags &flags);

    Signatures(const std::string& filepath);
    ~Signatures();

    bool fail();

    picojson::value::object sigsSource;
    bool error;
    std::shared_ptr<Waap::RegexPreconditions> m_regexPreconditions;

    // Regexes loaded from compiled signatures
    const Regex words_regex;
    const Regex specific_acuracy_keywords_regex;
    const Regex pattern_regex;
    const Regex un_escape_pattern;
    const Regex quotes_ev_pattern;
    const Regex comment_ev_pattern;
    const Regex quotes_space_ev_pattern;
    const Regex allowed_text_re;
    const Regex pipe_split_re;
    const Regex semicolon_split_re;
    const Regex longtext_re;
    const Regex nospaces_long_value_re;
    const Regex good_header_name_re;
    const Regex good_header_value_re;
    const std::set<std::string> ignored_for_nospace_long_value;
    const std::set<std::string> global_ignored_keywords;
    const std::set<std::string> global_ignored_patterns;
    const std::set<std::string> url_ignored_keywords;
    const std::set<std::string> url_ignored_patterns;
    const Regex url_ignored_re;
    const std::set<std::string> header_ignored_keywords;
    const std::set<std::string> header_ignored_patterns;
    const Regex header_ignored_re;
    const std::map<std::string, std::vector<std::string>> filter_parameters;
    const std::map<std::string, std::vector<std::string>> m_attack_types;
    const Regex php_serialize_identifier;
    const Regex html_regex;
    const Regex uri_parser_regex;
    const boost::regex confluence_macro_re;
#if 0 // Removed by Pavel's request. Leaving here in case he'll want to add this back...
    const std::set<std::string> cookie_ignored_keywords;
    const std::set<std::string> cookie_ignored_patterns;
    const Regex cookie_ignored_re;
#endif
    std::map<std::string, Regex*> headers_re;
    const Regex format_magic_binary_re;
    std::map<std::string, Regex*> params_type_re;

    // Signatures for responses
    const Regex resp_hdr_pattern_regex_list;
    const Regex resp_hdr_words_regex_list;
    const Regex resp_body_pattern_regex_list;
    const Regex resp_body_words_regex_list;

    const std::set<std::string> remove_keywords_always;
    const boost::regex user_agent_prefix_re;
    const boost::regex binary_data_kw_filter;
    const boost::regex wbxml_data_kw_filter;

    // Pre-compiled Hyperscan patterns and metadata for performance optimization
    struct HyperscanPattern {
        std::string originalPattern;
        std::string hyperscanPattern;
        std::string groupName;
        std::string category;
        std::string regexSource;
        bool isFastReg;
        bool isEvasion;

        HyperscanPattern() : isFastReg(false), isEvasion(false) {}
    };

    // Pre-processed hyperscan patterns for each regex category
    std::vector<HyperscanPattern> m_keywordHyperscanPatterns;
    std::vector<HyperscanPattern> m_patternHyperscanPatterns;

    // Assertion flags corresponding to each pattern (same indices as above vectors)
    std::vector<AssertionFlags> m_keywordAssertionFlags;
    std::vector<AssertionFlags> m_patternAssertionFlags;

    // Getter methods for precompiled patterns
    const std::vector<HyperscanPattern>& getKeywordHyperscanPatterns() const;
    const std::vector<HyperscanPattern>& getPatternHyperscanPatterns() const;

    // Getter methods for assertion flags
    const std::vector<AssertionFlags>& getKeywordAssertionFlags() const;
    const std::vector<AssertionFlags>& getPatternAssertionFlags() const;

    // PmWordSet for incompatible patterns that need to use traditional regex scanning
    Waap::RegexPreconditions::PmWordSet m_incompatiblePatternsPmWordSet;

    // Getter method for incompatible patterns PmWordSet
    const Waap::RegexPreconditions::PmWordSet& getIncompatiblePatternsPmWordSet() const;

    // Hyperscan initialization state management
    bool isHyperscanInitialized() const;
    void setHyperscanInitialized(bool initialized);

    // Check if Hyperscan should be used (based on configuration)
    static bool shouldUseHyperscan(bool force = false);

    void processRegexMatch(
        const std::string &groupName,
        const std::string &groupValue,
        std::string &word,
        std::vector<std::string> &keyword_matches,
        Waap::Util::map_of_stringlists_t &found_patterns,
        bool longTextFound,
        bool binaryDataFound
    ) const;

private:
    picojson::value::object loadSource(const std::string& waapDataFileName);
    void preprocessHyperscanPatterns();
    bool m_hyperscanInitialized;
};

inline std::string repr_uniq(const std::string & value) {
    std::string result;
    char hist[256];
    memset(&hist, 0, sizeof(hist));

    for (std::string::const_iterator pC = value.begin(); pC != value.end(); ++pC) {
        unsigned char ch = (unsigned char)(*pC);

        // Only take ASCII characters that are not alphanumeric, and each character only once
        if (ch <= 127 && !isalnum(ch) && hist[ch] == 0) {
            // Convert low ASCII characters to their C/C++ printable equivalent
            // (used for easier viewing. Also, binary data causes issues with ElasticSearch)
            switch (ch) {
                case 0x07: result += "\\a"; break;
                case 0x08: result += "\\b"; break;
                case 0x09: result += "\\t"; break;
                case 0x0A: result += "\\n"; break;
                case 0x0B: result += "\\v"; break;
                case 0x0C: result += "\\f"; break;
                case 0x0D: result += "\\r"; break;
                case 0x5C: result += "\\\\"; break;
                case 0x27: result += "\\\'"; break;
                case 0x22: result += "\\\""; break;
                case 0x3F: result += "\\\?"; break;
                default: {
                    if (ch >= 32) {
                        result += (char)ch;
                    }
                    else {
                        char buf[16];
                        sprintf(buf, "\\" "x%02X", ch);
                        result += buf;
                    }
                }
            }

            hist[ch] = 1;
        }
    }

    return result;
}

inline bool isShortWord(const std::string& word) {
    return word.size() <= 2;
}

inline bool isShortHtmlTag(const std::string& word) {
    return !word.empty() && word.size() <= 4 && word[0] == '<' && word[word.size() - 1] == '>';
}

#endif
