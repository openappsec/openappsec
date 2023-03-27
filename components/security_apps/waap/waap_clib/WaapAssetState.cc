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

// #define WAF2_LOGGING_ENABLE (does performance impact)
#include "WaapAssetState.h"
#include "Waf2Regex.h"
#include "debug.h"
#include "Waf2Util.h"
#include "maybe_res.h"
#include "picojson.h"
#include "agent_core_utilities.h"
#include <algorithm>
#include <fstream>
#include <boost/regex.hpp>

#define MAX_CACHE_VALUE_SIZE 1024

USE_DEBUG_FLAG(D_WAAP_ASSET_STATE);
USE_DEBUG_FLAG(D_WAAP_SAMPLE_PREPROCESS);
USE_DEBUG_FLAG(D_WAAP_SAMPLE_SCAN);
USE_DEBUG_FLAG(D_WAAP_EVASIONS);

typedef picojson::value::object JsObj;
typedef picojson::value JsVal;
typedef picojson::value::array JsArr;
typedef std::map<std::string, std::vector<std::string>> filtered_parameters_t;

#ifdef WAF2_LOGGING_ENABLE
static void
print_filtered(std::string title, const std::set<std::string>& ignored_set, const std::vector<std::string>& v) {
    dbgTrace(D_WAAP_SAMPLE_SCAN) << "--------------------------";
#if 0 // TODO:: may be useful for debug, but in general no need to print this on every scanned value...
    dbgTrace(D_WAAP_SAMPLE_SCAN) << "Ignored " << title << " set:";
    for (std::set<std::string>::const_iterator it = ignored_set.begin(); it != ignored_set.end(); ++it) {
        const std::string& word = *it;
        dbgTrace(D_WAAP_SAMPLE_SCAN) << "*'" << word << "'";
    }
#endif
    dbgTrace(D_WAAP_SAMPLE_SCAN) << title << " collected:";
    for (std::vector<std::string>::const_iterator it = v.begin(); it != v.end(); ++it) {
        const std::string& word = *it;

        if (ignored_set.find(word) == ignored_set.end()) {
            // not in ignored_set
            dbgTrace(D_WAAP_SAMPLE_SCAN) << "+'" << word << "'";
        }
        else {
            // in ignored set
            dbgTrace(D_WAAP_SAMPLE_SCAN) << "-'" << word << "'";
        }
    }
    dbgTrace(D_WAAP_SAMPLE_SCAN) << "--------------------------";
}

static void print_found_patterns(const Waap::Util::map_of_stringlists_t& m) {
    dbgTrace(D_WAAP_SAMPLE_SCAN) << "-- found_patterns: ---------";
    for (auto g = m.begin(); g != m.end(); ++g) {
        dbgTrace(D_WAAP_SAMPLE_SCAN) << "'" << g->first << "'";
        for (auto p = g->second.begin(); p != g->second.end(); ++p) {
            dbgTrace(D_WAAP_SAMPLE_SCAN) << " `-> '" << (*p) << "'";
        }
    }
    dbgTrace(D_WAAP_SAMPLE_SCAN) << "--------------------------";
}
#endif

static bool err_hex = false;
static const std::string path_traversal_chars_regex = "[\\w.%?*\\/\\\\]";
static const std::string evasion_hex_regex_unallowed_prefix_helper =
        "(?:(?<!(?<!0x|%u)[0-9a-f][0-9a-f])|(?<!(?<!%)[0-9a-f][0-9a-f]))";
static const std::string evasion_hex_regex_helper = "(0x[0-9a-f][0-9a-f])";
static const SingleRegex evasion_hex_regex(
    evasion_hex_regex_unallowed_prefix_helper + evasion_hex_regex_helper + path_traversal_chars_regex +
    "|" + path_traversal_chars_regex + evasion_hex_regex_unallowed_prefix_helper + evasion_hex_regex_helper,
    err_hex,
    "evasion_hex_regex");
static const std::string bad_hex_regex_helper = "(%[cC]1%(([19][cC])|([pP][cC])|(8[sS])))";
static const boost::regex bad_hex_regex(bad_hex_regex_helper);
static const SingleRegex evasion_bad_hex_regex(
    bad_hex_regex_helper + path_traversal_chars_regex +
    "|" + path_traversal_chars_regex + bad_hex_regex_helper,
    err_hex,
    "evasion_bad_hex_regex");
static const std::string utf_evasion_for_dot_helper =
    "(%[cC]0%[562aAfFeE][eE])";
static const SingleRegex utf_evasion_for_dot(
    utf_evasion_for_dot_helper + path_traversal_chars_regex +
    "|" + path_traversal_chars_regex + utf_evasion_for_dot_helper,
    err_hex,
    "utf_evasion_for_dot");
static const boost::regex utf_evasion_for_dot_regex(utf_evasion_for_dot_helper);
static const std::string sqli_comma_evasion_regex_helper = "\"\\s*,\\s*\"";
static const boost::regex sqli_comma_evasion_regex(sqli_comma_evasion_regex_helper);

WaapAssetState::WaapAssetState(const std::shared_ptr<WaapAssetState>& pWaapAssetState,
    const std::string& waapDataFileName,
    const std::string& id) :
    WaapAssetState(pWaapAssetState->m_Signatures,
        waapDataFileName,
        pWaapAssetState->m_cleanValuesCache.capacity(),
        pWaapAssetState->m_suspiciousValuesCache.capacity(),
        pWaapAssetState->m_sampleTypeCache.capacity(),
        id)
{
    scoreBuilder.mergeScores(pWaapAssetState->scoreBuilder);
    updateScores();
    m_typeValidator = pWaapAssetState->m_typeValidator;

    registerConfigLoadCb(
    [this]()
        {
            clearRateLimitingState();
            clearSecurityHeadersState();
            clearErrorLimitingState();
        }
    );
}

WaapAssetState::WaapAssetState(std::shared_ptr<Signatures> signatures,
    const std::string& waapDataFileName,
    size_t cleanValuesCacheCapacity,
    size_t suspiciousValuesCacheCapacity,
    size_t sampleTypeCacheCapacity,
    const std::string& assetId) :
    m_Signatures(signatures),
    m_waapDataFileName(waapDataFileName),
    m_assetId(assetId),
    scoreBuilder(this),
    m_rateLimitingState(nullptr),
    m_errorLimitingState(nullptr),
    m_securityHeadersState(nullptr),


    m_filtersMngr(nullptr),
    m_typeValidator(getWaapDataDir() + "/waap.data"),
    m_cleanValuesCache(cleanValuesCacheCapacity),
    m_suspiciousValuesCache(suspiciousValuesCacheCapacity),
    m_sampleTypeCache(sampleTypeCacheCapacity)
    {
        if (assetId != "" && Singleton::exists<I_AgentDetails>())
        {
            I_AgentDetails* agentDetails = Singleton::Consume<I_AgentDetails>::by<WaapComponent>();
            std::string path = agentDetails->getTenantId() + "/" + assetId;
            m_filtersMngr = std::make_shared<IndicatorsFiltersManager>(path, assetId, this);
        }
        else
        {
            m_filtersMngr = std::make_shared<IndicatorsFiltersManager>("", "", this);
        }
        // Load keyword scores - copy from ScoreBuilder
        updateScores();
    }

    WaapAssetState::~WaapAssetState() {
        // TODO:: leaving this uncommented may introduce (not critical) memory leak.
        // Should return this code after testing it well.
#if 0
    // clean up the headers_re map to avoid memory leak
        for (auto it = m_Signatures->headers_re.begin(); it != m_Signatures->headers_re.end(); ++it) {
            delete it->second; // delete allocated Regex instances
        }
#endif
    }

    std::shared_ptr<Signatures> WaapAssetState::getSignatures() const
    {
        return m_Signatures;
    }


    void WaapAssetState::reset()
    {
        m_filtersMngr->reset();
    }

    void filterUnicode(std::string & text) {
        std::string::iterator it = text.begin();
        std::string::iterator result = it;
        uint32_t acc = 0;
        int bytes_left = 0;

        for (; it != text.end(); ++it) {
            unsigned char ch = (unsigned char)(*it);

            // If character high bits are 10xxxxxx, then it might be UTF-8 character used to evade.
            // For example 0xc0, 0xaf may mean '/' in broken utf-8 decoders
            // In our implementation we do remove leading byte in UTF8 encoding (such as 0xc0),
            // but strip down the following bytes (with high bits 01).
            if (ch <= 127) {
                *result++ = ch;
                bytes_left = 0; // any character <= 127 stops collecting UTF8 code
            }
            else {
                if (bytes_left == 0) {
                    // collect utf8 code
                    if ((ch & 0xE0) == 0xC0) { // 110X XXXX  two bytes follow

                        if ((ch & 0x1E) != 0) {
                            acc = ch & 31;
                        }
                        bytes_left = 1;
                    }
                    else if ((ch & 0xF0) == 0xE0) { // 1110 XXXX  three bytes follow
                        acc = ch & 15;
                        bytes_left = 2;
                    }
                    else if ((ch & 0xF8) == 0xF0) { // 1111 0XXX  four bytes follow
                        acc = ch & 7;
                        bytes_left = 3;
                    }
                    else if ((ch & 0xFC) == 0xF8) { // 1111 10XX  five bytes follow (by standard -an error)
                        acc = ch & 3;
                        bytes_left = 4;
                    }
                    else if ((ch & 0xFE) == 0xFC) { // 1111 110X  six bytes follow (by standard -an error)
                        acc = ch & 1;
                        bytes_left = 5;
                    }
                    else {
                        // error
                        bytes_left = 0;
                    }
                }
                else if (bytes_left > 0) {
                    // "good" encoder would check that the following bytes contain "10" as their high bits,
                    // but buggy encoders don't, so are we!
                    acc = (acc << 6) | (ch & 0x3F);
                    bytes_left--;

                    if (bytes_left == 0) {
                        // finished collecting the utf8 code
                        if (acc <= 127) {
                            *result++ = acc;
                        }
                        else if (isSpecialUnicode(acc)) {
                            *result++ = convertSpecialUnicode(acc);
                        }
                        acc = 0;
                    }
                }
            }
        }

        text.erase(result, text.end());
    }

#if 0
    //std::replace_if(text.begin(), text.end(), [](char c) { return !(c>=0); }, ' ');
    inline void replaceUnicode(std::string & text, const char repl) {
        std::string::iterator it = text.begin();

        for (; it != text.end(); ++it) {
            if (*it < 0) {
                *it = repl;
            }
        }
    }
#endif

    void trimSpaces(std::string & text) {
        size_t result_position = 0;
        size_t position = 0;
        space_stage state = NO_SPACES;
        uint32_t code;

        if (text.empty()) {
            return;
        }

        for (;position < text.size(); position++) {
            code = text[position];
            switch (code) {
                case '\t':
                case ' ':
                case '\f':
                case '\v':
                    if (state == NO_SPACES) {
                        state = SPACE_SYNBOL;
                        text[result_position++] = code;
                    }
                    break;
                case '\r':
                    switch (state) {
                        case (SPACE_SYNBOL):
                            text[result_position - 1] = code;
                            state = BR_SYMBOL;
                            break;
                        case (NO_SPACES):
                            text[result_position++] = code;
                            state = BR_SYMBOL;
                            break;
                        case (BN_SYMBOL):
                            text[result_position++] = code;
                            state = BNR_SEQUENCE;
                            break;
                        default:
                            break;
                    }
                    break;
                case '\n':
                    switch (state) {
                        case (SPACE_SYNBOL):
                            text[result_position - 1] = code;
                            state = BN_SYMBOL;
                            break;
                        case (NO_SPACES):
                            text[result_position++] = code;
                            state = BN_SYMBOL;
                            break;
                        case (BR_SYMBOL):
                            text[result_position++] = code;
                            state = BRN_SEQUENCE;
                            break;
                        default:
                            break;
                    }
                    break;
                default:
                    text[result_position++] = code;
                    state = NO_SPACES;
            }
        }
        text.erase(result_position, position - result_position);
    }

    // Python equivalent: text = re.sub(r'[^\x00-\x7F]+',' ', text)
    void replaceUnicodeSequence(std::string & text, const char repl) {
        std::string::iterator it = text.begin();
        std::string::iterator result = it;
        uint32_t acc = 0;
        int bytes_left = 0;

        for (; it != text.end(); ++it) {
            unsigned char ch = (unsigned char)(*it);

            // If character high bits are 10xxxxxx, then it might be UTF-8 character used to evade.
            // For example 0xc0, 0xaf may mean '/' in broken utf-8 decoders
            // In our implementation we do remove leading byte in UTF8 encoding (such as 0xc0),
            // but strip down the following bytes (with high bits 01).
            if (ch <= 127) {
                *result++ = ch;
                bytes_left = 0; // any character <= 127 stops collecting UTF8 code
            }
            else {
                if (bytes_left == 0) {
                    // collect utf8 code
                    if ((ch & 0xE0) == 0xC0) { // 110X XXXX  two bytes follow
                        if ((ch & 0x1E) != 0) {
                            acc = ch & 31;
                        }
                        bytes_left = 1;
                    }
                    else if ((ch & 0xF0) == 0xE0) { // 1110 XXXX  three bytes follow
                        acc = ch & 15;
                        bytes_left = 2;
                    }
                    else if ((ch & 0xF8) == 0xF0) { // 1111 0XXX  four bytes follow
                        acc = ch & 7;
                        bytes_left = 3;
                    }
                    else if ((ch & 0xFC) == 0xF8) { // 1111 10XX  five bytes follow (by standard -an error)
                        acc = ch & 3;
                        bytes_left = 4;
                    }
                    else if ((ch & 0xFE) == 0xFC) { // 1111 110X  six bytes follow (by standard -an error)
                        acc = ch & 1;
                        bytes_left = 5;
                    }
                    else {
                        // error
                        bytes_left = 0;
                    }
                }
                else if (bytes_left > 0) {
                    // "good" encoder would check that the following bytes contain "10" as their high bits,
                    // but buggy encoders don't, so are we!
                    acc = (acc << 6) | (ch & 0x3F);
                    bytes_left--;

                    if (bytes_left == 0) {
                        // finished collecting the utf8 code
                        if (acc <= 127) {
                            *result++ = acc;
                        }
                        else if (isSpecialUnicode(acc)) {
                            *result++ = convertSpecialUnicode(acc);
                        }
                        else {
                            *result++ = repl;
                        }
                        acc = 0;
                    }
                }
            }
        }

        text.erase(result, text.end());
    }

    void
    fixBreakingSpace(std::string &line)
    {
        for (char &c : line) {
            if (c == (char)0xA0) { // "non-breaking space"
                c = ' '; // convert to normal space
            }
        }
    }

    std::string unescape(const std::string & s) {
        std::string text = s;
        dbgTrace(D_WAAP_SAMPLE_PREPROCESS) << "unescape: (0) '" << text << "'";

        fixBreakingSpace(text);
        // 1. remove all unicode characters from string. Basically,
        // remove all characters whose ASCII code is >=128.
        // Python equivalent: text.encode('ascii',errors='ignore')
        filterUnicode(text);
        dbgTrace(D_WAAP_SAMPLE_PREPROCESS) << "unescape: (1) '" << text << "'";

        text = filterUTF7(text);
        dbgTrace(D_WAAP_SAMPLE_PREPROCESS) << "unescape: (1) (after filterUTF7) '" << text << "'";

        // 2. Replace %xx sequences by their single-character equivalents.
        // Also replaces '+' symbol by space character.
        // Python equivalent: text = urllib.unquote_plus(text)
        text.erase(unquote_plus(text.begin(), text.end()), text.end());
        dbgTrace(D_WAAP_SAMPLE_PREPROCESS) << "unescape: (2) '" << text << "'";

        fixBreakingSpace(text);

        // 3. remove all unicode characters from string. Basically,
        // remove all characters whose ASCII code is >=128.
        // Python equivalent: text.encode('ascii',errors='ignore')
        filterUnicode(text);
        dbgTrace(D_WAAP_SAMPLE_PREPROCESS) << "unescape: (3) '" << text << "'";

        // 4. oh shi?... should I handle unicode html entities (python's htmlentitydefs module)???
        // Python equivalent: text = HTMLParser.HTMLParser().unescape(text)
        text.erase(escape_html(text.begin(), text.end()), text.end());
        dbgTrace(D_WAAP_SAMPLE_PREPROCESS) << "unescape: (4) '" << text << "'";

        // 5. Apply backslash escaping (like in C)
        // Python equivalent: text = text.decode('string_escape')
        text.erase(escape_backslashes(text.begin(), text.end()), text.end());
        dbgTrace(D_WAAP_SAMPLE_PREPROCESS) << "unescape: (5) '" << text << "'";

        // 6. remove all unicode characters from string. Basically,
        // remove all characters whose ASCII code is >=128.
        // Python equivalent: text.encode('ascii',errors='ignore')
        filterUnicode(text);
        dbgTrace(D_WAAP_SAMPLE_PREPROCESS) << "unescape: (6) '" << text << "'";

        // 7. Replace %xx sequences by their single-character equivalents.
        // Also replaces '+' symbol by space character.
        // Python equivalent: text = urllib.unquote_plus(text)
        text.erase(unquote_plus(text.begin(), text.end()), text.end());
        dbgTrace(D_WAAP_SAMPLE_PREPROCESS) << "unescape: (7) '" << text << "'";

        unescapeUnicode(text);
        dbgTrace(D_WAAP_SAMPLE_PREPROCESS) << "after unescapeUnicode '" << text << "'";

        // 8. remove all unicode characters from string. Basically,
        // remove all characters whose ASCII code is >=128.
        // Python equivalent: text.encode('ascii',errors='ignore')
        filterUnicode(text);
        dbgTrace(D_WAAP_SAMPLE_PREPROCESS) << "unescape: (8) '" << text << "'";

        // 9. ???
        //
        //try:
        //    text = text.decode('utf-8')
        //except:
        //    pass

        // 10. Replace each sequence of unicode characters with single space
        // Python equivalent: text = re.sub(r'[^\x00-\x7F]+',' ', text)
        // TODO:: actually, in python Pavel do this:
        // text = re.sub(r'[^\x00-\x7F]+',' ', text).encode("ascii","ignore")
        replaceUnicodeSequence(text, ' ');

#if 0 // Removed Aug 25 2018. Reason for removal - breaks input containing ASCII zeros.
        // 11. remove all unicode characters from string.
        // Basically, remove all characters whose ASCII code is >=128.
        // Python equivalent: text.encode('ascii',errors='ignore')
        filterUnicode(text);
#endif

        dbgTrace(D_WAAP_SAMPLE_PREPROCESS) << "unescape: (11) '" << text << "'";

        trimSpaces(text);

        // 12. finally, apply tolower() to all characters of a string
        // std::for_each(text.begin(), text.end(), [](char &c) { c = tolower(c); });
        for (std::string::iterator pC = text.begin(); pC != text.end(); ++pC) {
            *pC = tolower(*pC);
        }

        dbgTrace(D_WAAP_SAMPLE_PREPROCESS) << "unescape: (12) '" << text << "'";
        return text;
    }

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

    static bool isShortWord(const std::string &word)
    {
        return word.size() <= 2;
    }

    static bool isShortHtmlTag(const std::string &word)
    {
        return !word.empty() && word.size() <= 3 && word[0] == '<';
    }

    void
    WaapAssetState::checkRegex(
            const SampleValue &sample,
            const Regex & pattern,
            std::vector<std::string>& keyword_matches,
            Waap::Util::map_of_stringlists_t & found_patterns,
            bool longTextFound,
            bool binaryDataFound) const
    {
        dbgFlow(D_WAAP_SAMPLE_SCAN) << "checkRegex: line='" << sample.getSampleString() << "' patt='" <<
            pattern.getName() << "' longTextFound=" << longTextFound << " binaryDataFound=" << binaryDataFound;

        std::vector<RegexMatch> matches;
        sample.findMatches(pattern, matches);

        for (std::vector<RegexMatch>::const_iterator pMatch = matches.begin(); pMatch != matches.end(); ++pMatch) {
            const RegexMatch& match = *pMatch;

            // Get whole match (group[0], which is always present in any match)
            std::string word = match.groups.front().value;

            dbgTrace(D_WAAP_SAMPLE_SCAN) << "checkRegex: match='" << word << "':";

            // Short words matched by regexes wont be detected in some cases like
            // if enough binary data is present in the value.
            if (binaryDataFound && word.size() <= 2) {
                dbgTrace(D_WAAP_SAMPLE_SCAN) << "Will not add a short keyword '" << word <<
                    "' because binaryData was found";
                continue;
            }

            for (std::vector<RegexMatch::MatchGroup>::const_iterator pGroup = match.groups.begin() + 1;
                pGroup != match.groups.end();
                ++pGroup) {
                std::string group = pGroup->name;

                if (group == "") {
                    continue; // skip unnamed group
                }

                const std::string& value = pGroup->value;
                dbgTrace(D_WAAP_SAMPLE_SCAN) << "checkRegex: group name='" << group <<
                    "' value='" << value << "', word='" << word << "':";

                // python:
                // if 'fast_reg' in group:
                //    if 'evasion' in group:
                //        word = repr(str(''.join(set(value))))
                //    else:
                //        word =group
                if (group.find("fast_reg") != std::string::npos) {
                    dbgTrace(D_WAAP_SAMPLE_SCAN) << "checkRegex: found '*fast_reg*' in group name";
                    if (group.find("evasion") != std::string::npos) {
                        dbgTrace(D_WAAP_SAMPLE_SCAN) <<
                            "checkRegex: found both 'fast_reg' and 'evasion' in group name.";

                        word = "encoded_" + repr_uniq(value);

                        // Normally, the word added to the keyword_matches list contain the character sequence.
                        // However, sometimes (for example in case the sequence contained only unicode characters),
                        // after running repr_uniq() the word will remain empty string. In this case leave
                        // something meaningful/readable there.
                        if (word == "encoded_") {
                            dbgTrace(D_WAAP_SAMPLE_SCAN) <<
                                "checkRegex: empty word after repr_uniq: resetting word to 'character_encoding'"
                                " and group to 'evasion'.";
                            word = "character_encoding";
                        }
                        else if (Waap::Util::str_isalnum(word)) {
                            dbgTrace(D_WAAP_SAMPLE_SCAN) <<
                                "checkRegex: isalnum word after repr_uniq: resetting group to 'evasion'.";
                            // If the found match is alphanumeric (we've seen strings like "640x480" match)
                            // we still should assume evasion but it doesn't need to include "fast_reg",
                            // which would cause unconditional report to stage2 and hit performance...
                            // This is why we remove the word "fast_reg" from the group name.
                            group = "evasion";
                        }

                        if (longTextFound) {
                            dbgTrace(D_WAAP_SAMPLE_SCAN) <<
                                "checkRegex: longTextFound so resetting group name to 'longtext'";
                            group = "longtext";
                        }
                    }
                    else {
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
                    dbgTrace(D_WAAP_SAMPLE_SCAN) << "Not adding keyword '" << word << "' because longtext was found";
                }
                else if (binaryDataFound && (isShortWord(word) || isShortHtmlTag(word) ||
                    NGEN::Regex::regexMatch(__FILE__, __LINE__, group, m_Signatures->binary_data_kw_filter))) {
                    dbgTrace(D_WAAP_SAMPLE_SCAN) << "Not adding group='" << group << "', word='" << word <<
                        "' - due to binary data";
                    continue;
                }
                else if ((std::find(
                    keyword_matches.begin(),
                    keyword_matches.end(),
                    word) == keyword_matches.end())) {
                    // python: if (word not in current_matches): current_matches.append(word)
                    keyword_matches.push_back(word);
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
                if (std::find(
                    found_patterns[group].begin(),
                    found_patterns[group].end(),
                    value
                ) == found_patterns[group].end()) {
                    found_patterns[group].push_back(value);
                }
            }
        }
    }

    // TODO:: implement onload mechanism.
    static bool isOnLoad = 0;

static void calcRepeatAndWordsCount(const std::string &line, unsigned int &repeat, unsigned int &wordsCount)
{
    repeat = 0;
    wordsCount = 0;
    int prev = -1;
    int prevPrev = -1;

    for (std::string::const_iterator pC = line.begin(); pC != line.end(); ++pC) {
        if (*pC == prev || *pC == prevPrev) {
            repeat++;
        }

        if (Waap::Util::isAlphaAsciiFast(*pC) && !Waap::Util::isAlphaAsciiFast(prev)) {
            wordsCount++;
        }

        prevPrev = prev;
        prev = *pC;
    }
}

static void calcRepetitionAndProbing(Waf2ScanResult &res, const std::set<std::string> *ignored_keywords,
        const std::string &line, bool &detectedRepetition, bool &detectedProbing, unsigned int &wordsCount)
{
    unsigned int repeat;
    calcRepeatAndWordsCount(line, repeat, wordsCount);

    if (!detectedRepetition && repeat>100) { // detect potential buffer overflow attacks
            dbgTrace(D_WAAP_SAMPLE_SCAN) << "repetition detected: repeat=" << repeat;
        detectedRepetition = true;
        res.keyword_matches.push_back("repetition");
    }

    // python:
    // keywords_num = sum(1 for x in keyword_matches if x not in ignored_keywords)
    size_t keywords_num = countNotInSet(res.keyword_matches, *ignored_keywords);

    dbgTrace(D_WAAP_SAMPLE_SCAN) << "wordsCount: " << wordsCount << ", repeat=" << repeat
        << ", keyword_matches(num=" << keywords_num << ", size=" << res.keyword_matches.size() << ")";

    if (!detectedProbing //res.keyword_matches.size()
        && keywords_num + 2 > wordsCount
        // res.keyword_matches.size()
        && keywords_num != 0)
    {
        dbgTrace(D_WAAP_SAMPLE_SCAN) << "probing detected: keywords_num=" << keywords_num <<
            ", wordsCount=" << wordsCount;
        detectedProbing = true;
        res.keyword_matches.push_back("probing");
    }
}

void
WaapAssetState::filterKeywordsDueToLongText(Waf2ScanResult &res) const
{
    // Test for long value without spaces (these can often cause false alarms)
    if (m_Signatures->nospaces_long_value_re.hasMatch(res.unescaped_line)) {
        dbgTrace(D_WAAP_SAMPLE_SCAN) << "nospaces_long_value matched. may remove some keywords below...";
        // remove some keywords that are often present in such long lines
        std::vector<std::string> &v = res.keyword_matches;
        for (std::vector<std::string>::iterator it = v.begin(); it != v.end();) {
            std::string &word = *it;
            if (m_Signatures->ignored_for_nospace_long_value.find(word) !=
                m_Signatures->ignored_for_nospace_long_value.end()) {
                dbgTrace(D_WAAP_SAMPLE_SCAN)
                    << "Removing keyword '"
                    << word
                    << "' because nospaces_long_value was found";
                it = v.erase(it);
            }
            else {
                ++it;
            }
        }
    }

#ifdef WAF2_LOGGING_ENABLE
    // Dump interesting statistics and scores
    print_filtered("keywords", *ignored_keywords, res.keyword_matches);
    print_found_patterns(res.found_patterns);
    dbgTrace(D_WAAP_SAMPLE_SCAN) << "keyword_matches.size()=" << res.keyword_matches.size();
#endif
}

bool
checkBinaryData(const std::string &line, bool binaryDataFound)
{
    // Test whether count of non-printable characters in the parameter value is too high.
    // Note that high-ASCII characters (>=128) are assumed "printable".
    // All non-ASCII UTF-8 characters fall into this cathegory.
    if (!binaryDataFound && line.size() > 25) {
        size_t nonPrintableCharsCount = 0;

        for (size_t i=0; i<line.size(); ++i) {
            unsigned char ch = (unsigned char)(line[i]);
            if (!isprint(ch) && (ch != '\r') && (ch != '\t') && (ch != '\n')) {
                nonPrintableCharsCount++;
            }
        }

        dbgTrace(D_WAAP_SAMPLE_SCAN) << "checkBinaryData('" << line << "'): non-printable=" <<
            nonPrintableCharsCount << ", len=" << line.size();

        // note: the threshold here is the same as used in base64 decoding (in function b64DecodeChunk)
        if (nonPrintableCharsCount * 32 >= line.size()*10) {
            dbgTrace(D_WAAP_SAMPLE_SCAN) <<  "checkBinaryData('" << line << "'): detected BINARY DATA";
            binaryDataFound = true;
        }
    }
    return binaryDataFound;
}

bool
WaapAssetState::apply(
    const std::string &line,
    Waf2ScanResult &res,
    const std::string &scanStage,
    bool isBinaryData,
    const Maybe<std::string> splitType) const
{
    dbgTrace(D_WAAP_SAMPLE_SCAN)
        << "WaapAssetState::apply('"
        << line
        << "', scanStage="
        << scanStage
        << ", splitType='"
        << (splitType.ok() ? *splitType: "")
        << "'";

    // Handle response scan stages
    if (scanStage == "resp_body") {
        res.clear();
        SampleValue sample(line, nullptr);
        checkRegex(sample,
            m_Signatures->resp_body_words_regex_list,
            res.keyword_matches,
            res.found_patterns,
            false,
            false);
        checkRegex(sample,
            m_Signatures->resp_body_pattern_regex_list,
            res.keyword_matches,
            res.found_patterns,
            false,
            false);
        dbgTrace(D_WAAP_SAMPLE_SCAN) << "WaapAssetState::apply(): response body " <<
            (res.keyword_matches.empty() ? "is not" : "is") << " suspicious";
        return !res.keyword_matches.empty();
    }

    if (scanStage == "resp_header") {
        res.clear();
        SampleValue sample(line, nullptr);
        checkRegex(sample,
            m_Signatures->resp_body_words_regex_list,
            res.keyword_matches,
            res.found_patterns,
            false,
            false);
        checkRegex(sample,
            m_Signatures->resp_body_pattern_regex_list,
            res.keyword_matches,
            res.found_patterns,
            false,
            false);
        dbgTrace(D_WAAP_SAMPLE_SCAN) << "WaapAssetState::apply(): response header " <<
            (res.keyword_matches.empty() ? "is not" : "is") << " suspicious";
        return !res.keyword_matches.empty();
    }

    // Only cache values less or equal than MAX_CACHE_VALUE_SIZE
    bool shouldCache = (line.size() <= MAX_CACHE_VALUE_SIZE);

    if (shouldCache) {
        // Handle cached clean values
        CacheKey cache_key(line, scanStage, isBinaryData, splitType.ok() ? *splitType : "");
        if (m_cleanValuesCache.exist(cache_key)) {
            dbgTrace(D_WAAP_SAMPLE_SCAN) << "WaapAssetState::apply('" << line << "'): not suspicious (cache)";
            res.clear();
            return false;
        }

        // Handle cached suspicious values (if found - fills out the "res" structure)
        if (m_suspiciousValuesCache.get(cache_key, res)) {
            dbgTrace(D_WAAP_SAMPLE_SCAN) << "WaapAssetState::apply('" << line << "'): suspicious (cache)";

#ifdef WAF2_LOGGING_ENABLE
            // Dump cached result
            print_filtered("keywords", std::set<std::string>(), res.keyword_matches);
            print_filtered("patterns", std::set<std::string>(), res.regex_matches);
            print_found_patterns(res.found_patterns);
#endif
            return true;
        }
    }

    dbgTrace(D_WAAP_SAMPLE_SCAN) << "WaapAssetState::apply('" << line << "'): passed the cache check.";

    const std::set<std::string>* ignored_keywords = &m_Signatures->global_ignored_keywords;
    const std::set<std::string>* ignored_patterns = &m_Signatures->global_ignored_patterns;
    bool isUrlScanStage = false;
    bool isHeaderScanStage = false;

    if ((scanStage.size() == 3 && scanStage == "url") || (scanStage.size() == 7 && scanStage == "referer")) {
        if (m_Signatures->url_ignored_re.hasMatch(line)) {
            dbgTrace(D_WAAP_SAMPLE_SCAN) << "WaapAssetState::apply('" << line << "'): ignored for URL.";

            if (shouldCache) {
                m_cleanValuesCache.insert(CacheKey(line, scanStage, isBinaryData, splitType.ok() ? *splitType : ""));
            }

            res.clear();
            return false;
        }

        ignored_keywords = &m_Signatures->url_ignored_keywords;
        ignored_patterns = &m_Signatures->url_ignored_patterns;
        isUrlScanStage = true;
    }
    else if ((scanStage.size() == 6 && scanStage == "header") ||
        (scanStage.size() == 6 && scanStage == "cookie")) {
        if (m_Signatures->header_ignored_re.hasMatch(line)) {
            dbgTrace(D_WAAP_SAMPLE_SCAN) << "WaapAssetState::apply('" << line << "'): ignored for header.";

            if (shouldCache) {
                m_cleanValuesCache.insert(CacheKey(line, scanStage, isBinaryData, splitType.ok() ? *splitType : ""));
            }

            res.clear();
            return false;
        }

        ignored_keywords = &m_Signatures->header_ignored_keywords;
        ignored_patterns = &m_Signatures->header_ignored_patterns;
        isHeaderScanStage = true;
    }

#if 0
    // Removed by Pavel's request. Leaving here in case he'll want to add this back...
    //// Pavel told me he wants to use "global" settings for cookie values, rather than cookie-specific ones here.
    //else if (scanStage.size() == 6 && (scanStage == "cookie")) {
    //    if (cookie_ignored_re.hasMatch(line)) {
    //        dbgTrace(D_WAAP_SAMPLE_SCAN) << "WaapAssetState::apply('" << line << "'): ignored for cookie.";
    //        if (shouldCache) {
    //            m_cleanValuesCache.insert(CacheKey(line, scanStage));
    //        }
    //        res.clear();
    //        return false;
    //    }

    //    ignored_keywords = &cookie_ignored_keywords;
    //    ignored_patterns = &cookie_ignored_patterns;
    //}
#endif

// Only perform these checks under load
    if (isOnLoad) {
        // Skip values that are too short
        if (line.length() < 3) {
            dbgTrace(D_WAAP_SAMPLE_SCAN) << "WaapAssetState::apply('" << line <<
                "'): skipping: did not pass the length check.";

            if (shouldCache) {
                m_cleanValuesCache.insert(CacheKey(line, scanStage, isBinaryData, splitType.ok() ? *splitType : ""));
            }

            res.clear();
            return false;
        }

        // Skip values where all characters are alphanumeric
        bool allAlNum = true;

        for (std::string::const_iterator pC = line.begin(); pC != line.end(); ++pC) {
            if (!isalnum(*pC)) {
                allAlNum = false;
                break;
            }
        }

        if (allAlNum) {
            if (shouldCache) {
                m_cleanValuesCache.insert(CacheKey(line, scanStage, isBinaryData, splitType.ok() ? *splitType : ""));
            }

            res.clear();
            return false;
        }

        dbgTrace(D_WAAP_SAMPLE_SCAN) << "WaapAssetState::apply('" << line << "'): passed the stateless checks.";

        // Skip values that are longer than 10 characters, and match allowed_text_re regex
        if (line.length() > 10) {
            if (m_Signatures->allowed_text_re.hasMatch(line) > 0) {
                dbgTrace(D_WAAP_SAMPLE_SCAN) << "WaapAssetState::apply('" << line <<
                    "'): matched on allowed_text - ignoring.";

                if (shouldCache) {
                    m_cleanValuesCache.insert(
                        CacheKey(line, scanStage, isBinaryData, splitType.ok() ? *splitType : "")
                    );
                }

                res.clear();
                return false;
            }
        }
    }

    std::string unquote_line = line;
    unquote_line.erase(unquote_plus(unquote_line.begin(), unquote_line.end()), unquote_line.end());

    // If binary data type is detected outside the scanner - enable filtering specific matches/keywords
    bool binaryDataFound =
        checkBinaryData(unquote_line, isBinaryData) ||
        checkBinaryData(line, isBinaryData);

    // Complex unescape and then apply lowercase
    res.unescaped_line = unescape(line);

    dbgTrace(D_WAAP_SAMPLE_SCAN) << "unescapedLine: '" << res.unescaped_line << "'";

    // Detect long text spans, and also any-length spans that end with file extensions such as ".jpg"
    bool longTextFound = m_Signatures->longtext_re.hasMatch(res.unescaped_line);

    if (longTextFound) {
        dbgTrace(D_WAAP_SAMPLE_SCAN) << "longtext found";
    }

    dbgTrace(D_WAAP_SAMPLE_SCAN) << "doing first set of checkRegex calls...";

    // Scan unescaped_line with aho-corasick once, and reuse it in multiple calls to checkRegex below
    // This is done to improve performance of regex matching.
    SampleValue unescapedLineSample(res.unescaped_line, m_Signatures->m_regexPreconditions);

    checkRegex(
        unescapedLineSample,
        m_Signatures->specific_acuracy_keywords_regex,
        res.keyword_matches,
        res.found_patterns,
        longTextFound,
        binaryDataFound
    );
    checkRegex(unescapedLineSample, m_Signatures->words_regex, res.keyword_matches, res.found_patterns, longTextFound,
        binaryDataFound);

    filterKeywordsDueToLongText(res);

    bool detectedRepetition = false;
    bool detectedProbing = false;
    unsigned int wordsCount = 0;

    // Calculate repetition and/or probing indicators
    if (!binaryDataFound) {
        calcRepetitionAndProbing(res, ignored_keywords, res.unescaped_line, detectedRepetition, detectedProbing,
            wordsCount);
    }

    // List of keywords to remove
    std::vector<std::string> keywordsToRemove;

    // Handle semicolon and pipe-split values.
    // Specifically exclude split cookie values to avoid high-probability high-impact false positives.
    // note: All-digits values triggers fp when prepended with separator, so they are excluded
    if (scanStage != "cookie" && splitType.ok() && !Waap::Util::isAllDigits(res.unescaped_line)) {
        dbgTrace(D_WAAP_EVASIONS) << "split value detected type='" << *splitType << "' value='" << line << "'";

        // Split value detected eligible for special handling. Scan it after prepending the appropriate prefix
        std::string unescaped;

        std::set<std::string> keywords_to_filter {
            "probing",
            "os_cmd_sep_medium_acuracy"
        };

        if (*splitType == "sem") {
            keywords_to_filter.insert(";");
            unescaped = ";" + res.unescaped_line;
        } else if (*splitType == "pipe") {
            keywords_to_filter.insert("|");
            unescaped = "|" + res.unescaped_line;
        }

        SampleValue unescapedSample(unescaped, m_Signatures->m_regexPreconditions);
        checkRegex(unescapedSample, m_Signatures->specific_acuracy_keywords_regex, res.keyword_matches,
            res.found_patterns, longTextFound, binaryDataFound);
        checkRegex(unescapedSample, m_Signatures->words_regex, res.keyword_matches, res.found_patterns,
            longTextFound, binaryDataFound);
        checkRegex(unescapedSample, m_Signatures->pattern_regex, res.regex_matches, res.found_patterns,
            longTextFound, binaryDataFound);

        filterKeywordsDueToLongText(res);

        // If only the filtered keywords were detected (no extras) - filter them. If any extra keyword is detected
        // then leave everything
        if (countNotInSet(res.keyword_matches, keywords_to_filter) == 0) {
            for (const std::string &keyword_to_filter : keywords_to_filter) {
                keywordsToRemove.push_back(keyword_to_filter);
            }
        }

        if (!binaryDataFound) {
            // Recalculate repetition and/or probing indicators
            unsigned int newWordsCount = 0;
            calcRepetitionAndProbing(res, ignored_keywords, unescaped, detectedRepetition, detectedProbing,
                newWordsCount);
            // Take minimal words count because empirically it means evasion was probably succesfully decoded
            wordsCount = std::min(wordsCount, newWordsCount);
        }
    }

    bool os_cmd_ev = Waap::Util::find_in_map_of_stringlists_keys("os_cmd_ev", res.found_patterns);

    if (os_cmd_ev) {
        dbgTrace(D_WAAP_EVASIONS) << "os command evasion found";

        // Possible os command evasion detected: - clean up and scan with regexes again.
        std::string unescaped;
        size_t kwCount = res.keyword_matches.size();
        size_t pos = 0;
        size_t found;

        do {
            found = res.unescaped_line.find('[', pos);
            if (found != std::string::npos)
            {
                unescaped += res.unescaped_line.substr(pos, found-pos);
                if (found + 3 < res.unescaped_line.size() &&
                    res.unescaped_line[found+1] == res.unescaped_line[found+2] && res.unescaped_line[found+3] == ']')
                {
                    unescaped += res.unescaped_line[found+1];
                    pos = found+4; // [aa]
                }
                else
                {
                    unescaped += res.unescaped_line[found];
                    pos = found+1;
                }
            }
        } while(found != std::string::npos);
        unescaped += res.unescaped_line.substr(pos); // add tail

        if (res.unescaped_line != unescaped) {
            SampleValue unescapedSample(unescaped, m_Signatures->m_regexPreconditions);
            checkRegex(unescapedSample, m_Signatures->specific_acuracy_keywords_regex, res.keyword_matches,
                res.found_patterns, longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->words_regex, res.keyword_matches, res.found_patterns,
                longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->pattern_regex, res.regex_matches, res.found_patterns,
                longTextFound, binaryDataFound);
        }

        if (kwCount == res.keyword_matches.size()) {
            // Remove the evasion keyword if no real evasion found
            keywordsToRemove.push_back("os_cmd_ev");
            os_cmd_ev = false;
        }
        else if (!binaryDataFound) {
            // Recalculate repetition and/or probing indicators
            unsigned int newWordsCount = 0;
            calcRepetitionAndProbing(res, ignored_keywords, unescaped, detectedRepetition, detectedProbing,
                newWordsCount);
            // Take minimal words count because empirically it means evasion was probably succesfully decoded
            wordsCount = std::min(wordsCount, newWordsCount);
        }
    }

    bool quotes_ev = Waap::Util::find_in_map_of_stringlists_keys("quotes_ev", res.found_patterns);

    if (quotes_ev) {
        dbgTrace(D_WAAP_EVASIONS) << "quotes evasion found";

        // Possible quotes evasion detected: - clean up and scan with regexes again.

        std::string unescaped = m_Signatures->quotes_ev_pattern.sub(res.unescaped_line);

        size_t kwCount = res.keyword_matches.size();

        if (res.unescaped_line != unescaped) {
            SampleValue unescapedSample(unescaped, m_Signatures->m_regexPreconditions);
            checkRegex(unescapedSample, m_Signatures->specific_acuracy_keywords_regex, res.keyword_matches,
                res.found_patterns, longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->words_regex, res.keyword_matches, res.found_patterns,
                longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->pattern_regex, res.regex_matches, res.found_patterns,
                longTextFound, binaryDataFound);
        }

        if (kwCount == res.keyword_matches.size()) {
            // Remove the evasion keyword if no real evasion found
            keywordsToRemove.push_back("quotes_ev");
            quotes_ev = false;
        }
        else if (!binaryDataFound) {
            // Recalculate repetition and/or probing indicators
            unsigned int newWordsCount = 0;
            calcRepetitionAndProbing(res, ignored_keywords, unescaped, detectedRepetition, detectedProbing,
                newWordsCount);
            // Take minimal words count because empirically it means evasion was probably succesfully decoded
            wordsCount = std::min(wordsCount, newWordsCount);
        }
    }

    if (Waap::Util::containsInvalidUtf8(line)) {
        dbgTrace(D_WAAP_EVASIONS) << "invalid utf-8 evasion found";

        // Possible quotes evasion detected: - clean up and scan with regexes again.

        std::string unescaped = Waap::Util::unescapeInvalidUtf8(line);

        size_t kwCount = res.keyword_matches.size();
        unescaped = unescape(unescaped);

        if (res.unescaped_line != unescaped) {
            SampleValue unescapedSample(unescaped, m_Signatures->m_regexPreconditions);
            checkRegex(unescapedSample, m_Signatures->specific_acuracy_keywords_regex, res.keyword_matches,
                res.found_patterns, longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->words_regex, res.keyword_matches, res.found_patterns,
                longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->pattern_regex, res.regex_matches, res.found_patterns,
                longTextFound, binaryDataFound);
        }

        if (kwCount != res.keyword_matches.size() && !binaryDataFound) {
            // Recalculate repetition and/or probing indicators
            unsigned int newWordsCount = 0;
            calcRepetitionAndProbing(res, ignored_keywords, unescaped, detectedRepetition, detectedProbing,
                newWordsCount);
            // Take minimal words count because empirically it means evasion was probably succesfully decoded
            wordsCount = std::min(wordsCount, newWordsCount);
        }
    }

    Maybe<std::string> broken_utf8_line = Waap::Util::containsBrokenUtf8(line, unquote_line);

    if (broken_utf8_line.ok()) {
        dbgTrace(D_WAAP_EVASIONS) << "broken-down utf-8 evasion found";
        std::string unescaped = Waap::Util::unescapeBrokenUtf8(broken_utf8_line.unpack());
        size_t kwCount = res.keyword_matches.size();

        unescaped = unescape(unescaped);

        if (res.unescaped_line != unescaped) {
            SampleValue unescapedSample(unescaped, m_Signatures->m_regexPreconditions);
            checkRegex(unescapedSample, m_Signatures->specific_acuracy_keywords_regex, res.keyword_matches,
                res.found_patterns, longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->words_regex, res.keyword_matches, res.found_patterns,
                longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->pattern_regex, res.regex_matches, res.found_patterns,
                longTextFound, binaryDataFound);
        }

        if (kwCount != res.keyword_matches.size() && !binaryDataFound) {
            // Recalculate repetition and/or probing indicators
            unsigned int newWordsCount = 0;
            calcRepetitionAndProbing(res, ignored_keywords, unescaped, detectedRepetition, detectedProbing,
                newWordsCount);
            // Take minimal words count because empirically it means evasion was probably succesfully decoded
            wordsCount = std::min(wordsCount, newWordsCount);
        }
    }

    bool comment_ev = Waap::Util::find_in_map_of_stringlists_keys("comment_ev", res.found_patterns);

    if (comment_ev) {
        // Possible quotes evasion detected: - clean up and scan with regexes again.
        dbgTrace(D_WAAP_EVASIONS) << "comment evasion found";

        std::string unescaped = m_Signatures->comment_ev_pattern.sub(res.unescaped_line);
        size_t kwCount = res.keyword_matches.size();

        if (res.unescaped_line != unescaped) {
            SampleValue unescapedSample(unescaped, m_Signatures->m_regexPreconditions);
            checkRegex(unescapedSample, m_Signatures->specific_acuracy_keywords_regex, res.keyword_matches,
                res.found_patterns, longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->words_regex, res.keyword_matches, res.found_patterns,
                longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->pattern_regex, res.regex_matches, res.found_patterns,
                longTextFound, binaryDataFound);
        }

        if (kwCount == res.keyword_matches.size()) {
            // Remove the evasion keyword if no real evasion found
            keywordsToRemove.push_back("comment_ev");
            comment_ev = false;
        }
        else if (!binaryDataFound) {
            // Recalculate repetition and/or probing indicators
            unsigned int newWordsCount = 0;
            calcRepetitionAndProbing(res, ignored_keywords, unescaped, detectedRepetition, detectedProbing,
                newWordsCount);
            // Take minimal words count because empirically it means evasion was probably succesfully decoded
            wordsCount = std::min(wordsCount, newWordsCount);
        }
    }

    bool quoutes_space_evasion = Waap::Util::find_in_map_of_stringlists_keys(
        "quotes_space_ev_fast_reg",
        res.found_patterns
    );

    if (quoutes_space_evasion) {
        // Possible quotes space evasion detected: - clean up and scan with regexes again.
        dbgTrace(D_WAAP_EVASIONS) << "quotes space evasion found";
        std::string unescaped = m_Signatures->quotes_space_ev_pattern.sub(res.unescaped_line);
        size_t kwCount = res.keyword_matches.size();

        if (res.unescaped_line != unescaped) {
            SampleValue unescapedSample(unescaped, m_Signatures->m_regexPreconditions);
            checkRegex(unescapedSample, m_Signatures->specific_acuracy_keywords_regex, res.keyword_matches,
                res.found_patterns, longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->words_regex, res.keyword_matches, res.found_patterns,
                longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->pattern_regex, res.regex_matches, res.found_patterns,
                longTextFound, binaryDataFound);
        }

        if (kwCount == res.keyword_matches.size()) {
            // Remove the evasion keyword if no real evasion found
            keywordsToRemove.push_back("quotes_space_evasion");
            quoutes_space_evasion = false;
        }
        else if (!binaryDataFound) {
            // Recalculate repetition and/or probing indicators
            unsigned int newWordsCount = 0;
            calcRepetitionAndProbing(res, ignored_keywords, unescaped, detectedRepetition, detectedProbing,
                newWordsCount);
            // Take minimal words count because empirically it means evasion was probably succesfully decoded
            wordsCount = std::min(wordsCount, newWordsCount);
        }
    }

    if (Waap::Util::testUrlBareUtf8Evasion(line)) {
        // Possible quotes evasion detected: - clean up and scan with regexes again.
        dbgTrace(D_WAAP_EVASIONS) << "url_bare_utf8 evasion found";

        // Revert the encoding and rescan again
        // Insert additional '%' character after each sequence of three characters either "%C0" or "%c0".
        std::string unescaped = line;
        replaceAll(unescaped, "%c0", "%c0%");
        replaceAll(unescaped, "%C0", "%C0%");

        // Run the result through another pass of "unescape" which will now correctly urldecode and utf8-decode it
        unescaped = unescape(unescaped);
        size_t kwCount = res.keyword_matches.size();

        if (res.unescaped_line != unescaped) {
            SampleValue unescapedSample(unescaped, m_Signatures->m_regexPreconditions);
            checkRegex(unescapedSample, m_Signatures->specific_acuracy_keywords_regex, res.keyword_matches,
                res.found_patterns, longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->words_regex, res.keyword_matches, res.found_patterns,
                longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->pattern_regex, res.regex_matches, res.found_patterns,
                longTextFound, binaryDataFound);
        }

        if (kwCount != res.keyword_matches.size() && !binaryDataFound) {
            // Recalculate repetition and/or probing indicators
            unsigned int newWordsCount = 0;
            calcRepetitionAndProbing(res, ignored_keywords, unescaped, detectedRepetition, detectedProbing,
                newWordsCount);
            // Take minimal words count because empirically it means evasion was probably succesfully decoded
            wordsCount = std::min(wordsCount, newWordsCount);
        }
    }

    boost::cmatch what;
    if (boost::regex_search(res.unescaped_line.c_str(), what, sqli_comma_evasion_regex)) {
        // Possible SQLi evasion detected (","): - clean up and scan with regexes again.
        dbgTrace(D_WAAP_EVASIONS) << "Possible SQLi evasion detected (\",\"): - clean up and scan with regexes again.";

        std::string unescaped = res.unescaped_line;
        unescaped = boost::regex_replace(unescaped, sqli_comma_evasion_regex, "");
        unescaped = unescape(unescaped);

        if (res.unescaped_line != unescaped) {
            SampleValue unescapedSample(unescaped, m_Signatures->m_regexPreconditions);
            checkRegex(unescapedSample, m_Signatures->specific_acuracy_keywords_regex, res.keyword_matches,
                    res.found_patterns, longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->words_regex, res.keyword_matches, res.found_patterns,
                    longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->pattern_regex, res.regex_matches, res.found_patterns,
                    longTextFound, binaryDataFound);
        }


        // Recalculate repetition and/or probing indicators
        unsigned int newWordsCount = 0;
        calcRepetitionAndProbing(res, ignored_keywords, unescaped, detectedRepetition, detectedProbing,
                newWordsCount);
        // Take minimal words count because empirically it means evasion was probably succesfully decoded
        wordsCount = std::min(wordsCount, newWordsCount);

    }

    if ((res.unescaped_line.find("0x") != std::string::npos) && evasion_hex_regex.hasMatch(res.unescaped_line)) {
        dbgTrace(D_WAAP_EVASIONS) << "hex evasion found (in unescaped line)";

        std::string unescaped = res.unescaped_line;
        replaceAll(unescaped, "0x", "\\x");
        unescapeUnicode(unescaped);
        dbgTrace(D_WAAP_EVASIONS) << "unescaped =='" << unescaped << "'";

        size_t kwCount = res.keyword_matches.size();

        if (res.unescaped_line != unescaped) {
            SampleValue unescapedSample(unescaped, m_Signatures->m_regexPreconditions);
            checkRegex(unescapedSample, m_Signatures->specific_acuracy_keywords_regex, res.keyword_matches,
                res.found_patterns, false, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->words_regex, res.keyword_matches, res.found_patterns,
                false, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->pattern_regex, res.regex_matches, res.found_patterns,
                false, binaryDataFound);
        }

        if (kwCount != res.keyword_matches.size() && !binaryDataFound) {
            for (const auto &kw : res.keyword_matches) {
                if (kw.size() < 2 || str_contains(kw, "os_cmd_high_acuracy_fast_reg") ||
                        kw == "os_cmd_sep_medium_acuracy" ||   str_contains(kw, "regex_code_execution") ||
                        str_contains(kw, "regex_code_execution") || kw == "character_encoding" ||
                        str_contains(kw, "quotes_ev_fast_reg") || str_contains(kw, "encoded_") ||
                        str_contains(kw, "medium_acuracy") || str_contains(kw, "high_acuracy_fast_reg_xss"))
                {
                    keywordsToRemove.push_back(kw);
                }
            }

            // Recalculate repetition and/or probing indicators
            unsigned int newWordsCount = 0;
            calcRepetitionAndProbing(res, ignored_keywords, unescaped, detectedRepetition, detectedProbing,
                newWordsCount);
            // Take minimal words count because empirically it means evasion was probably succesfully decoded
            wordsCount = std::min(wordsCount, newWordsCount);
        }

    }

    if ((line.find("0x") != std::string::npos) && evasion_hex_regex.hasMatch(line)) {
        dbgTrace(D_WAAP_EVASIONS) << "hex evasion found (in raw line)";
        std::string unescaped = line;
        replaceAll(unescaped, "0x", "\\x");
        unescapeUnicode(unescaped);
        dbgTrace(D_WAAP_EVASIONS) << "unescape == '" << unescaped << "'";

        size_t kwCount = res.keyword_matches.size();

        if (line != unescaped) {
            SampleValue unescapedSample(unescaped, m_Signatures->m_regexPreconditions);
            checkRegex(unescapedSample, m_Signatures->specific_acuracy_keywords_regex, res.keyword_matches,
                res.found_patterns, false, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->words_regex, res.keyword_matches, res.found_patterns,
                false, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->pattern_regex, res.regex_matches, res.found_patterns,
                false, binaryDataFound);
        }

        if (kwCount != res.keyword_matches.size() && !binaryDataFound) {
            for (const auto &kw : res.keyword_matches) {
                if (kw.size() < 2 || str_contains(kw, "os_cmd_high_acuracy_fast_reg") ||
                        kw == "os_cmd_sep_medium_acuracy" ||   str_contains(kw, "regex_code_execution") ||
                        str_contains(kw, "regex_code_execution") || kw == "character_encoding" ||
                        str_contains(kw, "quotes_ev_fast_reg") || str_contains(kw, "encoded_") ||
                        str_contains(kw, "medium_acuracy") || str_contains(kw, "high_acuracy_fast_reg_xss"))
                {
                    keywordsToRemove.push_back(kw);
                }
            }
            // Recalculate repetition and/or probing indicators
            unsigned int newWordsCount = 0;
            calcRepetitionAndProbing(res, ignored_keywords, unescaped, detectedRepetition, detectedProbing,
                newWordsCount);
            // Take minimal words count because empirically it means evasion was probably succesfully decoded
            wordsCount = std::min(wordsCount, newWordsCount);
        }

    }

    if ((res.unescaped_line.find("%") != std::string::npos) && evasion_bad_hex_regex.hasMatch(res.unescaped_line)) {
        dbgTrace(D_WAAP_EVASIONS) << "Bad hex evasion found (%c1%1c or %c1%9c in unescaped line)";

        std::string unescaped = res.unescaped_line;

        unescaped = boost::regex_replace(unescaped, bad_hex_regex, "/");
        unescaped = unescape(unescaped);
        dbgTrace(D_WAAP_EVASIONS) << "unescaped =='" << unescaped << "'";

        size_t kwCount = res.keyword_matches.size();

        if (res.unescaped_line != unescaped) {
            SampleValue unescapedSample(unescaped, m_Signatures->m_regexPreconditions);
            checkRegex(unescapedSample, m_Signatures->specific_acuracy_keywords_regex, res.keyword_matches,
                    res.found_patterns, longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->words_regex, res.keyword_matches, res.found_patterns,
                    longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->pattern_regex, res.regex_matches, res.found_patterns,
                    longTextFound, binaryDataFound);
        }

        if (kwCount != res.keyword_matches.size() && !binaryDataFound) {
            // Recalculate repetition and/or probing indicators
            unsigned int newWordsCount = 0;
            calcRepetitionAndProbing(res, ignored_keywords, unescaped, detectedRepetition, detectedProbing,
                    newWordsCount);
            // Take minimal words count because empirically it means evasion was probably succesfully decoded
            wordsCount = std::min(wordsCount, newWordsCount);
        }

    }

    if ((line.find("%") != std::string::npos) && evasion_bad_hex_regex.hasMatch(line)) {
        dbgTrace(D_WAAP_EVASIONS) << "Bad hex evasion found (%c1%1c or  %c1%9c in raw line)";
        std::string unescaped = line;

        unescaped = boost::regex_replace(unescaped, bad_hex_regex, "/");
        unescaped = unescape(unescaped);
        dbgTrace(D_WAAP_EVASIONS) << "unescaped == '" << unescaped << "'";

        size_t kwCount = res.keyword_matches.size();

        if (line != unescaped) {
            SampleValue unescapedSample(unescaped, m_Signatures->m_regexPreconditions);
            checkRegex(unescapedSample, m_Signatures->specific_acuracy_keywords_regex, res.keyword_matches,
                    res.found_patterns, longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->words_regex, res.keyword_matches, res.found_patterns,
                    longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->pattern_regex, res.regex_matches, res.found_patterns,
                    longTextFound, binaryDataFound);
        }

        if (kwCount != res.keyword_matches.size() && !binaryDataFound) {
            // Recalculate repetition and/or probing indicators
            unsigned int newWordsCount = 0;
            calcRepetitionAndProbing(res, ignored_keywords, unescaped, detectedRepetition, detectedProbing,
                    newWordsCount);
            // Take minimal words count because empirically it means evasion was probably succesfully decoded
            wordsCount = std::min(wordsCount, newWordsCount);
        }
    }

    if ((res.unescaped_line.find("%") != std::string::npos) && utf_evasion_for_dot.hasMatch(res.unescaped_line)) {
        dbgTrace(D_WAAP_EVASIONS) <<
            "UTF evasion for dot found (%c0%*e) in unescaped line";
        std::string unescaped = res.unescaped_line;

        unescaped = boost::regex_replace(unescaped, utf_evasion_for_dot_regex, ".");
        unescaped = unescape(unescaped);
        dbgTrace(D_WAAP_EVASIONS) << "unescaped == '" << unescaped << "'";

        size_t kwCount = res.keyword_matches.size();

        if (res.unescaped_line != unescaped) {
            SampleValue unescapedSample(unescaped, m_Signatures->m_regexPreconditions);
            checkRegex(unescapedSample, m_Signatures->specific_acuracy_keywords_regex, res.keyword_matches,
                    res.found_patterns, longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->words_regex, res.keyword_matches, res.found_patterns,
                    longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->pattern_regex, res.regex_matches, res.found_patterns,
                    longTextFound, binaryDataFound);
        }

        if (kwCount != res.keyword_matches.size() && !binaryDataFound) {
            // Recalculate repetition and/or probing indicators
            unsigned int newWordsCount = 0;
            calcRepetitionAndProbing(res, ignored_keywords, unescaped, detectedRepetition, detectedProbing,
                    newWordsCount);
            // Take minimal words count because empirically it means evasion was probably succesfully decoded
            wordsCount = std::min(wordsCount, newWordsCount);
        }
    }


    if ((line.find("%") != std::string::npos) && utf_evasion_for_dot.hasMatch(line)) {
        dbgTrace(D_WAAP_EVASIONS) << "UTF evasion for dot found (%c0%*e) in raw line";
        std::string unescaped = line;

        unescaped = boost::regex_replace(unescaped, utf_evasion_for_dot_regex, ".");
        unescaped = unescape(unescaped);
        dbgTrace(D_WAAP_EVASIONS) << "unescaped == '" << unescaped << "'";

        size_t kwCount = res.keyword_matches.size();

        if (line != unescaped) {
            SampleValue unescapedSample(unescaped, m_Signatures->m_regexPreconditions);
            checkRegex(unescapedSample, m_Signatures->specific_acuracy_keywords_regex, res.keyword_matches,
                    res.found_patterns, longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->words_regex, res.keyword_matches, res.found_patterns,
                    longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->pattern_regex, res.regex_matches, res.found_patterns,
                    longTextFound, binaryDataFound);
        }

        if (kwCount != res.keyword_matches.size() && !binaryDataFound) {
            // Recalculate repetition and/or probing indicators
            unsigned int newWordsCount = 0;
            calcRepetitionAndProbing(res, ignored_keywords, unescaped, detectedRepetition, detectedProbing,
                    newWordsCount);
            // Take minimal words count because empirically it means evasion was probably succesfully decoded
            wordsCount = std::min(wordsCount, newWordsCount);
        }
    }


    // python: escape ='hi_acur_fast_reg_evasion' in found_patterns
    bool escape = Waap::Util::find_in_map_of_stringlists_keys("evasion", res.found_patterns);

    if (escape) {
        // Possible evasion detected: remove unicode \u and \x sequences,
        // delete all trash in un_escape_pattern, and scan with regexes again.
        dbgTrace(D_WAAP_EVASIONS) << "escape pattern found";

        std::string unescaped = res.unescaped_line;

        dbgTrace(D_WAAP_EVASIONS) << "unescape'" << unescaped << "'";
        replaceAll(unescaped, "0x", "\\x");
        replaceAll(unescaped, "%u", "\\u");
        std::string zero;
        zero.push_back(0);
        replaceAll(unescaped, zero, "");
        unescapeUnicode(unescaped);

        // from python: unescaped = un_escape_pattern.sub(r'',line) + ' ' + un_escape_pattern.sub(r' ',line)
        // note: "line" in python is called "unescaped" in this code.
        unescaped = m_Signatures->un_escape_pattern.sub(unescaped) + " " +
            m_Signatures->un_escape_pattern.sub(unescaped, " ");

        size_t kwCount = res.keyword_matches.size();

        if (res.unescaped_line != unescaped) {
            SampleValue unescapedSample(unescaped, m_Signatures->m_regexPreconditions);
            checkRegex(unescapedSample, m_Signatures->specific_acuracy_keywords_regex, res.keyword_matches,
                res.found_patterns, longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->words_regex, res.keyword_matches, res.found_patterns,
                longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->pattern_regex, res.regex_matches, res.found_patterns,
                longTextFound, binaryDataFound);
        }

        if (kwCount == res.keyword_matches.size()) {
            // Remove the evasion keyword if no real evasion found
            keywordsToRemove.push_back("evasion");
            escape = false;
        }
        else if (!binaryDataFound) {
            // Recalculate repetition and/or probing indicators
            unsigned int newWordsCount = 0;
            calcRepetitionAndProbing(res, ignored_keywords, unescaped, detectedRepetition, detectedProbing,
                newWordsCount);
            // Take minimal words count because empirically it means evasion was probably succesfully decoded
            wordsCount = std::min(wordsCount, newWordsCount);
        }
    }

    // Detect bash "backslash" evasions
    // Note that the search for low binary ASCII codes such as 7 or 8 are done here because
    // unescaped_line after unescape() contains post-processed string, where original \b was already converted to
    // single character (ASCII 8).
    // This should handle cases like /\bin/sh
    unsigned char prev_uch = '\0';
    for (char ch : res.unescaped_line) {
        unsigned char uch = (unsigned char)ch;
        if ((uch >= 0x07 && uch <= 0x0D) || (uch == '\\') || (uch == '/' && prev_uch == '/')) {
            escape = true;
            break;
        }
        prev_uch = uch;
    }

    if (escape) {
        dbgTrace(D_WAAP_EVASIONS) << "try decoding bash evasions";

        // Possible bash evasion detected: - clean up and scan with regexes again.
        dbgTrace(D_WAAP_EVASIONS) << "unescape='" << res.unescaped_line << "'";

        std::string unescaped;
        unescaped.reserve(res.unescaped_line.size()); // preallocate to improve performance of += clauses below

        // Partially revert the effect of the escape_backslashes() function, remove the '\' characters and
        // squash string of successive forward slashes to single slash.
        // This allows us to decode bash evasions like "/\b\i\n/////s\h"
        char prev_ch = '\0';
        for (char ch : res.unescaped_line) {
                switch (ch) {
                        case 7: unescaped += "a"; break;
                        case 8: unescaped += "b"; break;
                        case 9: unescaped += "t"; break;
                        case 10: unescaped += "n"; break;
                        case 11: unescaped += "v"; break;
                        case 12: unescaped += "f"; break;
                        case 13: unescaped += "r"; break;
                        case '\\': break; // remove backslashes
                        default:
                                // squash strings of successive '/' characters into single '/' character
                                if (prev_ch == '/' && ch == '/') {
                                        break;
                                }
                                unescaped += ch;
                }

                prev_ch = ch;
        }

        size_t kwCount = res.keyword_matches.size();

        if (res.unescaped_line != unescaped) {
            SampleValue unescapedSample(unescaped, m_Signatures->m_regexPreconditions);
            checkRegex(unescapedSample, m_Signatures->specific_acuracy_keywords_regex, res.keyword_matches,
                res.found_patterns, longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->words_regex, res.keyword_matches, res.found_patterns,
                longTextFound, binaryDataFound);
            checkRegex(unescapedSample, m_Signatures->pattern_regex, res.regex_matches, res.found_patterns,
                longTextFound, binaryDataFound);
        }

        if (kwCount == res.keyword_matches.size()) {
            // Remove the evasion keyword if no real evasion found
            keywordsToRemove.push_back("evasion");
            escape = false;
        }
        else if (!binaryDataFound) {
            // Recalculate repetition and/or probing indicators
            unsigned int newWordsCount = 0;
            calcRepetitionAndProbing(res, ignored_keywords, unescaped, detectedRepetition, detectedProbing,
                newWordsCount);
            // Take minimal words count because empirically it means evasion was probably succesfully decoded
            wordsCount = std::min(wordsCount, newWordsCount);
        }
    }

    // Remove evasion keywords that should not be reported because there's no real evasion found
    if (!keywordsToRemove.empty()) {
        dbgTrace(D_WAAP_SAMPLE_SCAN)
            << "Removing these keywords (probably due to evasions): "
            << Waap::Util::vecToString(keywordsToRemove);
    }

    for (const auto &value : keywordsToRemove) {
        Waap::Util::remove_startswith(res.keyword_matches, value);
        Waap::Util::remove_in_map_of_stringlists_keys(value, res.found_patterns);
    }


    // python:
    // if headers:
    //      keyword_matches = [x for x in keyword_matches if x not in '\(/);$=']
    if (isHeaderScanStage) {
        removeItemsMatchingSubstringOf(res.keyword_matches, "\\(/);$=");
        // For headers, also remove all ignored patterns entirely, not just ignore it from counts
        for (const auto &ignored_pattern : *ignored_patterns) {
            if (res.found_patterns.erase(ignored_pattern)) {
                dbgTrace(D_WAAP_SAMPLE_SCAN) << "Removed the found pattern in header: '" << ignored_pattern << "'";
            }
        }
    }

    // python:
    // keywords_num = sum(1 for x in keyword_matches if x not in ignored_keywords)
    size_t keywords_num = countNotInSet(res.keyword_matches, *ignored_keywords);
    size_t regex_num = countNotInSet(res.regex_matches, *ignored_patterns);

    bool forceReport = isUrlScanStage && Waap::Util::find_in_map_of_stringlists_keys("url", res.found_patterns);

    if (forceReport) {
        dbgTrace(D_WAAP_SAMPLE_SCAN) << "setting forceReport becacuse we are in url context and "
            "'high_acuracy_fast_reg_evation' pattern is found!";
    }

    // python:
    // if keywords_num >2 or ('acuracy' in  patterns and not headers) or
    // special_patten in patterns or 'probing' in keyword_matches  or 'repetition' in keyword_matches:
    if (keywords_num + regex_num > 2 ||
        Waap::Util::find_in_map_of_stringlists_keys("acur", res.found_patterns) ||
        forceReport ||
        detectedRepetition ||
        detectedProbing) {
        dbgTrace(D_WAAP_SAMPLE_SCAN) << "pre-suspicion found.";
        // apply regex signatures
        checkRegex(unescapedLineSample, m_Signatures->pattern_regex, res.regex_matches, res.found_patterns,
            longTextFound, binaryDataFound);

        // python:
        // if len(regex_matches) and 'probing' not in keyword_matches:
        //    if len(keyword_matches+regex_matches)+2>words:
        //        keyword_matches.append('probing')
        if (!binaryDataFound && res.regex_matches.size() > 0 && !detectedProbing) {
            // if len(''.join(res.keyword_matches+res.regex_matches))>=alphanumeric_num {
            if (res.keyword_matches.size() + res.regex_matches.size() + 2 > wordsCount) {
                detectedProbing = true;
                res.keyword_matches.push_back("probing");
            }
        }

        // python:
        // keywords_num = sum(1 for x in keyword_matches if x not in ignored_keywords)
        keywords_num = countNotInSet(res.keyword_matches, *ignored_keywords);
        regex_num = countNotInSet(res.regex_matches, *ignored_patterns);

        // Regular (medium) acuracy contributes 1 to the score.
        // High acuracy contributes 2 to the score.
        int acuracy = 0;

        // python:
        // if 'acuracy' in patterns and not url:
        if (Waap::Util::find_in_map_of_stringlists_keys("acur", res.found_patterns))
        {
            acuracy = 1;
            // search for "high_acuracy" or "hi_acur" signature names
            if (Waap::Util::find_in_map_of_stringlists_keys("high", res.found_patterns) ||
                Waap::Util::find_in_map_of_stringlists_keys("hi_acur", res.found_patterns))
            {
                acuracy = 2;
            }
        }

        // "Acuracy" contribution alone won't trigger suspicion yet. It needs additional boost
        // of finding some keywords and/or matched regexes.
        int score = keywords_num + acuracy + (2 * regex_num);

#ifdef WAF2_LOGGING_ENABLE
        // Dump interesting statistics and scores
        print_filtered("keywords", *ignored_keywords, res.keyword_matches);
        print_filtered("patterns", *ignored_patterns, res.regex_matches);
        print_found_patterns(res.found_patterns);

        dbgTrace(D_WAAP_SAMPLE_SCAN) << "before decision: keywords(num=" << keywords_num << ", size=" <<
            res.keyword_matches.size() << "); regex(num=" << regex_num << ", size=" << res.regex_matches.size() <<
            "; acuracy=" << acuracy << "; score=" << score << "; forceReport=" << forceReport << "; probing=" <<
            detectedProbing << "; repetition=" << detectedRepetition << "; 'fast_reg' in found_patterns: " <<
            Waap::Util::find_in_map_of_stringlists_keys("fast_reg", res.found_patterns);
#endif

        // python:
        // if (keywords_num+acuracy+2*regex_num)>2 or  special_patten in patterns or
        // 'fast_reg' in patterns  or 'probing' in keyword_matches  or 'repetition' in keyword_matches:
        if (score > 2 ||
            forceReport ||
            detectedProbing ||
            detectedRepetition ||
            Waap::Util::find_in_map_of_stringlists_keys("fast_reg", res.found_patterns)) {
            dbgTrace(D_WAAP_SAMPLE_SCAN) << "apply(): suspicion found (score=" << score << ").";

            if (shouldCache) {
                m_suspiciousValuesCache.insert(
                    {CacheKey(line, scanStage, isBinaryData, splitType.ok() ? *splitType : ""), res}
                );
            }

            return true; // suspicion found
        }

        dbgTrace(D_WAAP_SAMPLE_SCAN) << "apply(): suspicion not found (score=" << score << ").";
    }

    dbgTrace(D_WAAP_SAMPLE_SCAN) << "apply(): not suspicious.";

    if (shouldCache) {
        m_cleanValuesCache.insert(CacheKey(line, scanStage, isBinaryData, splitType.ok() ? *splitType : ""));
    }

    res.clear();
    return false;
}

void WaapAssetState::updateScores()
{
    scoreBuilder.snap();
}

std::string WaapAssetState::getWaapDataFileName() const {
    return m_waapDataFileName;
}

std::map<std::string, std::vector<std::string>>& WaapAssetState::getFilterVerbose()
{
    return m_filtered_keywords_verbose;
}

std::string WaapAssetState::getWaapDataDir() const {
    size_t lastSlash = m_waapDataFileName.find_last_of('/');
    std::string sigsFilterDir = ((lastSlash == std::string::npos) ?
        m_waapDataFileName : m_waapDataFileName.substr(0, lastSlash));
    dbgTrace(D_WAAP_ASSET_STATE) << " signatures filters directory: " << sigsFilterDir;
    return sigsFilterDir;
}

void WaapAssetState::updateFilterManagerPolicy(IWaapConfig* pConfig)
{
    m_filtersMngr->loadPolicy(pConfig);
}

bool WaapAssetState::isKeywordOfType(const std::string& keyword, ParamType type) const
{
    return m_typeValidator.isKeywordOfType(keyword, type);
}

bool WaapAssetState::isBinarySampleType(const std::string & sample) const
{
    // Binary data detection is based on existance of at least two ASCII NUL bytes
    size_t nulBytePos = sample.find('\0', 0);
    if (nulBytePos != std::string::npos) {
        nulBytePos = sample.find('\0', nulBytePos+1);
        if (nulBytePos != std::string::npos) {
            dbgTrace(D_WAAP_ASSET_STATE) << "binary_input sample type detected (nul bytes)";
            return true;
        }
    }

    std::vector<RegexMatch> matches;
    m_Signatures->format_magic_binary_re.findAllMatches(sample, matches);
    if (!matches.empty()) {
        dbgTrace(D_WAAP_ASSET_STATE) << "binary_input sample type detected (signature)";
        return true;
    }

    return false;
}

static Maybe<uint8_t>
parse_wbxml_uint8(const std::string & sample, size_t &offset)
{
    if (offset >= sample.size()) {
        return genError("not wbxml");
    }
    return sample[offset++];
}

static Maybe<uint32_t>
parse_wbxml_mb_uint32(const std::string & sample, size_t &offset)
{
    uint32_t value = 0;
    for (int i=0; i < 5; i++) {
        Maybe<uint8_t> v = parse_wbxml_uint8(sample, offset);
        if (!v.ok()) return genError("not wbxml");
        value = (value << 7) | (*v & 0x7F);
        if ((*v & 0x80) == 0) {
            return value;
        }
    }
    return genError("not wbxml");
}

bool WaapAssetState::isWBXMLSampleType(const std::string & sample) const
{
    size_t offset = 0;
    // Parse protocol version
    Maybe<uint8_t> version = parse_wbxml_uint8(sample, offset);
    // Support only wbxml protocol versions 1-3 which can be more or less reliably detected
    if (!version.ok() || *version==0 || *version > 0x03) return false;
    // Parse public id
    Maybe<uint32_t> public_id = parse_wbxml_mb_uint32(sample, offset);
    if (!public_id.ok()) return false;
    // Parse and validate charset (this is optional for v0 but we don't detect v0 anyway)
    Maybe<uint32_t> charset = parse_wbxml_mb_uint32(sample, offset);
    if (!charset.ok()) return false;
    // Only subset of charsets are allowed
    static const uint32_t allowed_charsets[] = {0, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 17, 106, 1000, 1015, 2026};
    if (std::find(std::begin(allowed_charsets), std::end(allowed_charsets), *charset) ==
        std::end(allowed_charsets))
    {
        return false;
    }
    Maybe<uint32_t> strtbl_len = parse_wbxml_mb_uint32(sample, offset);
    return strtbl_len.ok() && *strtbl_len <= sample.size() - offset;
}

std::set<std::string> WaapAssetState::getSampleType(const std::string & sample) const
{
    std::set<std::string> types;
    bool shouldCache = (sample.size() <= MAX_CACHE_VALUE_SIZE);

    // Handle cached clean values
    if (shouldCache && m_sampleTypeCache.exist(sample)) {
        dbgTrace(D_WAAP_ASSET_STATE) << "WaapAssetState::getSampleType() sample: '" << sample <<
            "' type is unknown (cache)";
        types.insert("unknown");
        return types;
    }

    for (auto& type_re : m_Signatures->params_type_re)
    {
        dbgTrace(D_WAAP_ASSET_STATE) << "WaapAssetState::getSampleType checking: " << sample <<
            " against " << type_re.first;
        std::vector<RegexMatch> matches;
        type_re.second->findAllMatches(sample, matches);

        dbgTrace(D_WAAP_ASSET_STATE) << "number of matched keywords: " << matches.size();
        if (matches.empty())
        {
            continue;
        }

        types.insert(type_re.first);
    }

    // Binary data detection is based on existance of at least two ASCII NUL bytes
    if (isBinarySampleType(sample)) {
        dbgTrace(D_WAAP_ASSET_STATE) << "reporting binary_input sample type";
        types.insert("binary_input");
    }

    if (types.empty())
    {
        types.insert("unknown");
        m_sampleTypeCache.insert(sample);
    }

    return types;
}

void WaapAssetState::logIndicatorsInFilters(const std::string &param, Waap::Keywords::KeywordsSet& keywords,
    IWaf2Transaction* pTransaction)
{
    m_filtersMngr->registerKeywords(param, keywords, pTransaction);
}

void WaapAssetState::logParamHit(Waf2ScanResult& res, IWaf2Transaction* pTransaction)
{
    Waap::Keywords::KeywordsSet emptySet;
    std::string key = IndicatorsFiltersManager::generateKey(res.location, res.param_name, pTransaction);
    m_filtersMngr->registerKeywords(key, emptySet, pTransaction);
}

void WaapAssetState::filterKeywords(
    const std::string &param,
    Waap::Keywords::KeywordsSet& keywords,
    std::vector<std::string>& filteredKeywords)
{
    dbgTrace(D_WAAP_ASSET_STATE) << "filter keywords";
    m_filtersMngr->filterKeywords(param, keywords, filteredKeywords);
}

void WaapAssetState::clearFilterVerbose()
{
    m_filtered_keywords_verbose.clear();
}

void WaapAssetState::filterVerbose(const std::string &param,
    std::vector<std::string>& filteredKeywords)
{
    m_filtersMngr->filterVerbose(param, filteredKeywords, m_filtered_keywords_verbose);
}

void WaapAssetState::filterKeywordsByParameters(
    const std::string &parameter_name, Waap::Keywords::KeywordsSet &keywords_set)
{
    dbgTrace(D_WAAP_ASSET_STATE) << "filter keywords based on parameter name: " << parameter_name;
    auto filter_parameters_itr = m_Signatures->filter_parameters.find(parameter_name);
    if (filter_parameters_itr != m_Signatures->filter_parameters.end())
    {
        dbgTrace(D_WAAP_ASSET_STATE) << "Found keywords to filter based on parameter name";
        const auto &vec = filter_parameters_itr->second;
        for (auto keyword_to_filter : vec)
        {
            auto keywords_set_itr = keywords_set.find(keyword_to_filter);
            if (keywords_set_itr != keywords_set.end())
            {
                dbgTrace(D_WAAP_ASSET_STATE) << "Filtering keyword: " << keyword_to_filter;
                keywords_set.erase(keyword_to_filter);
            }
        }
    }
    else
    {
        dbgTrace(D_WAAP_ASSET_STATE) << "No keywords need to be filtered for this parameter";
    }
}

void WaapAssetState::removeKeywords(Waap::Keywords::KeywordsSet &keywords_set)
{
    for (auto &keyword_to_remove : m_Signatures->remove_keywords_always)
    {
        auto keyword_set_itr = keywords_set.find(keyword_to_remove);
        if (keyword_set_itr != keywords_set.end())
        {
            dbgTrace(D_WAAP_ASSET_STATE) << "Removing keyword: " << keyword_to_remove << " from keyword set";
            keywords_set.erase(keyword_set_itr);
        }
    }
}

void WaapAssetState::removeWBXMLKeywords(Waap::Keywords::KeywordsSet &keywords_set,
    std::vector<std::string> &filtered_keywords)
{
    for (auto it = keywords_set.begin(); it != keywords_set.end();) {
        if (NGEN::Regex::regexMatch(__FILE__, __LINE__, *it, m_Signatures->wbxml_data_kw_filter)) {
            dbgTrace(D_WAAP_ASSET_STATE) << "Filtering keyword due to wbxml: '" << *it << "'";
            filtered_keywords.push_back(*it);
            it = keywords_set.erase(it);
        }
        else {
            ++it;
        }
    }
}

void WaapAssetState::createRateLimitingState(const std::shared_ptr<Waap::RateLimiting::Policy> &rateLimitingPolicy)
{
    m_rateLimitingState = std::make_shared<Waap::RateLimiting::State>(rateLimitingPolicy);
}

void WaapAssetState::createErrorLimitingState(const std::shared_ptr<Waap::RateLimiting::Policy> &errorLimitingPolicy)
{
    m_errorLimitingState = std::make_shared<Waap::RateLimiting::State>(errorLimitingPolicy);
}

void WaapAssetState::createSecurityHeadersState(
    const std::shared_ptr<Waap::SecurityHeaders::Policy> &securityHeadersPolicy)
{
    m_securityHeadersState = std::make_shared<Waap::SecurityHeaders::State>(securityHeadersPolicy);
}

std::shared_ptr<Waap::RateLimiting::State>& WaapAssetState::getRateLimitingState()
{
    return m_rateLimitingState;
}

std::shared_ptr<Waap::RateLimiting::State>& WaapAssetState::getErrorLimitingState()
{
    return m_errorLimitingState;
}

std::shared_ptr<Waap::SecurityHeaders::State>& WaapAssetState::getSecurityHeadersState()
{
    return m_securityHeadersState;
}


void WaapAssetState::clearRateLimitingState()
{
    m_rateLimitingState.reset();
}

void WaapAssetState::clearErrorLimitingState()
{
    m_errorLimitingState.reset();
}

void WaapAssetState::clearSecurityHeadersState()
{
    m_securityHeadersState.reset();
}

