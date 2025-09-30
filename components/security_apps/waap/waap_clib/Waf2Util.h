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

#ifndef __WAF2_UTIL_H__148aa7e4
#define __WAF2_UTIL_H__148aa7e4

#include "WaapValueStatsAnalyzer.h"
#include "log_generator.h"
#include <assert.h>
#include <memory.h>
#include <ctype.h>
#include <stdint.h>
#include <list>
#include <vector>
#include <set>
#include <string>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include "WaapEnums.h"
#include "yajl/yajl_gen.h"

#define GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)

enum base64_variants {SINGLE_B64_CHUNK_CONVERT, KEY_VALUE_B64_PAIR, CONTINUE_AS_IS, CONTINUE_DUAL_SCAN};
enum base64_stage {BEFORE_EQUAL, EQUAL, DONE, MISDETECT};
enum base64_decode_status {B64_DECODE_INVALID, B64_DECODE_OK, B64_DECODE_INCOMPLETE, B64_DECODE_SUSPECTED};

#define BASE64_ENTROPY_BASE_THRESHOLD 5.0
#define BASE64_ENTROPY_DECODED_THRESHOLD 5.4
#define BASE64_ENTROPY_THRESHOLD_DELTA 0.25
#define BASE64_MIN_SIZE_LIMIT 16
#define BASE64_MAX_SIZE_LIMIT 1024

// This is portable version of stricmp(), which is non-standard function (not even in C).
// Contrary to stricmp(), for a slight optimization, s2 is ASSUMED to be already in lowercase.
// s1 can be in mixed case and is convetred using tolower() before comparing to s2.
// The function returns true if s1 (with all charactes lowered case) matches s2, false if not.
inline bool my_stricmp(const char *s1, const char *s2) {
    assert(s1 != NULL);
    assert(s2 != NULL);

    // Compare header name, case insensitively, to "content-type"
    while (*s1 && *s2 && tolower(*s1)==*s2) {
        s1++;
        s2++;
    }

    // returns true if s1 (after applying tolower()) eactly matches s2
    return (*s1=='\0' && *s2=='\0');
}

// same as my_stricmp(), but assumes s1 has known size, and does not assume s1 string is null-terminated.
inline bool my_strincmp(const char *s1, const char *s2, size_t s1_size) {
    assert(s1 != NULL);
    assert(s2 != NULL);

    // Compare header name, case insensitively, to "content-type"
    while (s1_size > 0 && *s2 && tolower(*s1)==*s2) {
        s1++;
        s2++;
        s1_size--; // reduce s1_size until we exhaust at most s1_size characters of the s1 string.
    }

    // returns true if s1 (after applying tolower()) eactly matches s2
    return (s1_size==0 && *s2=='\0');
}

inline bool my_stristarts_with(const char *s1, const char *s2) {
    assert(s1 != NULL);
    assert(s2 != NULL);

    // Compare case insensitively
    while (*s1 && *s2 && tolower(*s1)==*s2) {
        s1++;
        s2++;
    }

    // returns true if s1 (after applying tolower()) starts with s2
    // (this happens when we finished to examine all s2 and it compared correctly to start of s1)
    return (*s2=='\0');
}

inline unsigned char from_hex(unsigned char ch, bool &valid) {
    valid = true;

    if (ch <= '9' && ch >= '0')
        ch -= '0';
    else if (ch <= 'f' && ch >= 'a')
        ch -= 'a' - 10;
    else if (ch <= 'F' && ch >= 'A')
        ch -= 'A' - 10;
    else {
        valid = false;
        ch = 0;
    }

    return ch;
}

inline bool str_starts_with(const std::string& value, const std::string& prefix)
{
    if (prefix.size() > value.size()) {
        return false;
    }

    return value.compare(0, prefix.size(), prefix) == 0;
}

inline bool str_ends_with(const std::string& value, const std::string& ending)
{
    if (ending.size() > value.size()) {
        return false;
    }

    return value.compare(value.size() - ending.size(), ending.size(), ending) == 0;
}

template<class _IT>
_IT unquote_plus(_IT first, _IT last, bool decodeUrl=true, bool decodePlus=true) {
    _IT result = first;
    enum { STATE_COPY, STATE_FIRST_DIGIT, STATE_SECOND_DIGIT } state = STATE_COPY;
    unsigned char accVal = 0; // accumulated character (from hex digits)
    char lastCh = 0;

    for (; first != last; ++first) {
        switch (state) {
            case STATE_COPY:
                if (*first == '+' && decodePlus) {
                    *result++ = ' ';
                }
                else if (decodeUrl && *first == '%') {
                    state = STATE_FIRST_DIGIT;
                }
                else {
                    *result++ = *first;
                }

                break;
            case STATE_FIRST_DIGIT: {
                bool valid;
                lastCh = *first; // remember it solely for special case where 2nd character is invalid hex
                accVal = from_hex(*first, valid);

                if (valid) {
                    state = STATE_SECOND_DIGIT;
                }
                else {
                    *result++ = '%'; // put the percent symbol to the output stream
                    if (*first == '%') {
                        // we found the '%%' sequence. Put back the first '%' character and continue
                        // in the same state (as if we've just seen the first '%')
                        // this supports the case of %%xx, which would otherwise fail to parse.
                    }
                    else {
                        // put the "invalid" symbol to the output stream
                        *result++ = *first;
                        // continue copying
                        state = STATE_COPY;
                    }
                }

                break;
            }
            case STATE_SECOND_DIGIT: {
                bool valid;
                accVal = (accVal << 4) | from_hex(*first, valid);

                if (valid) {
                    // After second hex digit decoded succesfully - put computed character to output and
                    // continue to "copying" state
                    *result++ = accVal;
                }
                else {
                    if (*first == '%') {
                        // put the percent symbol to the output
                        *result++ = '%';
                        // put the first (among two) character (that was valid hex char), back to the output stream.
                        *result++ = lastCh;
                        state = STATE_FIRST_DIGIT;
                        break;
                    }
                    // If second character is invalid - return original '%', the first character,
                    // and the second character to the output.

                    // put the percent symbol to the output
                    *result++ = '%';
                    // put the first (among two) character (that was valid hex char), back to the output stream.
                    *result++ = lastCh;
                    // put the second (among two) "invalid" character to the output stream.
                    *result++ = *first;
                }

                state = STATE_COPY;
                break;
            }
        }
    }

    if (state == STATE_FIRST_DIGIT) {
        // put the percent symbol to the output stream
        *result++ = '%';
    }
    else if (state == STATE_SECOND_DIGIT) {
        // put the percent symbol to the output
        *result++ = '%';
        // put the first (among two) character (that was valid hex char), back to the output stream.
        *result++ = lastCh;
    }

    return result;
}

inline bool isHexDigit(const char ch) {
    return isdigit(ch) || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
}

template<class _IT>
_IT escape_backslashes(_IT first, _IT last) {
    _IT src = first;
    _IT dst = first;
    _IT mark = first;

    enum { STATE_COPY, STATE_ESCAPE, STATE_OCTAL, STATE_HEX } state = STATE_COPY;
    unsigned char accVal = 0;
    unsigned char digitsCount = 0;

    for (; src != last && dst < last; ++src) {
        switch (state) {
            case STATE_COPY:
                if (*src == '\\') {
                    mark = src;
                    state = STATE_ESCAPE;
                } else {
                    *dst++ = *src;
                }
                break;
            case STATE_ESCAPE: {
                if (*src >= '0' && *src <= '7') {
                    accVal = *src - '0';
                    digitsCount = 1;
                    state = STATE_OCTAL;
                    break;
                } else if (*src == 'x') {
                    accVal = 0;
                    digitsCount = 0;
                    state = STATE_HEX;
                    break;
                } else {
                    switch (*src) {
                        // Copy a matching character without the backslash before it
                        case 'a': *dst++ = 7; break; // BELL
                        case 'b': *dst++ = 8; break; // BACKSPACE
                        case 'e': *dst++ = 27; break; // ESCAPE
                        case 't': *dst++ = 9; break; // HORIZONTAL TAB
                        case 'n': *dst++ = 10; break; // LINEFEED
                        case 'v': *dst++ = 11; break; // VERTICAL TAB
                        case 'f': *dst++ = 12; break; // FORMFEED
                        case 'r': *dst++ = 13; break; // CARRIAGE RETURN
                        case '\?': *dst++ = '\?'; break; // QUESTION MARK
                        case '\\': *dst++ = '\\'; break; // upon seeing double backslash - output only one
                        case '\"': *dst++ = '\"'; break; // DOUBLE QUOTE
                        case '\'': *dst++ = '\''; break; // SINGLE QUOTE
                        default:
                            // invalid escape sequence - do not replace it (return original characters)
                            // Copy from back-track, not including current character, and continue
                            while (dst <= mark && mark < src) {
                                *dst++ = *mark++;
                            }

                            // Copy current (terminator) character which is not "escape" and return to copy state
                            // If current character is escape - stay is "escape" state
                            if (*src != '\\') {
                                *dst++ = *src;
                                state = STATE_COPY;
                            } else {
                                mark = src;
                            }
                            break;
                    }

                    state = STATE_COPY;
                }

                break;
            }
            case STATE_OCTAL: {
                if (*src >= '0' && *src <= '7') {
                    accVal = (accVal << 3) | (*src - '0');
                    digitsCount++;
                    // Up to 3 octal digits imposed by C standard, so after 3 digits accumulation stops.
                    if (digitsCount == 3) {
                        *dst++ = accVal; // output character corresponding to collected accumulated value
                        digitsCount = 0;
                        state = STATE_COPY;
                    }
                } else {
                    // invalid octal digit stops the accumulation
                    *dst++ = accVal; // output character corresponding to collected accumulated value
                    digitsCount = 0;
                    if (*src != '\\') {
                        // If terminating character is not backslash output the terminating character
                        *dst++ = *src;
                        state = STATE_COPY;
                    } else {
                        // If terminating character is backslash start next escape sequence
                        mark = src;
                        state = STATE_ESCAPE;
                    }
                }

                break;
            }
            case STATE_HEX: {
                if (!isHexDigit(*src)) {
                    // Copy from back-track, not including *src character (which is absent), and continue
                    while (dst <= mark && mark < src) {
                        *dst++ = *mark++;
                    }
                    if (*src != '\\') {
                        // If terminating character is not backslash output the terminating character
                        *dst++ = *src;
                        state = STATE_COPY;
                    } else {
                        // If terminating character is backslash start next escape sequence
                        mark = src;
                        state = STATE_ESCAPE;
                    }
                } else {
                    accVal = accVal << 4;
                    if (isdigit(*src)) {
                        accVal += *src - '0';
                    } else if (*src >= 'a' && *src <= 'f') {
                        accVal += *src - 'a' + 10;
                    } else if (*src >= 'A' && *src <= 'F') {
                        accVal += *src - 'A' + 10;
                    }
                    digitsCount++;
                    // exactly 2 hex digits are anticipated, so after 2 digits accumulation stops.
                    if (digitsCount == 2) {
                        *dst++ = accVal; // output character corresponding to collected accumulated value
                        digitsCount = 0;
                        state = STATE_COPY;
                    }
                }
                break;
            }
        }
    }

    if (dst < last) {
        // Handle state at end of input
        bool copyBackTrack = true;
        switch (state) {
            case STATE_HEX:
                // this can only happen on this sequence '\xH' where H is a single hex digit.
                // in this case the sequence is considered invalid and should be copied verbatim (copyBackTrack=true)
                break;
            case STATE_OCTAL:
                // this can only happen when less than 3 octal digits are found at the value end, like '\1' or '\12'
                *dst++ = accVal; // output character corresponding to collected accumulated value
                copyBackTrack = false;
                break;
            case STATE_COPY:
                copyBackTrack = false;
                break;
            case STATE_ESCAPE:
                break;
        }

        if (copyBackTrack) {
            // invalid escape sequence - do not replace it (return original characters)
            // Copy from back-track
            while (dst <= mark && mark < src) {
                *dst++ = *mark++;
            }
        }
    }

    return dst;
}

inline bool str_contains(const std::string &haystack, const std::string &needle)
{
    return haystack.find(needle) != std::string::npos;
}

struct HtmlEntity {
    const char *name;
    unsigned short value;
};

extern const  struct HtmlEntity g_htmlEntities[];
extern const size_t g_htmlEntitiesCount;

template<class _IT>
_IT escape_html(_IT first, _IT last) {
    _IT dst = first;
    _IT src = first;
    enum {
        STATE_COPY,
        STATE_ESCAPE,
        STATE_NAMED_CHARACTER_REFERENCE,
        STATE_NUMERIC_START,
        STATE_NUMERIC, STATE_HEX
    } state = STATE_COPY;
    unsigned short accVal = 0; // should be unsigned short to hold unicode character code (16-bits)
    bool digitsSeen = false;
    std::list<size_t> potentialMatchIndices;
    size_t matchLength = 0;
    size_t lastKnownMatchIndex = -1;
    _IT mark = src;

    for (; src != last && dst < last; ++src) {
        switch (state) {
            case STATE_COPY:
                if (*src == '&') {
                    mark = src;
                    state = STATE_ESCAPE;
                }
                else {
                    *dst++ = *src;
                }
                break;
            case STATE_ESCAPE:
                if (isalpha(*src)) {
                    // initialize potential matches list
                    potentialMatchIndices.clear();

                    for (size_t index = 0; index < g_htmlEntitiesCount; ++index) {
                        if (*src == g_htmlEntities[index].name[0]) {
                            potentialMatchIndices.push_back(index);
                            lastKnownMatchIndex = index;
                        }
                    }

                    // No potential matches - send ampersand and current character to output
                    if (potentialMatchIndices.size()  == 0) {
                        *dst++ = '&';
                        *dst++ = *src;
                        state = STATE_COPY;
                        break;
                    }

                    // 1st character already matched, so matchLen already starts from 1
                    matchLength = 1;
                    state = STATE_NAMED_CHARACTER_REFERENCE;
                }
                else if (*src == '#') {
                    digitsSeen = 0;
                    accVal = 0;
                    state = STATE_NUMERIC_START;
                }
                else {
                    // not isalpha and not '#' - this is invalid character reference - do not replace it
                    // (return original characters)
                    *dst++ = '&';
                    *dst++ = *src;
                    state = STATE_COPY;
                }
                break;

            case STATE_NAMED_CHARACTER_REFERENCE:
                // Find and remove all potential matches that do not match anymore
                {
                    int increaseMatchLength = 0;

                    for (
                        std::list<size_t>::iterator pPotentialMatchIndex = potentialMatchIndices.begin();
                        pPotentialMatchIndex != potentialMatchIndices.end();
                        ) {
                        lastKnownMatchIndex = *pPotentialMatchIndex;
                        const char *matchName = g_htmlEntities[lastKnownMatchIndex].name;

                        // If there are no more characters in the potntial match name,
                        // or the next tested character doesn't match - kill the match
                        if ((matchName[matchLength] == '\0') || (matchName[matchLength] != *src)) {
                            // remove current element from the list of potential matches
                            pPotentialMatchIndex = potentialMatchIndices.erase(pPotentialMatchIndex);
                        }
                        else {
                            increaseMatchLength = 1;
                            ++pPotentialMatchIndex;
                        }
                    }

                    matchLength += increaseMatchLength;
                }

                // No more potential matches: unsuccesful match -> flush all consumed characters back to output stream
                if (potentialMatchIndices.size() == 0) {
                    // Send consumed ampersand to the output
                    *dst++ = '&';

                    // Send those matched characters (these are the same that we consumed) - to the output
                    for (size_t i = 0; i < matchLength; i++) {
                        *dst++ = g_htmlEntities[lastKnownMatchIndex].name[i];
                    }

                    // Send the character that terminated our search for possible matches
                    *dst++ = *src;

                    // Continue copying text verbatim
                    state = STATE_COPY;
                    break; // note: this breaks out of the for() loop, not out of the switch
                }

                // There are still potential matches and ';' is hit
                if (*src == ';') {
                    // longest match found for the named character reference.
                    // translate it into output character(s) and we're done.
                    unsigned short value = g_htmlEntities[lastKnownMatchIndex].value;

                    // Encode UTF code point as UTF-8 bytes
                    if (value < 0x80) {
                        *dst++ = value;
                    }
                    else if (value < 0x800 ) {
                        *dst++ = (value >> 6)    | 0xC0;
                        *dst++ = (value & 0x3F) | 0x80;
                    }
                    else { // (value <= 0xFFFF : always true because value type is unsigned short which is 16-bit
                        *dst++ = (value >> 12) | 0xE0;
                        *dst++ = ((value >> 6) & 0x3F) | 0x80;
                        *dst++ = (value & 0x3F) | 0x80;
                    }

                    // Continue copying text verbatim
                    state = STATE_COPY;
                    break; // note: this breaks out of the for() loop, not out of the switch
                }
                break;
            case STATE_NUMERIC_START:
                digitsSeen = false;
                accVal = 0;
                if (*src == 'x' || *src == 'X') {
                    state = STATE_HEX;
                }
                else if (isdigit(*src)) {
                    digitsSeen = true;
                    accVal = *src - '0';
                    state = STATE_NUMERIC;
                }
                else {
                    // Sequence started with these two characters: '&#', and here is the third, non-digit character

                    // Copy from back-track, not including current character, and continue
                    while (dst <= mark && mark < src) {
                        *dst++ = *mark++;
                    }

                    if (*src == '&') {
                        // Terminator is also start of next escape sequence
                        mark = src;
                        state = STATE_ESCAPE;
                        break;
                    }
                    else {
                        // Copy the terminating character too
                        *dst++ = *src;
                    }
                    state = STATE_COPY;
                }
                break;
            case STATE_NUMERIC:
                if (!isdigit(*src)) {
                    if (digitsSeen) {
                        // Encode UTF code point as UTF-8 bytes
                        if (accVal < 0x80) {
                            *dst++ = accVal;
                        }
                        else if (accVal < 0x800 ) {
                            *dst++ = (accVal >> 6)    | 0xC0;
                            *dst++ = (accVal & 0x3F) | 0x80;
                        }
                        else { // (accVal <= 0xFFFF : always true because accVal type is unsigned short which is 16-bit
                            *dst++ = (accVal >> 12) | 0xE0;
                            *dst++ = ((accVal >> 6) & 0x3F) | 0x80;
                            *dst++ = (accVal & 0x3F) | 0x80;
                        }
                    }
                    else {
                        // Copy from back-track, not including current character (which is absent), and continue
                        while (dst <= mark && mark < src) {
                            *dst++ = *mark++;
                        }
                    }

                    if (*src == '&') {
                        // Terminator is also start of next escape sequence
                        mark = src;
                        state = STATE_ESCAPE;
                        break;
                    }
                    else if (!digitsSeen || *src != ';') {
                        // Do not copy the ';' but do copy any other terminator
                        // Note: the ';' should remain in the output if there were no digits seen.
                        *dst++ = *src;
                    }
                    state = STATE_COPY;
                }
                else {
                    digitsSeen = true;
                    accVal = accVal * 10 + *src - '0'; // TODO:: beware of integer overflow?
                }
                break;
            case STATE_HEX:
                if (!isHexDigit(*src)) {
                    if (digitsSeen) {
                        // Encode UTF code point as UTF-8 bytes
                        if (accVal < 0x80) {
                            *dst++ = accVal;
                        }
                        else if (accVal < 0x800 ) {
                            *dst++ = (accVal >> 6)    | 0xC0;
                            *dst++ = (accVal & 0x3F) | 0x80;
                        }
                        else { // (accVal <= 0xFFFF : always true because accVal type is unsigned short which is 16-bit
                            *dst++ = (accVal >> 12) | 0xE0;
                            *dst++ = ((accVal >> 6) & 0x3F) | 0x80;
                            *dst++ = (accVal & 0x3F) | 0x80;
                        }
                    }
                    else {
                        // Copy from back-track, not including current character (which is absent), and continue
                        while (dst <= mark && mark < src) {
                            *dst++ = *mark++;
                        }
                    }

                    if (*src == '&') {
                        // Terminator is also start of next escape sequence
                        mark = src;
                        state = STATE_ESCAPE;
                        break;
                    }
                    else if (!digitsSeen || *src != ';') {
                        // Do not copy the ';' but do copy any other terminator
                        // Note: the ';' should remain in the output if there were no digits seen.
                        *dst++ = *src;
                    }
                    state = STATE_COPY;
                }
                else {
                    digitsSeen = true;
                    accVal = accVal << 4;
                    if (isdigit(*src)) {
                        accVal += *src - '0';
                    }
                    else if (*src >= 'a' && *src <= 'f') {
                        accVal += *src - 'a' + 10;
                    }
                    else if (*src >= 'A' && *src <= 'F') {
                        accVal += *src - 'A' + 10;
                    }
                }
                break;
        }
    }

    if (state == STATE_ESCAPE && dst < last) {
        *dst++ = '&';
    }
    else if (state == STATE_NAMED_CHARACTER_REFERENCE && potentialMatchIndices.size() > 0 && dst < last) {
        // Send consumed ampersand to the output
        *dst++ = '&';

        // Send those matched characters (these are the same that we consumed) - to the output
        for (size_t i = 0; i < matchLength && dst < last; i++) {
            // Even if there are multiple potential matches, all of them start with the same
            // matchLength characters that we consumed!
            *dst++ = g_htmlEntities[lastKnownMatchIndex].name[i];
        }
    }
    if (state == STATE_HEX && !digitsSeen) { // Special case of "&#x"
        // Copy from back-track, not including current character (which is absent), and continue
        while (dst <= mark && mark < src) {
            *dst++ = *mark++;
        }
        state = STATE_COPY;
    }
    else if (state == STATE_HEX || state == STATE_NUMERIC || state == STATE_NUMERIC_START) {
        if (digitsSeen && dst < last) {
            // Encode UTF code point as UTF-8 bytes
            if (accVal < 0x80) {
                *dst++ = accVal;
            }
            else if (accVal < 0x800 && std::distance(dst, last) >= 2) {
                *dst++ = (accVal >> 6) | 0xC0;
                *dst++ = (accVal & 0x3F) | 0x80;
            }
            // (accVal <= 0xFFFF : always true because accVal type is unsigned short which is 16-bit
            else if (std::distance(dst, last) >= 3) {
                *dst++ = (accVal >> 12) | 0xE0;
                *dst++ = ((accVal >> 6) & 0x3F) | 0x80;
                *dst++ = (accVal & 0x3F) | 0x80;
            }
        }
        else {
            // Copy from back-track, not including current character (which is absent), and continue
            while (dst <= mark && mark < src) {
                *dst++ = *mark++;
            }
            state = STATE_COPY;
        }
    }

    return dst;
}

// Compare two buffers, case insensitive. Return true if they are equal (case-insensitive)
inline bool memcaseinsensitivecmp(const char *buf1, size_t buf1_len, const char *buf2, size_t buf2_len) {
    if (buf1_len != buf2_len) {
        return false;
    }

    for (; buf1_len > 0; --buf1_len) {
        if (tolower(*buf1++) != tolower(*buf2++)) {
            return false; // different
        }
    }

    return true; // equal
}

inline void replaceAll(std::string& str, const std::string& from, const std::string& to) {
    if(from.empty()) {
        return;
    }

    size_t start_pos = 0;

    while((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // In case 'to' contains 'from', like replacing 'x' with 'yx'
    }
}

inline std::string replaceAllCopy(std::string str, const std::string& from, const std::string& to) {
    replaceAll(str, from, to);
    return str;
}

inline void alignBase64Chunk (std::string &chunk)
{
    size_t len = chunk.length() % 4;
    if (len >= 2) {
        chunk.append(4-len, '=');
    }
}

// Count items in v that are not in ignored_set
inline size_t countNotInSet(const std::vector<std::string> &v, const std::set<std::string> &ignored_set) {
    size_t count = 0;

    for (const std::string &word : v) {
        if (ignored_set.find(word) == ignored_set.end()) {
            // not in ignored_set
            count++;
        }
    }

    return count;
}

// note: this algorithm may probably be rewritten with std::remove_if() and probably lambda,
// but this better done when we can finally use c++11
inline void removeItemsMatchingSubstringOf(std::vector<std::string> &v, const std::string& match) {
    for (std::vector<std::string>::iterator it=v.begin(); it != v.end();) {
        // Remove items that are contained (substr) within the (longer or equal-length) match string.
        if (match.find(*it) != std::string::npos) {
            it = v.erase(it);
        }
        else {
            ++it;
        }
    }
}

// Detect whether unicode code is in the "Halfwidth and Fullwidth Forms" set convertable to ASCII.
inline bool isUnicodeHalfAndFullWidthRange(uint32_t code) {
    return (code >= 0xFF01 && code <=0xFF5E);
}

// Convert unicode code from the "Halfwidth and Fullwidth Forms" set to ASCII.
inline char convertFromUnicodeHalfAndFullWidthRange(uint32_t code) {
    assert(isUnicodeHalfAndFullWidthRange(code));
    // Support set of unicode characters from the "Halfwidth and Fullwidth Forms" that are converted to ASCII
    static const char *xlat =
        "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    return xlat[code - 0xFF01];
}

inline bool isSpecialUnicode(uint32_t code) {
    return isUnicodeHalfAndFullWidthRange(code)
            || 0x2028 == code || 0x2029 == code
            || 0x2215 == code || 0x2216 == code
            || 0xEFC8 == code || 0xF025 == code;
}

inline char convertSpecialUnicode(uint32_t code) {
    if (isUnicodeHalfAndFullWidthRange(code)) {
        return convertFromUnicodeHalfAndFullWidthRange(code);
    }
    else if (0x2216 == code || 0xEFC8 == code || 0xF025 == code)
    {
        return '\\';
    }
    else if (0x2215 == code)
    {
        return '/';
    }
    // assuming 0x2028 == code || 0x2029 == code
    else
    {
        return '\n';
    }
}

inline void stripSpaces(std::string &text) {
    std::string::iterator it = text.begin();
    std::string::iterator result = it;

    for (; it != text.end(); ++it) {
        unsigned char ch = (unsigned char)(*it);

        // Include only non-space characters
        if (!isspace(ch)) {
            *result++ = ch;
        }
    }

    text.erase(result, text.end());
}

inline size_t countSubstrings(const std::string &str, const std::string &subStr) {
    if (subStr.empty()) {
        return str.size() + 1; // to conform to python's "str.count(subStr)" behavior when substr is empty string...
    }

    size_t count = 0;
    size_t pos = str.find(subStr);

    while( pos != std::string::npos) {
        count++;
        pos = str.find(subStr, pos + subStr.size());
    }

    return count;
}


// Test whether text starts one of the known HTML tag names
bool startsWithHtmlTagName(const char *text);

// Normalizing URL means replacing any pure-numeric  URL parts with the word "_num"
// The parameters part of the given uri is also stripped (the '?' character and anything after it).
std::string normalize_uri(const std::string &uri);

std::string normalize_param(const std::string& param);

// Analogous to python's text.decode('unicode_escape'), with the distinction that
// this function simply throws out the \uXXXX sequences instead of converting them to binary unicode sequences.
// This function performs in-place decoding, updating text string in progress.
void unescapeUnicode(std::string &text);

// Try to find and decode UTF7 chunks
std::string filterUTF7(const std::string &text);

base64_decode_status
decideStatusBase64Decoded(
    std::string& decoded,
    double entropy,
    double decoded_entropy,
    size_t spacer_count,
    size_t nonPrintableCharsCount,
    bool clear_on_error,
    double terminatorCharsSeen,
    bool called_with_prefix);

base64_decode_status
decodeBase64Chunk(
    const std::string &value,
    std::string::const_iterator it,
    std::string::const_iterator end,
    std::string &decoded,
    bool clear_on_error = true,
    bool called_with_prefix = false);

bool
b64DecodeChunk(
    const std::string &value,
    std::string::const_iterator it,
    std::string::const_iterator end,
    std::string &decoded);

std::vector<std::string>
split(const std::string& s, char delim);

namespace Waap {
namespace Util {
    typedef bool (*RegexSubCallback_f)(
        const std::string &value,
        std::string::const_iterator b,
        std::string::const_iterator e,
        std::string &repl);

    bool isValidJson(const std::string &input);

    enum KnownSourceType {
        SOURCE_TYPE_UNKNOWN = 0,
        SOURCE_TYPE_SENSOR_DATA = 1
    };

    KnownSourceType detectKnownSource(const std::string &input);
    bool isScreenedJson(const std::string &input);

    int definePrefixedJson(const std::string &input);

    bool detectJSONasParameter(const std::string &s,
            std::string &key,
            std::string &value);

    enum BinaryFileType {
        FILE_TYPE_NONE,
        FILE_TYPE_PNG,
        FILE_TYPE_JPEG,
        FILE_TYPE_PDF
    };

    void b64Decode(
            const std::string &s,
            RegexSubCallback_f cb,
            int &decodedCount,
            int &deletedCount,
            std::string &outStr);

    base64_variants b64Test (
            const std::string &s,
            std::string &key,
            std::string &value,
            BinaryFileType &binaryFileType,
            size_t offset = 0);

    // The original stdlib implementation of isalpha() supports locale settings which we do not really need.
    // It is also proven to contribute to slow performance in some of the algorithms using it.
    // This function has reduced functionality compared to stdlib isalpha(), but is much faster.
    inline bool isAlphaAsciiFast(unsigned char ch) {
        return ((unsigned int)ch | 32) - 'a' < 26;
    }

    // Compare two objects referenced by pointer - comparison is done by value (comparing objects themselves)
    // This is different from comparing object pointers.
    template<typename _T>
    bool compareObjects(_T &first, _T &second)
    {
        // If both are the same object (or both are equal to nullptr - then they are equivalent)
        if (first == second) {
            return true;
        }

        // If pointers are different and at least one of them is nullptr, then the other is not nullptr - so they are
        // not equivalent
        if (first == nullptr || second == nullptr) {
            return false;
        }

        // At this point, both pointers are for sure not nullptr, so we can dereference and compare objects pointed by
        return *first == *second;
    }

    inline bool str_isalnum(const std::string & value) {
        for (std::string::const_iterator pC = value.begin(); pC != value.end(); ++pC) {
            if (!std::isalnum(*pC)) {
                return false; // at least one non alphanumeric character detected
            }
        }

        return true;
    }

    inline bool isAllDigits(const std::string & value) {
        for (char ch : value) {
            if (!isdigit(ch)) {
                return false; // at least one non digit character detected
            }
        }

        return true;
    }

    typedef std::map<std::string, std::vector<std::string> > map_of_stringlists_t;

    // Yajl generator (C++ RAII edition :)
    struct Yajl {
        yajl_gen g;
        Yajl() :g(yajl_gen_alloc(NULL)) {}
        ~Yajl()
        {
            yajl_gen_free(g);
        }

        struct Map {
            yajl_gen& g;
            explicit Map(Yajl& y) : g(y.g)
            {
                yajl_gen_map_open(g);
            }
            ~Map()
            {
                yajl_gen_map_close(g);
            }
            void gen_null(const std::string& k)
            {
                yajl_gen_string(g, (unsigned char*)k.data(), k.size()); yajl_gen_null(g);
            }
            void gen_str(const std::string& k, const std::string& v)
            {
                yajl_gen_string(g, (unsigned char*)k.data(), k.size());
                yajl_gen_string(g, (unsigned char*)v.data(), v.size());
            }
            void gen_bool(const std::string& k, bool v)
            {
                yajl_gen_string(g, (unsigned char*)k.data(), k.size()); yajl_gen_bool(g, v);
            }
            void gen_integer(const std::string& k, long long int v)
            {
                yajl_gen_string(g, (unsigned char*)k.data(), k.size()); yajl_gen_integer(g, v);
            }
            void gen_double(const std::string& k, double v)
            {
                yajl_gen_string(g, (unsigned char*)k.data(), k.size()); yajl_gen_double(g, v);
            }
            void gen_key(const std::string& k)
            {
                yajl_gen_string(g, (unsigned char*)k.data(), k.size());
            }
        };

        struct Array {
            yajl_gen& g;
            explicit Array(Yajl& y) :g(y.g) { yajl_gen_array_open(g); }
            ~Array() { yajl_gen_array_close(g); }
            void gen_null() { yajl_gen_null(g); }
            void gen_str(const std::string& v) { yajl_gen_string(g, (unsigned char*)v.data(), v.size()); }
            void gen_bool(bool v) { yajl_gen_bool(g, v); }
            void gen_integer(long long int v) { yajl_gen_integer(g, v); }
            void gen_double(double v) { yajl_gen_double(g, v); }
        };

        std::string get_json_str() const {
            const unsigned char* buf;
            size_t len;
            yajl_gen_get_buf(g, &buf, &len);
            return std::string((char*)buf, len);
        }
    };

    enum ContentType {
        CONTENT_TYPE_UNKNOWN,
        CONTENT_TYPE_XML,
        CONTENT_TYPE_JSON,
        CONTENT_TYPE_GQL,
        CONTENT_TYPE_HTML,
        CONTENT_TYPE_MULTIPART_FORM,
        CONTENT_TYPE_URLENCODED,
        CONTENT_TYPE_WBXML,
        CONTENT_TYPES_COUNT
    };

// LCOV_EXCL_START Reason: coverage upgrade
    inline const char* getContentTypeStr(enum ContentType contentType) {
        static const char* contentTypeStr[] = {
            "UNKNOWN",
            "XML",
            "JSON",
            "HTML",
            "MULTIPART_FORM",
            "URLENCODED",
            "WBXML"
        };

        if (contentType >= CONTENT_TYPES_COUNT) {
            contentType = CONTENT_TYPE_UNKNOWN;
        }

        return contentTypeStr[contentType];
    };
// LCOV_EXCL_STOP

    static const std::string s_EncryptionKey = "KSO+hOFs1q5SkEnx8bvp67Om2zyHDD6ZJF4NHAa3R94=";;
    static const std::string s_EncryptionIV = "sxJNyEO7i6YfA1p9CTglHw==";

    // trim from start
    static inline std::string &ltrim(std::string &s) {
        s.erase(s.begin(), std::find_if(s.begin(), s.end(),
            [] (char c) { return !std::isspace(c); }));
        return s;
    }

    // trim from end
    static inline std::string &rtrim(std::string &s) {
        s.erase(std::find_if(s.rbegin(), s.rend(),
            [] (char c) { return !std::isspace(c); }).base(), s.end());
        return s;
    }

    // trim from both ends
    static inline std::string &trim(std::string &s) {
        return ltrim(rtrim(s));
    }

    // Find whether some word (what) exists wihin keys of the map.
    // The search done by *searching* for "what" string within each key string,
    // not by *comparing* "what" with each key string.
    bool find_in_map_of_stringlists_keys(const std::string & what, const map_of_stringlists_t & where);

    void remove_in_map_of_stringlists_keys(const std::string & what, map_of_stringlists_t & where);

    void remove_startswith(std::vector<std::string> &vec, const std::string &prefix);

    std::string AES128Decrypt(std::string& key, std::string& iv, std::string& message);
    std::string base64Encode(const std::string &input);
    std::string base64Decode(const std::string &input);
    std::string obfuscateXor(const std::string& toEncrypt);
    std::string obfuscateXorBase64(const std::string& toEncrypt);

    bool isGzipped(const std::string &stream);
    bool containsInvalidUtf8(const std::string &payload);

    bool containsPercentEncoding(const std::string &payload);

    // based on invalid utf-8 evasion from here: https://www.cgisecurity.com/lib/URLEmbeddedAttacks.html
    std::string unescapeInvalidUtf8(const std::string &text);

    Maybe<std::string> containsBrokenUtf8(const std::string &payload, const std::string &unquoted_payload);
    std::string unescapeBrokenUtf8(const std::string &text);

    bool containsCspReportPolicy(const std::string &payload);

    bool testNoSQLKeySuspect(const std::string &key);

    bool testUrlBareUtf8Evasion(const std::string &line);
    bool testUrlBadUtf8Evasion(const std::string &line);

    std::string urlDecode(std::string src);

    std::string injectSpacesToString(const std::string& std);

    std::string charToString(const char* s, int slen);

    std::string vecToString(const std::vector<std::string>& vec, char delim = ',');
    template<typename V>
    std::string
        setToString(const std::set<V>& set, bool addParenthesis=true) {
        std::ostringstream vts;

        if (addParenthesis)
        {
            vts << "[";
        }

        if (!set.empty())
        {
            for (auto itr = set.begin(); itr != set.end(); itr++)
            {
                vts << *itr << ", ";
            }
        }
        else
        {
            return std::string();
        }
        std::string res = vts.str();
        res.pop_back();
        res.pop_back();
        if (addParenthesis)
        {
            res += "]";
        }


        return res;
    }

    template<typename V>
    void mergeFromVectorWithoutDuplicates(
        const std::vector<V>& first_vector,
        std::vector<V>& second_vector)
    {
        for (const V& element : first_vector)
        {
            if(find(second_vector.begin(), second_vector.end(), element) == second_vector.end())
            {
                second_vector.push_back(element);
            }
        }
    }

    template<typename V, typename T>
    void mergeFromMapOfVectorsWithoutDuplicates(
        const std::map<V, std::vector<T>>& first_map,
        std::map<V, std::vector<T>>& second_map)
    {
        for (auto itr = first_map.begin(); itr != first_map.end(); itr++)
        {
            if (second_map.find(itr->first) != second_map.end())
            {
                const std::vector<T>& first_vector = first_map.at(itr->first);
                mergeFromVectorWithoutDuplicates(first_vector, second_map[itr->first]);
            }
            else
            {
                const std::vector<T>& first_vector = itr->second;
                second_map[itr->first] = first_vector;
            }
        }
    }

    template<typename V>
    void mergeSets(const std::set<V>& first_set, const std::set<V>& second_set, std::set<V>& merged_set)
    {
        std::set_union(
            first_set.begin(),
            first_set.end(),
            second_set.begin(),
            second_set.end(),
            std::inserter(merged_set, merged_set.begin())
        );
    }


    ReportIS::Severity computeSeverityFromThreatLevel(ThreatLevel threatLevel);
    ReportIS::Priority computePriorityFromThreatLevel(ThreatLevel threatLevel);
    std::string computeConfidenceFromThreatLevel(ThreatLevel threatLevel);

    void decodePercentEncoding(std::string &text, bool decodePlus=false);
    void decodeUtf16Value(const ValueStatsAnalyzer &valueStats, std::string &cur_val);

    std::string stripOptionalPort(const std::string::const_iterator &first, const std::string::const_iterator &last);
    std::string extractKeyValueFromCookie(const std::string &cookie, const std::string &key);
    bool isIpAddress(const std::string &ip_address);
    bool isUuid(const std::string& str);
    bool vectorStringContain(const std::vector<std::string>& vec, const std::string& str);
    bool isIpTrusted(const std::string &ip, const std::vector<std::string> &trusted_ips);


    ContentType detectContentType(const char* hdr_value);
    std::string convertParamTypeToStr(ParamType type);
    ParamType convertTypeStrToEnum(const std::string& typeStr);

}
}

#endif // __WAF2_UTIL_H__148aa7e4
