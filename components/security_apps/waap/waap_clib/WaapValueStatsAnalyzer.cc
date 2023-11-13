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

#include "WaapValueStatsAnalyzer.h"
#include <string>
#include <ctype.h>
#include "debug.h"
#include "Waf2Util.h"

USE_DEBUG_FLAG(D_WAAP);

bool checkUrlEncoded(const char *buf, size_t len)
{
    dbgFlow(D_WAAP);
    size_t i = 0;
    int hex_characters_to_follow = 0;
    bool has_encoded_value = false;

    for (; i < len; i++) {
        char ch = buf[i];
        if (ch == '%' && hex_characters_to_follow == 2) {
            continue;
        }

        if (hex_characters_to_follow > 0) {
            hex_characters_to_follow--;
            if (isHexDigit(ch)) {
                continue;
            }
            return false;
        } else if (ch == '%') {
            has_encoded_value = true;
            hex_characters_to_follow = 2;
            continue;
        }

        if (Waap::Util::isAlphaAsciiFast(static_cast<unsigned char>(ch)) || isdigit(ch)) {
            continue;
        }

        switch (ch) {
            case '.':
            case '-':
            case '_':
            case '~':
            case '!':
            case '*':
            case '\'':
            case '(':
            case ')':
            case ';':
            case ':':
            case '@':
            case '&':
            case '=':
            case '+':
            case '$':
            case ',':
            case '/':
            case '?':
            case '#':
            case '[':
            case ']':
                continue;
            default:
                return false;
        }
    }

    return has_encoded_value;
}

ValueStatsAnalyzer::ValueStatsAnalyzer(const std::string &cur_val)
    :
    hasCharSlash(false),
    hasCharColon(false),
    hasCharAmpersand(false),
    hasCharEqual(false),
    hasTwoCharsEqual(false),
    hasCharSemicolon(false),
    hasCharPipe(false),
    longestZerosSeq{0},
    isUTF16(false),
    canSplitSemicolon(true),
    canSplitPipe(true),
    hasSpace(false),
    isUrlEncoded(false),
    hasCharLess(false)
{
    unsigned int zerosSeq[2] = {0};
    bool lastNul = false; // whether last processed character was ASCII NUL
    size_t curValLength = cur_val.length();

    if (curValLength == 0) {
        canSplitSemicolon = false;
        canSplitPipe = false;
        return;
    }

    // Decide the input is candidate for UTF16 if all the following rules apply:
    // 1. Input buffer length is longer than 2 bytes
    // 2. Input buffer length is divisible by 2
    isUTF16 = (curValLength > 2) && (curValLength % 2 == 0);

    for (size_t i = 0; i < curValLength; ++i)
    {
        unsigned char ch = (unsigned char)cur_val[i];

        switch(ch) {
            case '/':
                hasCharSlash = true;
                break;
            case ':':
                hasCharColon = true;
                break;
            case '&':
                hasCharAmpersand = true;
                break;
            case '=':
                if (!hasTwoCharsEqual) {
                    if (hasCharEqual) {
                        hasTwoCharsEqual = true;
                    }
                    hasCharEqual = true;
                }
                break;
            case ';':
                hasCharSemicolon = true;
                break;
            case '|':
                hasCharPipe = true;
                break;
            case '<':
                hasCharLess = true;
                break;
            case '\"':
                hasDoubleQuote = true;
                break;
        }

        if (isspace(ch)) {
            hasSpace = true;
        }

        // The index will be 0 for even, and 1 for odd offsets
        int index = i % 2;

        // Compute longest sequence of ASCII NUL bytes over even and odd offsets in cur_val
        if (ch == 0)
        {
            if (lastNul)
            {
                // UTF-16 consists of subsequent pairs of bytes. Cancel UTF16 detection if there is a NUL bytes pair.
                // (but allow such a pair at the end of the input buffer: UTF16 could be "NUL terminated" this way)
                if (isUTF16 && (index == 1) && (i + 1 < curValLength)) {
                    isUTF16 = false;
                }

                // Anytime two ASCII NULs are encountered in a row - terminate counting the NUL-sequence length.
                zerosSeq[0] = 0;
                zerosSeq[1] = 0;
            }
            else
            {
                zerosSeq[index]++;
                longestZerosSeq[index] = std::max(zerosSeq[index], longestZerosSeq[index]);
            }

            lastNul = true;
        }
        else
        {
            zerosSeq[index] = 0;
            lastNul = false;
        }

        bool isAlphaNumeric = Waap::Util::isAlphaAsciiFast(ch) || isdigit(ch);

        if (canSplitSemicolon && !isAlphaNumeric) {
            switch (ch) {
                case '.':
                case '-':
                case '_':
                case '=':
                case ',':
                case '(':
                case ')':
                case ';':
                    break;
                default:
                    // Only alphanumeric characters and characters listed above are allowed, anything else disables
                    canSplitSemicolon = false;
            }
        }

        if (canSplitPipe && !isAlphaNumeric) {
            switch (ch) {
                case ':':
                case '?':
                case '.':
                case '-':
                case '_':
                case '=':
                case ',':
                case '[':
                case ']':
                case '/' :
                case ' ':
                case '\f':
                case '\v':
                case '\t':
                case '\r':
                case '\n':
                case '(':
                case ')':
                case '|':
                    break;
                default:
                    // Only alphanumeric characters and characters listed above are allowed, anything else disables
                    canSplitPipe = false;
            }
        }
    }

    // Only decode UTF16 if at least one longest zero bytes sequence (computed over odd
    // or over even input bytes) is longer than 2.
    // If both sequences are too short - do not decode UTF16 on such input.
    if (longestZerosSeq[0] <= 2 && longestZerosSeq[1] <= 2) {
        isUTF16 = false;
    }
    // Detect URLEncode value
    isUrlEncoded = checkUrlEncoded(cur_val.data(), cur_val.size());

    textual.clear();
    textual.append("hasCharSlash = ");
    textual +=(hasCharSlash ? "true" : "false");
    textual.append("\nhasCharColon = ");
    textual +=(hasCharColon ? "true" : "false");
    textual.append("\nhasCharAmpersand = ");
    textual +=(hasCharAmpersand ? "true" : "false");
    textual.append("\nhasCharEqual = ");
    textual +=(hasCharEqual ? "true" : "false");
    textual.append("\nhasTwoCharsEqual = ");
    textual +=(hasTwoCharsEqual ? "true" : "false");
    textual.append("\nhasCharSemicolon = ");
    textual +=(hasCharSemicolon ? "true" : "false");
    textual.append("\nhasCharPipe = ");
    textual +=(hasCharPipe ? "true" : "false");
    textual.append("\nisUTF16 = ");
    textual +=(isUTF16 ? "true" : "false");
    textual.append("\ncanSplitSemicolon = ");
    textual +=(canSplitSemicolon ? "true" : "false");
    textual.append("\ncanSplitPipe = ");
    textual +=(canSplitPipe ? "true" : "false");
    textual.append("\nhasSpace = ");
    textual +=(hasSpace ? "true" : "false");
    textual.append("\nisUrlEncoded = ");
    textual +=(isUrlEncoded ? "true" : "false");
    textual.append("\nhasCharLess = ");
    textual +=(hasCharLess ? "true" : "false");
    textual.append("\nhasDoubleQuote = ");
    textual +=(hasDoubleQuote ? "true" : "false");
}
