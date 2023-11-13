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

#include "Waf2Util.h"

#include "debug.h"
#include <map>
#include <string>
#include <sstream>
#include <vector>
#include <openssl/aes.h>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <sys/stat.h>
#include <stdio.h>
#include <locale.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "CidrMatch.h"
#include "debug.h"
#include "config.h"
#include "generic_rulebase/rulebase_config.h"
#include "user_identifiers_config.h"
#include "Waf2Regex.h"

using boost::algorithm::to_lower_copy;
using namespace std;

USE_DEBUG_FLAG(D_WAAP);
USE_DEBUG_FLAG(D_WAAP_EVASIONS);
USE_DEBUG_FLAG(D_WAAP_BASE64);
USE_DEBUG_FLAG(D_WAAP_JSON);
USE_DEBUG_FLAG(D_OA_SCHEMA_UPDATER);

#define MIN_HEX_LENGTH 6
#define charToDigit(c) (c - '0')

// See https://dev.w3.org/html5/html-author/charref
const  struct HtmlEntity g_htmlEntities[] =
{
    {"Tab;", 0x0009},
    {"NewLine;", 0x000A},
    {"nbsp;", 0x00A0},
    {"NonBreakingSpace;", 0x00A0},
    {"excl;", 0x0021},
    {"num;", 0x0023},
    {"dollar;", 0x0024},
    {"percnt;", 0x0025},
    {"lpar;", 0x0028},
    {"rpar;", 0x0029},
    {"ast;", 0x002A},
    {"midast;", 0x002A},
    {"plus;", 0x002B},
    {"comma;", 0x002C},
    {"period;", 0x002E},
    {"sol;", 0x002F},
    {"colon;", 0x003A},
    {"semi;", 0x003B},
    {"iexcl;", 0x00A1},
    {"cent;", 0x00A2},
    {"pound;", 0x00A3},
    {"curren;", 0x00A4},
    {"yen;", 0x00A5},
    {"brvbar;", 0x00A6},
    {"sect;", 0x00A7},
    {"uml;", 0x00A8},
    {"copy;", 0x00A9},
    {"ordf;", 0x00AA},
    {"laquo;", 0x00AB},
    {"not;", 0x00AC},
    {"shy;", 0x00AD},
    {"reg;", 0x00AE},
    {"macr;", 0x00AF},
    {"deg;", 0x00B0},
    {"plusmn;", 0x00B1},
    {"sup2;", 0x00B2},
    {"sup3;", 0x00B3},
    {"acute;", 0x00B4},
    {"micro;", 0x00B5},
    {"para;", 0x00B6},
    {"middot;", 0x00B7},
    {"cedil;", 0x00B8},
    {"sup1;", 0x00B9},
    {"ordm;", 0x00BA},
    {"raquo;", 0x00BB},
    {"frac14;", 0x00BC},
    {"frac12;", 0x00BD},
    {"frac34;", 0x00BE},
    {"iquest;", 0x00BF},
    {"Agrave;", 0x00C0},
    {"Aacute;", 0x00C1},
    {"Acirc;", 0x00C2},
    {"Atilde;", 0x00C3},
    {"Auml;", 0x00C4},
    {"Aring;", 0x00C5},
    {"AElig;", 0x00C6},
    {"Ccedil;", 0x00C7},
    {"Egrave;", 0x00C8},
    {"Eacute;", 0x00C9},
    {"Ecirc;", 0x00CA},
    {"Euml;", 0x00CB},
    {"Igrave;", 0x00CC},
    {"Iacute;", 0x00CD},
    {"Icirc;", 0x00CE},
    {"Iuml;", 0x00CF},
    {"ETH;", 0x00D0},
    {"Ntilde;", 0x00D1},
    {"Ograve;", 0x00D2},
    {"Oacute;", 0x00D3},
    {"Ocirc;", 0x00D4},
    {"Otilde;", 0x00D5},
    {"Ouml;", 0x00D6},
    {"times;", 0x00D7},
    {"Oslash;", 0x00D8},
    {"Ugrave;", 0x00D9},
    {"Uacute;", 0x00DA},
    {"Ucirc;", 0x00DB},
    {"Uuml;", 0x00DC},
    {"Yacute;", 0x00DD},
    {"THORN;", 0x00DE},
    {"szlig;", 0x00DF},
    {"agrave;", 0x00E0},
    {"aacute;", 0x00E1},
    {"acirc;", 0x00E2},
    {"atilde;", 0x00E3},
    {"auml;", 0x00E4},
    {"aring;", 0x00E5},
    {"aelig;", 0x00E6},
    {"ccedil;", 0x00E7},
    {"egrave;", 0x00E8},
    {"eacute;", 0x00E9},
    {"ecirc;", 0x00EA},
    {"euml;", 0x00EB},
    {"igrave;", 0x00EC},
    {"iacute;", 0x00ED},
    {"icirc;", 0x00EE},
    {"iuml;", 0x00EF},
    {"eth;", 0x00F0},
    {"ntilde;", 0x00F1},
    {"ograve;", 0x00F2},
    {"oacute;", 0x00F3},
    {"ocirc;", 0x00F4},
    {"otilde;", 0x00F5},
    {"ouml;", 0x00F6},
    {"divide;", 0x00F7},
    {"oslash;", 0x00F8},
    {"ugrave;", 0x00F9},
    {"uacute;", 0x00FA},
    {"ucirc;", 0x00FB},
    {"uuml;", 0x00FC},
    {"yacute;", 0x00FD},
    {"thorn;", 0x00FE},
    {"yuml;", 0x00FF},
    {"quot;", 0x0022},
    {"amp;", 0x0026},
    {"lt;", 0x003C},
    {"LT;", 0x003C},
    {"equals;", 0x003D},
    {"gt;", 0x003E},
    {"GT;", 0x003E},
    {"quest;", 0x003F},
    {"commat;", 0x0040},
    {"lsqb;", 0x005B},
    {"lback;", 0x005B},
    {"bsol;", 0x005C},
    {"rsqb;", 0x005D},
    {"rbrack;", 0x005D},
    {"Hat;", 0x005E},
    {"lowbar;", 0x005F},
    {"grave;", 0x0060},
    {"DiacriticalGrave;", 0x0060},
    {"lcub;", 0x007B},
    {"lbrace;", 0x007B},
    {"verbar;", 0x007C},
    {"vert;", 0x007C},
    {"VerticalLine;", 0x007C},
    {"rcub;", 0x007D},
    {"rbrace;", 0x007D},
    {"apos;", 0x0027},
    {"OElig;", 0x0152},
    {"oelig;", 0x0153},
    {"Scaron;", 0x0160},
    {"scaron;", 0x0161},
    {"Yuml;", 0x0178},
    {"circ;", 0x02C6},
    {"tilde;", 0x02DC},
    {"ensp;", 0x2002},
    {"emsp;", 0x2003},
    {"emsp13;", 0x2004},
    {"emsp14;", 0x2005},
    {"numsp;", 0x2007},
    {"puncsp;", 0x2008},
    {"thinsp;", 0x2009},
    {"ThinSpace;", 0x2009},
    {"hairsp;", 0x200A},
    {"VeryThinSpace;", 0x200A},
    {"ZeroWidthSpace;", 0x200B},
    {"NegativeVeryThinSpace;", 0x200B},
    {"NegativeThinSpace;", 0x200B},
    {"NegativeMediumSpace;", 0x200B},
    {"NegativeThickSpace;", 0x200B},
    {"zwnj;", 0x200C},
    {"zwj;", 0x200D},
    {"lrm;", 0x200E},
    {"rlm;", 0x200F},
    {"hyphen;", 0x2010},
    {"dash;", 0x2010},
    {"ndash;", 0x2013},
    {"mdash;", 0x2014},
    {"horbar;", 0x2015},
    {"Verbar;", 0x2016},
    {"Vert;", 0x2016},
    {"lsquo;", 0x2018},
    {"OpenCurlyQuote;", 0x2018},
    {"rsquo;", 0x2019},
    {"rsquor;", 0x2019},
    {"CloseCurlyQuote;", 0x2019},
    {"lsquor;", 0x201A},
    {"sbquo;", 0x201A},
    {"ldquo;", 0x201C},
    {"OpenCurlyDoubleQuote;", 0x201C},
    {"rdquo;", 0x201D},
    {"rdquor;", 0x201D},
    {"CloseCurlyDoubleQuote;", 0x201D},
    {"ldquor;", 0x201E},
    {"bdquo;", 0x201E},
    {"dagger;", 0x2020},
    {"Dagger;", 0x2021},
    {"permil;", 0x2030},
    {"lsaquo;", 0x2039},
    {"rsaquo;", 0x203A},
    {"euro;", 0x20AC},
    {"fnof;", 0x0192},
    {"Alpha;", 0x0391},
    {"Beta;", 0x0392},
    {"Gamma;", 0x0393},
    {"Delta;", 0x0394},
    {"Epsilon;", 0x0395},
    {"Zeta;", 0x0396},
    {"Eta;", 0x0397},
    {"Theta;", 0x0398},
    {"Iota;", 0x0399},
    {"Kappa;", 0x039A},
    {"Lambda;", 0x039B},
    {"Mu;", 0x039C},
    {"Nu;", 0x039D},
    {"Xi;", 0x039E},
    {"Omicron;", 0x039F},
    {"Pi;", 0x03A0},
    {"Rho;", 0x03A1},
    {"Sigma;", 0x03A3},
    {"Tau;", 0x03A4},
    {"Upsilon;", 0x03A5},
    {"Phi;", 0x03A6},
    {"Chi;", 0x03A7},
    {"Psi;", 0x03A8},
    {"Omega;", 0x03A9},
    {"alpha;", 0x03B1},
    {"beta;", 0x03B2},
    {"gamma;", 0x03B3},
    {"delta;", 0x03B4},
    {"epsilon;", 0x03B5},
    {"zeta;", 0x03B6},
    {"eta;", 0x03B7},
    {"theta;", 0x03B8},
    {"iota;", 0x03B9},
    {"kappa;", 0x03BA},
    {"lambda;", 0x03BB},
    {"mu;", 0x03BC},
    {"nu;", 0x03BD},
    {"xi;", 0x03BE},
    {"omicron;", 0x03BF},
    {"pi;", 0x03C0},
    {"rho;", 0x03C1},
    {"sigmaf;", 0x03C2},
    {"sigma;", 0x03C3},
    {"tau;", 0x03C4},
    {"upsilon;", 0x03C5},
    {"phi;", 0x03C6},
    {"chi;", 0x03C7},
    {"psi;", 0x03C8},
    {"omega;", 0x03C9},
    {"thetasym;", 0x03D1},
    {"upsih;", 0x03D2},
    {"piv;", 0x03D6},
    {"bull;", 0x2022},
    {"hellip;", 0x2026},
    {"prime;", 0x2032},
    {"Prime;", 0x2033},
    {"oline;", 0x203E},
    {"frasl;", 0x2044},
    {"MediumSpace;", 0x205F},
    {"NoBreak;", 0x2060},
    {"ApplyFunction;", 2061},
    {"af;", 2061},
    {"it;", 0x2062},
    {"InvisibleTimes;", 0x2062},
    {"ic;", 0x2063},
    {"InvisibleComma;", 0x2063},
    {"weierp;", 0x2118},
    {"image;", 0x2111},
    {"real;", 0x211C},
    {"trade;", 0x2122},
    {"alefsym;", 0x2135},
    {"larr;", 0x2190},
    {"uarr;", 0x2191},
    {"rarr;", 0x2192},
    {"darr;", 0x2193},
    {"harr;", 0x2194},
    {"crarr;", 0x21B5},
    {"lArr;", 0x21D0},
    {"uArr;", 0x21D1},
    {"rArr;", 0x21D2},
    {"dArr;", 0x21D3},
    {"hArr;", 0x21D4},
    {"forall;", 0x2200},
    {"part;", 0x2202},
    {"exist;", 0x2203},
    {"empty;", 0x2205},
    {"nabla;", 0x2207},
    {"isin;", 0x2208},
    {"notin;", 0x2209},
    {"ni;", 0x220B},
    {"prod;", 0x220F},
    {"sum;", 0x2211},
    {"minus;", 0x2212},
    {"lowast;", 0x2217},
    {"radic;", 0x221A},
    {"prop;", 0x221D},
    {"infin;", 0x221E},
    {"ang;", 0x2220},
    {"and;", 0x2227},
    {"or;", 0x2228},
    {"cap;", 0x2229},
    {"cup;", 0x222A},
    {"int;", 0x222B},
    {"there4;", 0x2234},
    {"sim;", 0x223C},
    {"cong;", 0x2245},
    {"asymp;", 0x2248},
    {"ne;", 0x2260},
    {"equiv;", 0x2261},
    {"le;", 0x2264},
    {"ge;", 0x2265},
    {"sub;", 0x2282},
    {"sup;", 0x2283},
    {"nsub;", 0x2284},
    {"sube;", 0x2286},
    {"supe;", 0x2287},
    {"oplus;", 0x2295},
    {"otimes;", 0x2297},
    {"perp;", 0x22A5},
    {"sdot;", 0x22C5},
    {"lceil;", 0x2308},
    {"rceil;", 0x2309},
    {"lfloor;", 0x230A},
    {"rfloor;", 0x230B},
    {"lang;", 0x2329},
    {"rang;", 0x232A},
    {"loz;", 0x25CA},
    {"spades;", 0x2660},
    {"clubs;", 0x2663},
    {"hearts;", 0x2665},
    {"diams;", 0x2666}
};

const size_t g_htmlEntitiesCount = sizeof(g_htmlEntities) / sizeof(g_htmlEntities[0]);

const char* g_htmlTags[] = {
    "a",
    "abbr",
    "acronym",
    "address",
    "applet",
    "embed",
    "object",
    "area",
    "article",
    "aside",
    "audio",
    "b",
    "base",
    "basefont",
    "bdi",
    "bdo",
    "big",
    "blockquote",
    "body",
    "br",
    "button",
    "canvas",
    "caption",
    "center",
    "cite",
    "code",
    "col",
    "colgroup",
    "datalist",
    "dd",
    "del",
    "details",
    "dfn",
    "dialog",
    "dir",
    "ul",
    "div",
    "dl",
    "dt",
    "em",
    "fieldset",
    "figcaption",
    "figure",
    "font",
    "footer",
    "form",
    "frame",
    "frameset",
    "h1",
    "h6",
    "head",
    "header",
    "hr",
    "html",
    "i",
    "iframe",
    "img",
    "input",
    "ins",
    "kbd",
    "keygen",
    "label",
    "legend",
    "li",
    "link",
    "main",
    "map",
    "mark",
    "menu",
    "menuitem",
    "meta",
    "meter",
    "nav",
    "noframes",
    "noscript",
    "ol",
    "optgroup",
    "option",
    "output",
    "p",
    "param",
    "pre",
    "progress",
    "q",
    "rp",
    "rt",
    "ruby",
    "s",
    "samp",
    "script",
    "section",
    "select",
    "small",
    "source",
    "video",
    "span",
    "strike",
    "strong",
    "style",
    "sub",
    "summary",
    "sup",
    "table",
    "tbody",
    "td",
    "textarea",
    "tfoot",
    "th",
    "thead",
    "time",
    "title",
    "tr",
    "track",
    "tt",
    "u",
    "var",
    "wbr",
    "event-source",
    "math",
    "svg",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6"
};

static const string b64_prefix("base64,");

const size_t g_htmlTagsCount = sizeof(g_htmlTags) / sizeof(g_htmlTags[0]);

bool startsWithHtmlTagName(const char* text) {
    for (size_t index = 0; index < g_htmlTagsCount; ++index) {
        // Return true if text starts with one of html tags
        if (my_stristarts_with(text, g_htmlTags[index])) {
            // starts with html tag, followed by space/tab/crlf character (see man isspace(),
            // or ends with '>' character.
            char termChar = text[strlen(g_htmlTags[index])];
            if (isspace(termChar) || termChar == '>' || termChar == '/') {
                return true;
            }
        }
    }

    return false;
}

string normalize_uri(const string& uri) {
    string result;
    string::const_iterator mark = uri.begin();
    bool isNumeric = false;

    string::const_iterator it = uri.begin();
    for (; it != uri.end() && *it != '?'; ++it) {
        if (*it == '/') {
            if (mark != it) {
                if (isNumeric) {
                    result += "_num";
                }
                else {
                    result.append(mark, it);
                }
            }

            result += "/";
            mark = it + 1;
            isNumeric = true;
            continue;
        }

        // reset isNumeric flag on first non-digit character in the path element string
        if (!isdigit(*it)) {
            isNumeric = false;
        }
    }

    // At this point, "it" points to where scanning stopped (can be end of uri string or the '?' character)
    // Append the rest of the string (or "_num" if last uri part was all numeric) - to the output.
    if (mark != it) {
        if (isNumeric) {
            result += "_num";
        }
        else {
            result.append(mark, it);
        }
    }

    return result;
}

string
normalize_param(const string& param)
{
    string result;
    string::const_iterator mark = param.begin();
    bool isNumeric = true;
    bool isHex = true;

    string::const_iterator it = param.begin();
    for (; it != param.end(); ++it) {
        if (!isalnum(*it)) {
            if (mark != it) {
                if (isNumeric || (isHex && it - mark >= MIN_HEX_LENGTH)) {
                    result += "_num";
                }
                else {
                    result.append(mark, it);
                }
            }

            result += *it;
            mark = it + 1;
            isNumeric = true;
            isHex = true;
            continue;
        }

        // reset isNumeric flag on first non-digit character in the path element string
        if (isHex && !isdigit(*it)) {
            if (!isHexDigit(*it)) {
                isHex = false;
            }
            isNumeric = false;
        }
    }

    // At this point, "it" points to where scanning stopped (can be end of uri string or the '?' character)
    // Append the rest of the string (or "_num" if last uri part was all numeric) - to the output.
    if (mark != it) {
        if (isNumeric || (isHex && it - mark >= MIN_HEX_LENGTH)) {
            result += "_num";
        }
        else {
            result.append(mark, it);
        }
    }

    return result;
}

void unescapeUnicode(string& text) {
    string::iterator it = text.begin();
    string::iterator result = it;
    char acc[16];   // accumulates characters we are parsing and do not want to copy directly.
                    // max len really possible is "\u00000000" + 1 char = 11 chars
    char* pAcc = NULL; // when non-NULL, points where to put next character inside acc buffer
    int digitsAnticipated = 0; // in state STATE_ESCAPE, how many hex digits we anticipate to be parsed
    uint32_t code = 0; // The Unicode codepoint value can't be larger than 32 bits
    char* p;
    // in state STATE_ESCAPE_X, how many non-zerohex digits discovered - to eliminate leading zeroes like \x000012
    int nonZeroHexCounter = 0;
    enum {
        STATE_COPY,
        STATE_FLUSH,
        STATE_ESCAPE,
        STATE_ESCAPE_U,
        STATE_ESCAPE_X
    } state = STATE_COPY;

    for (; it != text.end(); ++it) {
        const char ch = *it;

        switch (state) {
        case STATE_FLUSH: {
            // flush any accumulated left-overs into output buffer
            if (pAcc) {
                for (p = acc; p < pAcc; p++) {
                    *result++ = *p;
                }
                pAcc = NULL; // clear the acc buffer after we flushed it
            }
            state = STATE_COPY;
            // fall-through
            //RB: why no break?
        }
        // fallthrough
        case STATE_COPY: {

            if (ch == '\\') {
                // start accumulating characters instead of copying them
                pAcc = acc;
                state = STATE_ESCAPE;
                break;
            }
            break;
        }
        case STATE_ESCAPE: {
            // decide which kind of escape
            if (ch == 'u') {
                digitsAnticipated = 4; // parse/skip 4 hex digits
                code = 0;
                state = STATE_ESCAPE_U;
            }
            else if (ch == 'U') {
                digitsAnticipated = 8; // parse/skip 8 hex digits
                code = 0;
                state = STATE_ESCAPE_U;
            }
            else if (ch == 'x') {
#if 1
                digitsAnticipated = 1; // anticipate at least one HEX digit after \x
                code = 0;
                nonZeroHexCounter = 0;
                state = STATE_ESCAPE_X;
#else
                digitsAnticipated = 2; // parse/skip 2 hex digits
                code = 0;
                state = STATE_ESCAPE_U;
#endif
            }
            else {
                // this is invalid escape sequence: rollback and copy this character too
                state = STATE_FLUSH;
            }
            break;
        }
        case STATE_ESCAPE_U: {
            if (isHexDigit(ch)) {
                // accumulate code value
                code = (code << 4) + (isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10);
                digitsAnticipated--;

                if (digitsAnticipated == 0) {
                    // only output ASCII codes <= 127. "swallow" all unicode.
                    if (code <= 127) {
                        *result++ = (char)code;
                    }
                    else if (isSpecialUnicode(code)) {
                        *result++ = convertSpecialUnicode(code);
                    }

                    if (pAcc) {
                        pAcc = NULL; // throw away the accumulated source (escaped) sequencec.
                    }

                    // not STATE_COPY to avoid outputting current ch verbatim.
                    // FLUSH will output nothing because there's no ACC
                    state = STATE_FLUSH;
                    break;
                }

            }
            else {
                // invalid (non-hex) digit enountered
                state = STATE_FLUSH;
            }

            break;
        }
        case STATE_ESCAPE_X: {
            if (isHexDigit(ch)) {
                if ((nonZeroHexCounter) > 1) {
                    *result++ = (char)code;
                    if (pAcc) {
                        pAcc = NULL; // throw away the accumulated source (escaped) sequence.
                    }
                    state = STATE_COPY;
                } else {
                    code = (code << 4) + (isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10);
                    code &= 0xFF; // clamp the code value to two last digits
                    // Once at least one valid hex digit is here the sequence is considered
                    // valid and there's no need to accumulate it anymore.
                    if (pAcc) {
                        pAcc = NULL;
                    }

                    if (digitsAnticipated > 0) {
                        digitsAnticipated--;
                    }
                    if (code) {
                        nonZeroHexCounter++;
                    }
                }
            } else {
                // According to C standard, '\x' sequence must be followed by at least 1 valid hex digit
                if (digitsAnticipated > 0) {
                    // This is first character right after the '\x' sequence,
                    // and it is not a valid hex. This is bad sequence.
                    state = STATE_FLUSH;
                } else {
                    // We found non-hex character that terminates our \xhhhhh... sequence
                    *result++ = (char)code;
                    if (pAcc) {
                        pAcc = NULL; // throw away the accumulated source (escaped) sequence.
                    }

                    if (ch == '\\') {
                        // start accumulating characters instead of copying them
                        pAcc = acc;
                        state = STATE_ESCAPE;
                        break;
                    }

                    // STATE_COPY will cause current character (sequence terminator)
                    // to be output verbatim.
                    state = STATE_COPY;
                }
            }

            if (digitsAnticipated > 0) {
                digitsAnticipated--;
            }
            break;
        }
        }

        // Copy to output
        if (state == STATE_COPY) {
            *result++ = ch;
        }

        // Accumulate
        if (pAcc) {
            // Ensure we don't have buffer overflow
            assert(size_t(pAcc - acc) < sizeof(acc));
            *pAcc++ = ch;
        }
    }

    dbgTrace(D_WAAP) << " - LOOP FINISHED with state=" << state << "; digitsAnticipated=" <<
        digitsAnticipated << ", acc='" << string(acc, pAcc ? (int)(pAcc - acc) : 0) << "'";

    // Output code if we just finished decoding an escape sequence succesully and reached end of string
    if (state == STATE_ESCAPE_U && digitsAnticipated == 0) {
        // only output ASCII codes <= 127. "swallow" all unicode.
        if (code <= 127) {
            *result++ = (char)code;
        }
        else if (isSpecialUnicode(code)) {
            *result++ = convertSpecialUnicode(code);
        }

        if (pAcc) {
            pAcc = NULL; // throw away the accumulated source (escaped) sequencec.
        }
    }
    else if (state == STATE_ESCAPE_X) {
        if (isSpecialUnicode(code)) {
            *result++ = convertSpecialUnicode(code);
        }
        else
        {
            *result++ = (char)code;
        }
    }

    // flush any accumulated left-overs into output buffer
    if (pAcc) {
        for (p = acc; p < pAcc; p++) {
            *result++ = *p;
        }
    }

    text.erase(result, text.end());
}

// Attempts to validate and decode utf7-encoded chunk.
// Returns "next" iterator to position where to continue parsing for next chunks, and
// fills the "decoded" string with decoded data.
// If failed, the "next" will be equal to passed "it", and empty string put in "decoded".
inline const string::const_iterator
decodeUTF7Chunk(string::const_iterator it, string::const_iterator end, string& decoded) {
    decoded.clear();
    unsigned char val = 0;
    uint32_t acc = 0;
    int acc_bits = 0; // how many bits are filled in acc
    string::const_iterator next = it;

    while (it != end) {
        unsigned char c = *it;

        if (c >= 'A' && c <= 'Z') {
            val = c - 'A';
        }
        else if (c >= 'a' && c <= 'z') {
            val = c - 'a' + 26;
        }
        else if (c >= '0' && c <= '9') {
            val = c - '0' + 52;
        }
        else if (c == '+') {
            val = 62;
        }
        else if (c == '/') {
            val = 63;
        }
        else if (c == '-') {
            // end of encoded sequence (the '-' itself must not be output)
            if (!decoded.empty()) {
                next = it;
                return next; // successfully decoded. Returns decoded data in "decoded" parameter
            }

            decoded.clear(); // discard partial data
            return next;
        }
        else {
            decoded.clear(); // discard partial data
            return next;
        }

        acc = acc << 6 | val;
        acc_bits += 6;

        if (acc_bits >= 16) { // we got 16 bits or more in the accumulator
            int code = (acc >> (acc_bits - 16)) & 0xFFFF;

            // Take into account still-printable Unicode characters, convert them back to ASCII
            if (isSpecialUnicode(code)) {
                code = convertSpecialUnicode(code);
            }

            // Stop and return empty if we hit at least one non-printable character
            if (!isprint(code) && code != 0) {
                decoded.clear(); // discard partial data
                return next;
            }

            decoded += (char)code;
            acc_bits -= 16;
            acc &= (1 - (1 << acc_bits)); // leave only acc_bits low bits in the acc, clear the rest.
        }

        it++;
    }

    decoded.clear(); // discard partial data
    return next;
}

string filterUTF7(const string& text) {
    string result;
    string decoded;
    decoded.reserve(8);
    result.reserve(text.length());

    for (string::const_iterator it = text.begin(); it != text.end(); ++it) {
        if (*it == '+') {
            if (it + 1 == text.end()) { // "+" at end of string
                result += *it;
            }
            else if (*(it + 1) == '-') {
                // '+-' combination is converted to single '+'
                result += '+';
                it++; // this skips the "-"
                if (it == text.end()) {
                    break;
                }
            }
            else {
                // attempt to decode chunk
                it = decodeUTF7Chunk(it + 1, text.end(), decoded);
                if (decoded.empty()) { // decoding failed
                    result += '+';
                    result += *it;
                }
                else { // decoding succeeded
                    result += decoded;
                }
            }
        }
        else {
            result += *it;
        }
    }

    return result;
}

// Attempts to validate and decode base64-encoded chunk.
// Value is the full value inside which potential base64-encoded chunk was found,
// it and end point to start and end of that chunk.
// Returns true if succesful (and fills the "decoded" string with decoded data).
// Success criterias:
//  0. encoded sequence covers the whole value (doesn't have any characters around it)
//  1. encoded sequence consist of base64 alphabet (may end with zero, one or two '=' characters')
//  2. length of encoded sequence is exactly divisible by 4.
//  3. length of decoded is minimum 5 characters.
//  4. percent of non-printable characters (!isprint())
//     in decoded data is less than 10% (statistical garbage detection).
// Returns false above checks fail.
bool decodeBase64Chunk(
        const string& value,
        string::const_iterator it,
        string::const_iterator end,
        string& decoded)
{
    decoded.clear();
    uint32_t acc = 0;
    int acc_bits = 0; // how many bits are filled in acc
    int terminatorCharsSeen = 0; // whether '=' character was seen, and how many of them.
    uint32_t nonPrintableCharsCount = 0;
    uint32_t spacer_count = 0;

    dbgTrace(D_WAAP) << "decodeBase64Chunk: value='" << value << "' match='" << string(it, end) << "'";

    // The encoded data length (without the "base64," prefix) should be exactly divisible by 4
    // len % 4 is not 0 i.e. this is not base64
        if ((end - it) % 4 != 0) {
            dbgTrace(D_WAAP_BASE64) <<
                "b64DecodeChunk: (leave as-is) because encoded data length should be exactly divisible by 4.";
            return false;
        }

        while (it != end) {
            unsigned char c = *it;

            if (terminatorCharsSeen) {
                // terminator characters must all be '=', until end of match.
                if (c != '=') {
                    dbgTrace(D_WAAP_BASE64) <<
                        "decodeBase64Chunk: (leave as-is) because terminator characters must all be '='," <<
                        "until end of match.";
                    return false;
                }

                // We should see 0, 1 or 2 (no more) terminator characters
                terminatorCharsSeen++;

                if (terminatorCharsSeen > 2) {
                    dbgTrace(D_WAAP_BASE64) << "decodeBase64Chunk: (leave as-is) because terminatorCharsSeen > 2";
                    return false;
                }

                // allow for more terminator characters
                it++;
                continue;
            }

            unsigned char val = 0;

            if (c >= 'A' && c <= 'Z') {
                val = c - 'A';
            }
            else if (c >= 'a' && c <= 'z') {
                val = c - 'a' + 26;
            }
            else if (isdigit(c)) {
                val = c - '0' + 52;
            }
            else if (c == '+') {
                val = 62;
            }
            else if (c == '/') {
                val = 63;
            }
            else if (c == '=') {
                // Start tracking terminator characters
                terminatorCharsSeen++;
                it++;
                continue;
            }
            else {
                dbgTrace(D_WAAP_BASE64) << "decodeBase64Chunk: (leave as-is) because of non-base64 character ('" <<
                        c << "', ASCII " << (unsigned int)c << ")";
                return false; // non-base64 character
            }

            acc = (acc << 6) | val;
            acc_bits += 6;

            if (acc_bits >= 8) {
                int code = (acc >> (acc_bits - 8)) & 0xFF;
                // only leave low "acc_bits-8" bits, clear all higher bits
                uint32_t mask = ~(1 << (acc_bits - 8));
                acc &= mask;
                acc_bits -= 8;

                // Count non-printable characters seen
                if (!isprint(code) && (code != '\n') && (code != '\t')) {
                    nonPrintableCharsCount++;
                }
                if (code == '\r') {
                    spacer_count++;
                }

                decoded += (char)code;
            }

            it++;
        }

        // end of encoded sequence decoded.

        dbgTrace(D_WAAP_BASE64)
            << "decodeBase64Chunk: decoded.size="
            << decoded.size()
            << ", nonPrintableCharsCount="
            << nonPrintableCharsCount
            << ", spacer_count = "
            << spacer_count
            << ", decoded size = "
            << decoded.size()
            << "; decoded='"
            << decoded << "'";

        // Return success only if decoded.size>=5 and there are less than 10% of non-printable
        // characters in output.
        if (decoded.size() >= 5) {
            if (spacer_count > 1) {
                nonPrintableCharsCount = nonPrintableCharsCount - spacer_count + 1;
            }
            if (nonPrintableCharsCount * 10 < decoded.size()) {
                dbgTrace(D_WAAP_BASE64) << "decodeBase64Chunk: (decode/replace) decoded.size=" << decoded.size() <<
                        ", nonPrintableCharsCount=" << nonPrintableCharsCount << ": replacing with decoded data";
            }
            else {
                dbgTrace(D_WAAP_BASE64) << "decodeBase64Chunk: (delete) because decoded.size=" << decoded.size() <<
                        ", nonPrintableCharsCount=" << nonPrintableCharsCount;
                decoded.clear();
            }
            dbgTrace(D_WAAP_BASE64) << "returning true: successfully decoded."
                << " Returns decoded data in \"decoded\" parameter";
            return true; // successfully decoded. Returns decoded data in "decoded" parameter
        }

        // If decoded size is too small - leave the encoded value (return false)
        decoded.clear(); // discard partial data
        dbgTrace(D_WAAP_BASE64) << "decodeBase64Chunk: (leave as-is) because decoded too small. decoded.size=" <<
                decoded.size() <<
                ", nonPrintableCharsCount=" << nonPrintableCharsCount;
        return false;
}

// Attempts to detect and validate base64 chunk.
// Value is the full value inside which potential base64-encoded chunk was found,
// it and end point to start and end of that chunk.
// Returns true if succesful (and fills the "decoded" string with decoded data).
// Success criterias:
//  0. encoded sequence covers the whole value (doesn't have any characters around it)
//  1. encoded sequence consist of base64 alphabet (may end with zero, one or two '=' characters')
//  2. length of encoded sequence is exactly divisible by 4.
//  3. length of decoded is minimum 5 characters.
//  4. percent of non-printable characters (!isprint())
//     in decoded data is less than 10% (statistical garbage detection).
// Returns false above checks fail.
bool
b64DecodeChunk(
    const string& value,
    string::const_iterator it,
    string::const_iterator end,
    string& decoded)
{

    dbgTrace(D_WAAP_BASE64) << "b64DecodeChunk: value='" << value << "' match='" << string(it, end) << "'";

    // skip "base64," prefix if the line is starting with it.
    unsigned int len = end - it;
    if (len >= b64_prefix.size() &&
        it[0] == 'b' && it[1] == 'a' && it[2] == 's' && it[3] ==
        'e' && it[4] == '6' && it[5] == '4' && it[6] == ',') {
        it = it + b64_prefix.size(); // skip the prefix
    }
    else {
        // If the base64 candidate match within value is surrounded by other dat
        // (doesn't cover the value fully) - ignore the match.
        // This will result in the match being scanned raw.
        // Note that this purposedly doesn't include matches starting with "base64,"
        // prefix: we do want those prefixed matches to be decoded!
        if (it != value.begin() || end != value.end()) {
            dbgTrace(D_WAAP_BASE64) << "b64DecodeChunk: (leave as-is) because match is surrounded by other data.";
            return false;
        }
    }

    return decodeBase64Chunk(value, it, end, decoded);
}

vector<string> split(const string& s, char delim) {
    vector<string> elems;
    stringstream ss(s);
    string value;
    while (getline(ss, value, delim)) {
        elems.push_back(Waap::Util::trim(value));
    }
    return elems;
}

namespace Waap {
namespace Util {

#define B64_TRAILERCHAR '='

static bool err = false;
// based on malicious JSON "{1:\x00}"
static const int minimal_legal_json_size = 8;

static const SingleRegex invalid_hex_evasion_re(
    "%([g-zG-Z][0-9a-zA-Z]|[0-9a-zA-Z][g-zG-Z])",
    err,
    "invalid_hex_evasion"
);
static const SingleRegex broken_utf_evasion_re(
    "(?:^|[^%])(%[0-9a-f]%[0-9a-f])",
    err,
    "broken_utf_evasion"
);
static const SingleRegex csp_report_policy_re(
    "default-src\\s+[^\\w]+.*report-uri\\s+[^\\w]+",
    err,
    "csp_report_policy"
);
static const SingleRegex base64_key_value_detector_re(
        "^[^<>{};,&\\?|=\\s]+={1}\\s*.+",
        err,
        "base64_key_value");
static const SingleRegex json_key_value_detector_re(
    "\\A[^<>{};,&\\?|=\\s]+=[{\\[][^;\",}\\]]*[,:\"].+[\\s\\S]",
        err,
        "json_key_value");
static const SingleRegex base64_key_detector_re(
        "^[^<>{};,&\\?|=\\s]+={1}",
        err,
        "base64_key");
static const SingleRegex base64_prefix_detector_re(
        "data:\\S*;base64,\\S+|base64,\\S+",
        err,
        "base64_prefix");

// looks for combination <param>={<some text>*:<some text>*}
//used to allow parsing param=JSON to reduce false positives
bool detectJSONasParameter(const string &string_buffer,
        string &key,
        string &value)
{
    key.clear();
    value.clear();
    bool is_json_candidate_detected = json_key_value_detector_re.hasMatch(string_buffer);

    if (is_json_candidate_detected) {
        dbgTrace(D_WAAP_JSON) << "===JSONdetect===:  json_key_value_detector_re test passed - looking for key";
        string::const_iterator it = string_buffer.begin();
        for (; it != string_buffer.end(); ++it) {
            if (*it != '{') {
                continue;
            }
            // candidate should have size 8 or more - minimum for JSON with attack
            if ((string_buffer.end() - it) < minimal_legal_json_size) {
                dbgTrace(D_WAAP_JSON)
                    << "===JSONdetect===: candidate is shorter then the length"
                    "of the shortest known json attack which is: " << minimal_legal_json_size;
                return false;
            }

            key = std::string(string_buffer.begin(), it-1);
            value = std::string(it, string_buffer.end());
            break;
        }
    }
    dbgTrace(D_WAAP_JSON)
    << "===JSONdetect===:  key = '"
    << key
    << "', value = '"
    << value <<"'";
    return is_json_candidate_detected;
}

static void b64TestChunk(const string &s,
        string::const_iterator chunkStart,
        string::const_iterator chunkEnd,
        RegexSubCallback_f cb,
        int &decodedCount,
        int &deletedCount,
        string &outStr)
{
    size_t chunkLen = (chunkEnd - chunkStart);

    if ((chunkEnd - chunkStart) > static_cast<int>(b64_prefix.size()) &&
            chunkStart[0] == 'b' && chunkStart[1] == 'a' && chunkStart[2] == 's' && chunkStart[3] == 'e' &&
            chunkStart[4] == '6' && chunkStart[5] == '4' && chunkStart[6] == ',') {
        chunkLen -= b64_prefix.size();
    }

    size_t chunkRem = chunkLen % 4;

    // Only match chunk whose length is divisible by 4
    string repl;
    if (chunkRem == 0 && cb(s, chunkStart, chunkEnd, repl)) {
        // Succesfully matched b64 chunk
        if (!repl.empty()) {
            outStr += repl;
            decodedCount++;
        }
        else {
            deletedCount++;
        }
    }
    else {
        // Chunk was not processed - put original text
        size_t from = chunkStart - s.begin();
        size_t len = chunkEnd - chunkStart;
        outStr += s.substr(from, len);
    }
}

bool detectBase64Chunk(
        const string &s,
        string::const_iterator &start,
        string::const_iterator &end)
{
    dbgTrace(D_WAAP_BASE64) << " ===detectBase64Chunk===:  starting with = '" << s << "'";
    string::const_iterator it = s.begin();

    //detect "base64," prefix to start search after this
    for (; it != s.end()-7; it++) {
        if (it[0] == 'b' && it[1] == 'a' && it[2] == 's' && it[3] ==
                'e' && it[4] == '6' && it[5] == '4' && it[6] == ',') {
            it = it + 7;
            dbgTrace(D_WAAP_BASE64) << " ===detectBase64Chunk===:  prefix skipped = '" << *it << "'";
            break;
        }
    }

    //look for start of encoded string
    dbgTrace(D_WAAP_BASE64) << " ===detectBase64Chunk===:  B64 itself = '" << *it << "'";
    bool isB64AlphaChar = Waap::Util::isAlphaAsciiFast(*it) || isdigit(*it) || *it=='/' || *it=='+';

    if (isB64AlphaChar) {
        // start tracking potential b64 chunk - just check its size
        dbgTrace(D_WAAP_BASE64) << " ===detectBase64Chunk===:  isB64AlphaChar = true, '" << *it << "'";
        start = it;
        end = s.end();
        if ((end - start) % 4 == 0) {
            return true;
        }
    }
    // non base64 before supposed chunk - will not process
    return false;
}

bool isBase64PrefixProcessingOK (
        const string &s,
        string &value)
{
    string::const_iterator start, end;
    bool retVal = false;
    dbgTrace(D_WAAP_BASE64) << " ===isBase64PrefixProcessingOK===: before regex for prefix for string '" << s << "'";
    if (base64_prefix_detector_re.hasMatch(s)) {
        dbgTrace(D_WAAP_BASE64) << " ===isBase64PrefixProcessingOK===: prefix detected on string '" << s << "'";
        if (detectBase64Chunk(s, start, end)) {
            dbgTrace(D_WAAP_BASE64) << " ===isBase64PrefixProcessingOK===: chunk detected";
            if ((start != s.end()) && (end == s.end())) {
                retVal = decodeBase64Chunk(s, start, end, value);
            }
        }
    }
    return retVal;
}

base64_variants b64Test (
        const string &s,
        string &key,
        string &value)
{

    key.clear();
    bool retVal;

    dbgTrace(D_WAAP_BASE64) << " ===b64Test===: string =  " << s
            << " key = " << key << " value = " << value;
    // Minimal length
    if (s.size() < 8) {
        return CONTINUE_AS_IS;
    }
    dbgTrace(D_WAAP_BASE64) << " ===b64Test===: minimal lenght test passed";

    std::string prefix_decoded_val;
    string::const_iterator it = s.begin();

    // 1st check if we have key candidate
    if (base64_key_value_detector_re.hasMatch(s)) {
        base64_stage state = BEFORE_EQUAL;
        dbgTrace(D_WAAP_BASE64) << " ===b64Test===: testB64Key test passed - looking for key";
        for (; (it != s.end()) && (state != DONE) && (state != MISDETECT); ++it) {
            switch(state) {
            case BEFORE_EQUAL:
                if (*it != '=') {
                    key += string(1, *it);
                } else {
                    key += string(1, *it);
                    state = EQUAL;
                }
                break;
            case EQUAL:
                if (*it == '=') {
                    it = s.begin();
                    state=MISDETECT;
                    continue;
                }
                if (*it == ' ') {
                    //skip whitespaces - we don't need them in key
                    continue;
                } else {
                    state = DONE;
                }
                break;
            case DONE:
                continue;
            default:
                break;
            }

        }
        dbgTrace(D_WAAP_BASE64) << " ===b64Test===: detected key = " << key;
        if (it == s.end() || state == MISDETECT) {
            dbgTrace(D_WAAP_BASE64) << " ===b64Test===: detected  *it = s.end()" << *it;
            if (key.size() > 0) {
                it = s.begin();
                key.clear();
            }
        } else {
            it--;

            dbgTrace(D_WAAP_BASE64) << " ===b64Test===: Key is OK  *it = " << *it;
        }
    }

    dbgTrace(D_WAAP_BASE64) << " ===b64Test===: after processing key = '" << key << "'";
    bool found = isBase64PrefixProcessingOK(s, prefix_decoded_val);
    dbgTrace(D_WAAP_BASE64) << " ===b64Test===: after prefix test found = "
            << found << " new value is '" << prefix_decoded_val << "' - done";
    if (found) {
        value = prefix_decoded_val;
        if (key.empty()) {
            return SINGLE_B64_CHUNK_CONVERT;
        } else {
            key.pop_back();
            return KEY_VALUE_B64_PAIR;
        }
    }

    string::const_iterator start = s.end();
    dbgTrace(D_WAAP_BASE64) << " ===b64Test===:  B64 itself = " << *it << " =======";
    bool isB64AlphaChar = Waap::Util::isAlphaAsciiFast(*it) || isdigit(*it) || *it=='/' || *it=='+';
    if (isB64AlphaChar) {
        // 1st char is potential b64, let's try to convert this
        dbgTrace(D_WAAP_BASE64) <<
            " ===b64Test===:  Start tracking potential b64 chunk = " << *it << " =======";
        start = it;
        if ((s.end() - start) % 4 != 0) {
            key.clear();
            value.clear();
            return CONTINUE_AS_IS;;
        }
    }
    else {
        dbgTrace(D_WAAP_BASE64) <<
            " ===b64Test===: Non base64 before supposed chunk - will not process = " << *it << " =======";
        return CONTINUE_AS_IS;
    }

    if (start != s.end()) {
        // key is not empty, it should be tested for correct format (i.e. key=b64val and not splittable)
        // else leave it as is
        dbgTrace(D_WAAP_BASE64) << " ===b64Test===:BEFORE TESTING KEY key = '" << key << "'";
        if (!key.empty()) {
            if (!base64_key_detector_re.hasMatch(key)) {
                dbgTrace(D_WAAP_BASE64) << " ===b64Test===: Key is NOT GOOD regex key = '" << key << "'";
                return CONTINUE_AS_IS;
            }
            // remove '=' as last char in key - we don't need it
            key.pop_back();
            dbgTrace(D_WAAP_BASE64) << " ===b64Test===: FINAL key = '" << key << "'";
        }
        retVal = decodeBase64Chunk(s, start, s.end(), value);

        dbgTrace(D_WAAP_BASE64) << " ===b64Test===: After testing and conversion value = "
                << value << "retVal = '" << retVal <<"'";
        if (!retVal) {
            key.clear();
            value.clear();
            return CONTINUE_AS_IS;
        }
        dbgTrace(D_WAAP_BASE64) << " ===b64Test===: After tpassed retVal check = "
            << value << "retVal = '" << retVal <<"'" << "key = '" << key << "'";
        if (key.empty()) {
            return SINGLE_B64_CHUNK_CONVERT;
        } else {
            return KEY_VALUE_B64_PAIR;
        }

    } else {
        // There are symbols after base64 chunk - leave as is, may be it will be splitted no next step
        key.clear();
        value.clear();
        return CONTINUE_AS_IS;
    }
}

void b64Decode(
        const string &s,
        RegexSubCallback_f cb,
        int &decodedCount,
        int &deletedCount,
        string &outStr)
{
    decodedCount = 0;
    deletedCount = 0;
    outStr = "";
    int offsetFix = 0;

    string::const_iterator it = s.begin();

    // Minimal length
    if (s.end() - it < 8) {
        return;
    }

    // Search for substrings that match these criterias:
    //  1. substring length is divisible by 4
    //  2. substring contains only letters a-z, 0-9, '/' or '+' except last 1 or two characters that can be '='

    string::const_iterator chunkStart = s.end();
    for (; it != s.end(); ++it) {
        bool isB64AlphaChar = Waap::Util::isAlphaAsciiFast(*it) || isdigit(*it) || *it=='/' || *it=='+';
        if (chunkStart == s.end()) {
            if (isB64AlphaChar) {
                // start tracking potential b64 chunk
                chunkStart = it;
            }
            else {
                // Add anything before the potential match
                outStr += string(1, *it);
            }
        }
        else {
            // tracking b64 chunk
            if (!isB64AlphaChar) {
                if (*it == ',') {
                    // Check back and skip the "base64," prefix
                    if (chunkStart + b64_prefix.size() - 1 == it) {
                        string cand(chunkStart, it + 1);
                        if (cand == b64_prefix) {
                            offsetFix = b64_prefix.size();
                            continue;
                        }
                    }
                }

                size_t chunkLen = (it - chunkStart) - offsetFix;
                size_t chunkRem = chunkLen % 4;

                // Allow only one or two '=' characters at the end of the match
                if ((*it == B64_TRAILERCHAR) && (chunkRem == 2 || chunkRem == 3)) {
                    continue;
                }

                // Decode and add chunk
                b64TestChunk(s, chunkStart, it, cb, decodedCount, deletedCount, outStr);

                // stop tracking b64 chunk
                outStr += string(1, *it); // put the character that terminated the chunk
                chunkStart = s.end();
                offsetFix = 0;
            }
        }
    }

    if (chunkStart != s.end()) {
        b64TestChunk(s, chunkStart, it, cb, decodedCount, deletedCount, outStr);
    }
}

// Base64 functions stolen from orchestration_tools.cc
static const string base64_base_str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

string
base64Encode(const string &input)
{
    string out;
    int val = 0, val_base = -6;
    for (unsigned char c : input) {
        val = (val << 8) + c;
        val_base += 8;
        while (val_base >= 0) {
            out.push_back(base64_base_str[(val >> val_base) & 0x3F]);
            val_base -= 6;
        }
    }
    // -6 indicates the number of bits to take from each character
    // (6 bits is enough to present a range of 0 to 63)
    if (val_base > -6) out.push_back(base64_base_str[((val << 8) >> (val_base + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

bool find_in_map_of_stringlists_keys(const string &what, const map_of_stringlists_t &where)
{
    for (map_of_stringlists_t::const_iterator it = where.begin(); it != where.end(); ++it) {
        if (it->first.find(what) != string::npos) {
            return true;
        }
    }

    return false;
}

void remove_in_map_of_stringlists_keys(const string &what, map_of_stringlists_t &where)
{
    map_of_stringlists_t::iterator it = where.begin();

    while (it != where.end()) {
        if (it->first.find(what) != string::npos) {
            it = where.erase(it);
        }
        else {
            it++;
        }
    }
}

void remove_startswith(vector<string> &vec, const string &prefix)
{
    vec.erase(
        remove_if(vec.begin(), vec.end(),
            [&prefix](const string &kw)
            {
                return boost::starts_with(kw, prefix);
            }
        ),
        vec.end()
    );
}

string AES128Decrypt(
    string& key,
    string& iv,
    string& message)
{
    unsigned char* outdata = new unsigned char[message.length()];

    // data structure that contains the key itself
    AES_KEY aes_key;

    // set the encryption key
    AES_set_decrypt_key((const unsigned char*)key.c_str(), 128, &aes_key);

    AES_cbc_encrypt(
        (unsigned char*)message.c_str(),
        outdata, message.length(),
        &aes_key, (unsigned char*)iv.c_str(),
        AES_DECRYPT
        );

    // get value without padding
    size_t padding = outdata[message.length() - 1]; // last byte contain padding size
    string result = string((const char*)outdata, message.length() - padding);

    delete[] outdata;
    return result;
}

string
base64Decode(const string &input)
{
    string out;
    vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) {
        T[base64_base_str[i]] = i;
    }
    int val = 0, valb = -8;
    for (unsigned char c : input) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

bool
containsInvalidUtf8(const string &payload)
{
    return invalid_hex_evasion_re.hasMatch(payload);
}

string
unescapeInvalidUtf8(const string &payload)
{
    dbgFlow(D_WAAP_EVASIONS);
    vector<RegexMatchRange> regex_matches;
    invalid_hex_evasion_re.findMatchRanges(payload, regex_matches);

    string unescaped_text = payload;
    for (const auto &match : regex_matches) {
        static const int evasion_pattern_length = 3;

        int num = 0;
        size_t pos = match.start + 1;
        for (; pos < match.end; pos++) {
            const char &byte = unescaped_text[pos];
            if (isdigit(byte)) {
                num = (num << 4) + charToDigit(byte);
            } else {
                num = (num << 4) + ((tolower(byte) - 'a') + 10);
            }
        }

        char buf[evasion_pattern_length];
        snprintf(buf, evasion_pattern_length, "%02x", (num & 0xff));
        unescaped_text.replace(match.start + 1, evasion_pattern_length - 1, buf);

        dbgTrace(D_WAAP_EVASIONS) << "Value after conversion: decimal = " << num << ", hex = " << buf;
    }

    dbgTrace(D_WAAP_EVASIONS) << "unescaped_text: " << unescaped_text;

    return unescaped_text;
}

Maybe<std::string>
containsBrokenUtf8(const string &payload, const string &unquoted_payload)
{
    if (broken_utf_evasion_re.hasMatch(unquoted_payload)) {
        return unquoted_payload;
    } else if (broken_utf_evasion_re.hasMatch(payload)) {
        return payload;
    } else {
        return genError("does not contain broken-down UTF8");
    }
}

string
unescapeBrokenUtf8(const string &payload)
{
    string unescaped_text;
    unescaped_text.reserve(payload.length());

    int prev_esc_pos = -1;
    for (size_t pos = 0; pos < payload.length(); ++pos) {
        char c = payload[pos];
        if (c == '%') {
            // skip copying current '%' when encountered with the 2nd '%'
            // that follows and followed by only one hex digit
            if (prev_esc_pos >= 0 && pos-prev_esc_pos == 2 && isxdigit(payload[pos-1]) &&
                    pos+1 < payload.length() && isxdigit(payload[pos+1]) ) {
                prev_esc_pos = -1;
                continue;
            }
            // mark current '%' only when not following another '%'
            if (prev_esc_pos < 0 || pos-prev_esc_pos > 1) {
                prev_esc_pos = pos;
            }
        }
        unescaped_text += c;
    }

    dbgTrace(D_WAAP_EVASIONS) << "unescaped_text: " << unescaped_text;
    return unescaped_text;
}

bool
containsCspReportPolicy(const string &payload)
{
    return csp_report_policy_re.hasMatch(payload);
}

string
charToString(const char* s, int slen)
{
    if (!s || slen == 0) return "";

    return string(s, slen);
}

string
vecToString(const vector<string>& vec, char delim) {
    ostringstream vts;

    string delimStr;
    delimStr.push_back(delim);
    if (delim != '\n')
    {
        delimStr.push_back(' ');
    }

    vts << "[";
    if (!vec.empty())
    {
        // Convert all but the last element to avoid a trailing ","
        copy(vec.begin(), vec.end() - 1,
            ostream_iterator<string>(vts, delimStr.c_str()));

        // Now add the last element with no delimiter
        vts << vec.back();
    }
    else
    {
        return string();
    }
    vts << "]";


    return vts.str();
}


string
obfuscateXor(const string& toEncrypt) {
    char key[] = "CHECKPOINT"; //Any chars will work
    string output = toEncrypt;

    for (size_t i = 0; i < toEncrypt.size(); i++) {
        output[i] = toEncrypt[i] ^ key[i % ((sizeof(key)-1) / sizeof(char))];
    }

    return output;
}

string
obfuscateXorBase64(const string& toEncrypt) {
    return base64Encode(obfuscateXor(toEncrypt));
}

string injectSpacesToString(const string& str) {
    string retStr = "";
    if (str.length() == 0)
    {
        return retStr;
    }
    retStr.resize(str.length() * 2, ' ');
    for (size_t i = 0; i < str.length(); i++)
    {
        retStr[i * 2] = str[i];
    }
    retStr.pop_back();
    return retStr;
}

ReportIS::Severity computeSeverityFromThreatLevel(ThreatLevel threatLevel) {
    if (threatLevel == NO_THREAT) {
        return ReportIS::Severity::INFO;
    }
    else if (threatLevel == THREAT_INFO) {
        return ReportIS::Severity::LOW;
    }
    else if (threatLevel == LOW_THREAT) {
        return ReportIS::Severity::MEDIUM;
    }
    else if (threatLevel == MEDIUM_THREAT) {
        return ReportIS::Severity::HIGH;
    }

    return ReportIS::Severity::CRITICAL;
}

ReportIS::Priority computePriorityFromThreatLevel(ThreatLevel threatLevel) {
    if (threatLevel == NO_THREAT) {
        return ReportIS::Priority::LOW;
    }
    else if (threatLevel == THREAT_INFO) {
        return ReportIS::Priority::MEDIUM;
    }
    else if (threatLevel == LOW_THREAT) {
        return ReportIS::Priority::MEDIUM;
    }
    else if (threatLevel == MEDIUM_THREAT) {
        return ReportIS::Priority::HIGH;
    }

    return ReportIS::Priority::HIGH;
}

string computeConfidenceFromThreatLevel(ThreatLevel threatLevel)
{
    switch(threatLevel) {
        case NO_THREAT: return "Low";
        case THREAT_INFO: return "Low";
        case LOW_THREAT: return "Medium";
        case MEDIUM_THREAT: return "High";
        case HIGH_THREAT: return "Very High";
    }
    dbgWarning(D_WAAP) << "Reached impossible threat level value of: " << static_cast<int>(threatLevel);
    return "Low";
}

void decodePercentEncoding(string &text, bool decodePlus)
{
    // Replace %xx sequences by their single-character equivalents.
    // Do not replace the '+' symbol by space character because this would corrupt some base64 source strings
    // (base64 alphabet includes the '+' character).
    text.erase(
        unquote_plus(text.begin(), text.end(), checkUrlEncoded(text.data(), text.size()), decodePlus), text.end()
    );
    dbgTrace(D_WAAP) << "decodePercentEncoding: (after unquote_plus) '" << text << "'";
}

// Try to detect/decode UTF16 (detecting either BE and LE variant).
// The function uses statistics to try to guess whether UTF-16 is present and its exact variant (Big/Little endianess)
// If UTF-16 value is detected, value in cur_val is converted to utf8 in-place for use in later processing.
void decodeUtf16Value(const ValueStatsAnalyzer &valueStats, string &cur_val)
{
    // Do not change cur_val if UTF16 is not detected
    if (!valueStats.isUTF16) {
        return;
    }

    dbgTrace(D_WAAP) << "decoding UTF-16 into UTF-8 in-place";

    bool isBigEndian = false;
    size_t pos = 0;

    // First, detect BOM as a hint of UTF16-BE vs. LE variant. See https://unicode.org/faq/utf_bom.html#utf8-4
    if (cur_val[0] == (char)0xFE && cur_val[1] == (char)0xFF) {
        // UTF16-BE hint
        isBigEndian = true;
        // Skip the BOM
        pos++;
    }
    else if (cur_val[0] == (char)0xFF && cur_val[1] == (char)0xFE) {
        // UTF16-LE hint
        isBigEndian = false;
        // Skip the BOM
        pos++;
    }
    else {
        isBigEndian = (valueStats.longestZerosSeq[0] > valueStats.longestZerosSeq[1]);
    }

    // Decode utf16 into utf8
    string utf8Out;
    for (; pos<cur_val.length()/2; ++pos) {
        unsigned int code;

        if (isBigEndian) {
            code = (cur_val[pos*2] << 8) + cur_val[pos*2+1];
        }
        else {
            code = (cur_val[pos*2+1] << 8) + cur_val[pos*2];
        }

        // Encode UTF code point as UTF-8 bytes
        if (code < 0x80) {
            utf8Out += code;
        }
        else if (code < 0x800 ) {
            utf8Out += (code >> 6) | 0xC0;
            utf8Out += (code & 0x3F) | 0x80;
        }
        else { // (code <= 0xFFFF : always true because code type is unsigned short which is 16-bit
            utf8Out += (code >> 12) | 0xE0;
            utf8Out += ((code >> 6) & 0x3F) | 0x80;
            utf8Out += (code & 0x3F) | 0x80;
        }
    }

    // Return the value converted from UTF-16 to UTF-8
    cur_val = utf8Out;
}

bool testUrlBareUtf8Evasion(const string &line) {
    size_t percentPos = 0;

    while (percentPos < line.size()) {
        percentPos = line.find("%", percentPos);

        if (percentPos == string::npos) {
            return false;
        }

        if (percentPos + 2 < line.size() && tolower(line[percentPos + 1]) == 'c' && line[percentPos + 2] == '0') {
            // found "%c0"
            return true;
        }

        // Continue searching from next character after '%'
        percentPos++;
    }

    return false;
}

bool testUrlBadUtf8Evasion(const string &line) {
    size_t percentPos = 0;

    while (percentPos < line.size()) {
        percentPos = line.find("%", percentPos);

        if (percentPos == string::npos) {
            return false;
        }

        if (percentPos + 2 < line.size() && tolower(line[percentPos + 1]) == 'c' && line[percentPos + 2] == '1') {
            // found "%c1"
            return true;
        }

        // Continue searching from next character after '%'
        percentPos++;
    }

    return false;
}

string urlDecode(string src) {
    src.erase(unquote_plus(src.begin(), src.end(), true, false), src.end());
    return src;
}

// LCOV_EXCL_START Reason: The function will be deleted on another task
string
stripOptionalPort(const string::const_iterator &first, const string::const_iterator &last)
{
    // Microsoft XFF+IPv6+Port yikes - see also here https://github.com/eclipse/jetty.project/issues/3630
    if (*first == '[') {
        // Possible bracketed IPv6 address such as "[2001:db8::1]" + optional numeric ":<port>"
        auto close_bracket = find(first + 1, last, ']');
        if (close_bracket == last) return string(first, last);
        return string(first+1, close_bracket);
    }

    auto first_colon = find(first, last, ':');
    if (first_colon == last) return string(first, last);

    // If there is more than one colon it means its probably IPv6 address without brackets
    auto second_colon = find(first_colon + 1, last, ':');
    if (second_colon != last) return string(first, last);

    // If there's only one colon it can't be IPv6 and can only be IPv4 with port
    return string(first, first_colon);
}

bool
isIpTrusted(const string &ip, const vector<string> &trusted_ips)
{
    Waap::Util::CIDRData cidr_data;
    for (const auto &trusted_ip : trusted_ips) {
        if (
            ip == trusted_ip ||
            (Waap::Util::isCIDR(trusted_ip, cidr_data) && Waap::Util::cidrMatch(ip, cidr_data))
        ) {
            return true;
        }
    }
    return false;
}

string extractForwardedIp(const string &x_forwarded_hdr_val)
{
    vector<string> xff_splitted = split(x_forwarded_hdr_val, ',');
    vector<string> trusted_ips;
    string forward_ip;

    auto identify_config = getConfiguration<UsersAllIdentifiersConfig>(
        "rulebase",
        "usersIdentifiers"
    );

    if (!identify_config.ok()) {
        dbgDebug(D_WAAP) << "did not find xff definition in policy";
    } else {
        trusted_ips = (*identify_config).getHeaderValuesFromConfig("x-forwarded-for");
    }

    if (xff_splitted.size() > 0)
    {
        for (size_t k = 0; k < xff_splitted.size(); ++k)
        {
            string optional_result = trim(xff_splitted[k]);
            optional_result = stripOptionalPort(optional_result.cbegin(), optional_result.cend());
            if (isIpAddress(optional_result))
            {
                if (!isIpTrusted(optional_result, trusted_ips) && !trusted_ips.empty()) {
                    return "";
                } else if (forward_ip.empty()) {
                    forward_ip = optional_result;
                }
            }
        }
    }
    return forward_ip;
}

bool isIpAddress(const string &ip_address)
{
    struct in_addr source_inaddr;
    struct in6_addr source_inaddr6;

    // check from which type the target ip and check if ip belongs to is mask ip
    //convert sourceip to ip v4 or v6.
    bool isIpV4 = inet_pton(AF_INET, ip_address.c_str(), &source_inaddr) == 1;
    bool isIpV6 = inet_pton(AF_INET6, ip_address.c_str(), &source_inaddr6) == 1;

    return isIpV4 || isIpV6;
}

// LCOV_EXCL_STOP

string extractKeyValueFromCookie(const string &cookie, const string &key)
{
    string source = "";
    vector<string> cookie_splitted = split(cookie, ';');
    for (size_t l = 0; l < cookie_splitted.size(); ++l)
    {
        vector<string> cookie_key_splitted = split(cookie_splitted[l], '=');
        if (cookie_key_splitted.empty())
        {
            dbgWarning(D_WAAP) << "Failed to split the key-value from: " << cookie_splitted[l];
            continue;
        }
        if (cookie_key_splitted[0] == key)
        {
            source = cookie_key_splitted[1];

            if (key == "_oauth2_proxy")
            {
                source = Waap::Util::base64Decode(source);

                vector<string> currentUserIdentifier_splitted = split(source, '|');

                if (currentUserIdentifier_splitted.size() > 0)
                {
                    source = currentUserIdentifier_splitted[0];
                }
            }
            break;
        }
    }
    dbgTrace(D_WAAP) << "extracted source from Cookie:" << key << " : " << source;
    return source;
}

bool vectorStringContain(const vector<string>& vec, const string& str)
{
    for(auto &param : vec) {
        if(param.compare(str) == 0)
        {
            return true;
        }
    }
    return false;
}

ContentType detectContentType(const char* hdr_value) {
    const char* plus_p = ::strrchr(hdr_value, '+');
    // Detect XML content type if Content-Type header value ends with "+xml".
    // For example: "application/xhtml+xml", or "image/svg+xml"
    // For reference: see first answer here:
    // https://stackoverflow.com/questions/2965587/valid-content-type-for-xml-html-and-xhtml-documents
    if (plus_p && my_stricmp(plus_p + 1, "xml")) {
        return CONTENT_TYPE_XML;
    }

    const char* slash_p = ::strrchr(hdr_value, '/');

    if (slash_p) {
        // Detect XML content type if Content-Type header value ends with "/xml"
        if (my_stricmp(slash_p + 1, "xml")) {
            return CONTENT_TYPE_XML;
        }

        // Detect JSON content type if Content-Type header value is application/json or ends with "/json"
        if (my_stricmp(slash_p + 1, "json") || my_stristarts_with(hdr_value, "application/json")) {
            return CONTENT_TYPE_JSON;
        }

        // Detect Graphql content type if Content-Type header value is application/graphql
        if (my_stristarts_with(hdr_value, "application/graphql")) {
            return CONTENT_TYPE_GQL;
        }

        // Detect HTML content type
        if (my_stristarts_with(hdr_value, "text/html")) {
            return CONTENT_TYPE_HTML;
        }

        // Detect Multiplart Form Data content type
        if (my_stristarts_with(hdr_value, "multipart/form-data")) {
            return CONTENT_TYPE_MULTIPART_FORM;
        }

        // Detect URL Encoded content type
        if (my_stristarts_with(hdr_value, "application/x-www-form-urlencoded")) {
            return CONTENT_TYPE_URLENCODED;
        }

        // Detect binary xml file type
        if (my_stristarts_with(hdr_value, "application/vnd.ms-sync.wbxml")) {
            return CONTENT_TYPE_WBXML;
        }
    }

    return CONTENT_TYPE_UNKNOWN;
}

string convertParamTypeToStr(ParamType type)
{
    switch (type)
    {
    case UNKNOWN_PARAM_TYPE:
        return "unknown";
    case HTML_PARAM_TYPE:
        return "html_input";
    case URL_PARAM_TYPE:
        return "urls";
    case FREE_TEXT_PARAM_TYPE:
        return "free_text";
    case FREE_TEXT_FRENCH_PARAM_TYPE:
        return "free_text_french";
    case PIPE_PARAM_TYPE:
        return "pipes";
    case LONG_RANDOM_TEXT_PARAM_TYPE:
        return "long_random_text";
    case BASE64_PARAM_TYPE:
        return "base64";
    case ADMINISTRATOR_CONFIG_PARAM_TYPE:
        return "administration_config";
    case FILE_PATH_PARAM_TYPE:
        return "local_file_path";
    case SEMICOLON_DELIMITED_PARAM_TYPE:
        return "semicolon_delimiter";
    case ASTERISK_DELIMITED_PARAM_TYPE:
        return "asterisk_delimiter";
    case COMMA_DELIMITED_PARAM_TYPE:
        return "comma_delimiter";
    case AMPERSAND_DELIMITED_PARAM_TYPE:
        return "ampersand_delimiter";
    case BINARY_PARAM_TYPE:
        return "binary_input";
    default:
        dbgWarning(D_WAAP) << "unrecognized type " << to_string(type);
        return "unrecognized type";
    }
}

ParamType convertTypeStrToEnum(const string& typeStr)
{
    static unordered_map<string, ParamType> sNameTypeMap = {
    {"unknown", ParamType::UNKNOWN_PARAM_TYPE},
    {"administration_config", ParamType::ADMINISTRATOR_CONFIG_PARAM_TYPE},
    {"base64", ParamType::BASE64_PARAM_TYPE },
    {"free_text", ParamType::FREE_TEXT_PARAM_TYPE},
    {"free_text_french", ParamType::FREE_TEXT_FRENCH_PARAM_TYPE},
    {"html_input", ParamType::HTML_PARAM_TYPE},
    {"long_random_text", ParamType::LONG_RANDOM_TEXT_PARAM_TYPE},
    {"pipes", ParamType::PIPE_PARAM_TYPE},
    {"urls", ParamType::URL_PARAM_TYPE},
    {"local_file_path", ParamType::FILE_PATH_PARAM_TYPE},
    {"semicolon_delimiter", ParamType::SEMICOLON_DELIMITED_PARAM_TYPE},
    {"asterisk_delimiter", ParamType::ASTERISK_DELIMITED_PARAM_TYPE},
    {"comma_delimiter", ParamType::COMMA_DELIMITED_PARAM_TYPE},
    {"ampersand_delimiter", ParamType::AMPERSAND_DELIMITED_PARAM_TYPE},
    {"binary_input", ParamType::BINARY_PARAM_TYPE}
    };

    auto mapItr = sNameTypeMap.find(typeStr);
    if (mapItr != sNameTypeMap.end())
    {
        return mapItr->second;
    }
    dbgWarning(D_WAAP) << "unrecognized parameter type name: " << typeStr;
    return UNKNOWN_PARAM_TYPE;

}


}
}
