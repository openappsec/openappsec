#include "single_keyword.h"
#include "output.h"
#include "debug.h"

#include <map>
#include <strings.h>

using namespace std;

USE_DEBUG_FLAG(D_KEYWORD);

class DataKeyword : public SingleKeyword
{
public:
    explicit DataKeyword(const vector<KeywordAttr> &attr, const VariablesMapping &vars);
    MatchStatus isMatch(const I_KeywordRuntimeState* prev) const override;

private:
    void
    setOffset(const KeywordAttr &attr, const VariablesMapping &vars)
    {
        offset.setAttr(attr, vars, "data");
    }

    void
    setDepth(const KeywordAttr &attr, const VariablesMapping &vars)
    {
        depth.setAttr(attr, vars, "data");
    }

    void
    setCaret(const KeywordAttr &attr, const VariablesMapping &)
    {
        is_caret.setAttr(attr, "data");
    }

    void
    setRelative(const KeywordAttr &attr, const VariablesMapping &)
    {
        is_relative.setAttr(attr, "data");
    }

    void
    setCaseInsensitive(const KeywordAttr &attr, const VariablesMapping &)
    {
        is_case_insensitive.setAttr(attr, "data");
    }

    void
    setContext(const KeywordAttr &attr, const VariablesMapping &)
    {
        ctx.setAttr(attr, "data");
    }

    void parseString(const string &str);

    void
    addChar(char ch)
    {
        pattern.push_back(static_cast<unsigned char>(ch));
    }

    void calcTables();

    pair<uint, uint> getStartAndEndOffsets(uint buf_size, const I_KeywordRuntimeState *prev) const;
    uint bytesMatched(const Buffer&, uint) const;

    uint
    moveOnMatch() const
    {
        return pattern.size();
    }

    uint
    moveOnNoMatch(uint offset_from_end, unsigned char first_unmatched_byte) const
    {
        dbgAssert(shift.size() > offset_from_end) << "Shift table of the 'data' keyword is shorter than the offset";

        uint skip_size;
        if (skip[first_unmatched_byte]>offset_from_end) {
            skip_size = skip[first_unmatched_byte]-offset_from_end;
        } else {
            skip_size = 1;
        }

        return max(shift[offset_from_end], skip_size);
    }

    bool
    isConstant() const
    {
        return !is_relative && offset.isConstant() && depth.isConstant();
    }

    vector<unsigned char> pattern;
    uint                  skip[256];
    vector<uint>          shift;

    NumericAttr           offset;
    NumericAttr           depth;
    BoolAttr              is_negative;
    BoolAttr              is_caret;
    BoolAttr              is_relative;
    BoolAttr              is_case_insensitive;
    CtxAttr               ctx;

    static const map<string, void(DataKeyword::*)(const KeywordAttr &, const VariablesMapping &)> setops;
};

const map<string, void(DataKeyword::*)(const KeywordAttr &, const VariablesMapping &)> DataKeyword::setops = {
    { "relative", &DataKeyword::setRelative        },
    { "offset",   &DataKeyword::setOffset          },
    { "depth",    &DataKeyword::setDepth           },
    { "caret",    &DataKeyword::setCaret           },
    { "nocase",   &DataKeyword::setCaseInsensitive },
    { "part",     &DataKeyword::setContext         }
};

DataKeyword::DataKeyword(const vector<KeywordAttr> &attrs, const VariablesMapping &vars)
        :
    offset(),
    depth()
{
    auto &pattern_param = attrs[0].getParams();

    if (pattern_param.size() != 1) throw KeywordError("More than one element in the 'data' keyword pattern");
    const string &string_pattern = pattern_param[0];

    if (string_pattern.length() == 0) throw KeywordError("No input for the 'data' keyword");

    uint start = 0;
    if (string_pattern[0] == '!') {
        is_negative.setAttr("data", "negative");
        start++;
    }
    if (string_pattern[start] != '"') throw KeywordError("The data pattern does not begin with '\"'");

    uint end = string_pattern.length()-1;
    if (string_pattern[end] != '"') throw KeywordError("The data pattern does not end with '\"'");

    if (start+1 >= end) throw KeywordError("No input for the 'data' keyword");

    parseString(string_pattern.substr(start+1, end-(start+1)));

    for (uint i = 1; i<attrs.size(); i++) {
        auto curr = setops.find(attrs[i].getAttrName());
        if (curr == setops.end()) {
            throw KeywordError("Unknown attribute '" + attrs[i].getAttrName() + "' in the 'data' keyword");
        }
        auto set_func = curr->second;
        (this->*set_func)(attrs[i], vars);
    }

    calcTables();
}

void
DataKeyword::calcTables()
{
    if (is_case_insensitive) {
        for (auto &ch : pattern) {
            if (isupper(ch)) {
                ch = tolower(ch);
            }
        }
    }

    // Initialize skip table - when we meet a charecter that isn't in the pattern, we skip the whole pattern
    for (auto &ch_skip : skip) {
        ch_skip = pattern.size();
    }

    // Go over the charecters in the pattern.
    // We can skip from a charecter to the end of the pattern.
    // If a charecter appear more than once, the latest occurence take precedent.
    for (uint index = 0; index<pattern.size(); index++) {
        unsigned char ch = pattern[index];

        uint dist_to_end = pattern.size()-(index+1);
        if (is_case_insensitive && islower(ch)) {
            skip[toupper(ch)] = dist_to_end;
        }
        skip[ch] = dist_to_end;
    }

    // Initialize the shift table.
    shift.resize(pattern.size(), 0);

    uint end_offset = pattern.size()-1;
    // Go over all the suffixes (from the empty to the pattern-1)
    for (size_t suffix_len = 0; suffix_len<pattern.size(); suffix_len++) {
        // Find the smallest shift, so when shifting the suffix left:
        // 1. All chars overlapping between pattern and shifted suffix match.
        // 2. If the character before the shifted suffix overlaps the pattern, it doesn't match.
        // pattern = "hellololo", suff=2 (must match "[^o]lo"), shift=4 ("hel(lo)lolo")
        // pattern = "olo" suff=2 (must match "[^o]lo"), shift=2 ("(.o)lo")
        //           characters before the patterns are considered wild.
        for (uint shift_offset = 1; shift_offset<=pattern.size(); shift_offset++) {
            // Verify that in the current offset matches the suffix
            size_t num_of_overlapping_char;
            unsigned char *suffix_start_ptr;
            unsigned char *shifted_suffix_start_ptr;
            if (shift_offset+suffix_len <= pattern.size()) {
                // Shifted suffix doesn't exceed the pattern. Compare the whole suffix.
                num_of_overlapping_char  = suffix_len;
                suffix_start_ptr         = pattern.data() + pattern.size() - suffix_len;
                shifted_suffix_start_ptr = suffix_start_ptr - shift_offset;
            } else {
                // Shifted suffix exceeds the pattern. Compare only the overlaping charecters.
                num_of_overlapping_char  = pattern.size() - shift_offset;
                suffix_start_ptr         = pattern.data() + shift_offset;
                shifted_suffix_start_ptr = pattern.data();
            }

            if (bcmp(suffix_start_ptr, shifted_suffix_start_ptr, num_of_overlapping_char) != 0) continue;

            // Verify that what comes after the suffix doesn't match
            if (shift_offset+suffix_len < pattern.size()) {
                if (pattern[end_offset-suffix_len] == pattern[end_offset-(shift_offset+suffix_len)]) continue;
            }

            // Set the currect shift offset
            shift[suffix_len] = shift_offset;
            break;
        }
    }
}

void
DataKeyword::parseString(const string &str)
{
    string hex;
    bool hex_mode = false;
    bool after_bslash = false;

    for (auto ch : str) {
        if (after_bslash) {
            if (!isprint(ch)) {
                throw KeywordError(
                    "Illegal backslash character '" +
                    dumpHexChar(ch) +
                    "' in the pattern in the 'data' keyword"
                );
            }
            addChar(ch);
            after_bslash = false;
            continue;
        }

        switch (ch) {
        case '|': {
            if (!hex_mode) {
                hex = "";
                hex_mode = true;
            } else {
                if (hex.size()>0) throw KeywordError("Stoping in the middle of hex string in the 'data' keyword");
                hex_mode = false;
            }
            break;
        }
        case '\\': {
            if (hex_mode) throw KeywordError("Backslash in hex string in the 'data' keyword");
            after_bslash = true;
            break;
        }
        case '"': {
            throw KeywordError("Unescaped double quotation mark in the 'data' keyword");
            break;
        }
        default:
            if (hex_mode) {
                if (!isxdigit(ch)) {
                    if (ch != ' ') {
                        throw KeywordError(
                            "Illegal character '" +
                            dumpHexChar(ch) +
                            "' in the hex string in the 'data' keyword"
                        );
                    }
                    if (hex.size()>0) {
                        throw KeywordError("Space separating nibbles in the hex string in the 'data' keyword");
                    }
                    break;
                }

                hex += ch;

                if (hex.size()>=2) {
                    addChar(stol(hex, nullptr, 16));
                    hex = "";
                }
            } else {
                if (!isprint(ch)) {
                    throw KeywordError(
                        "Illegal character '" +
                        dumpHexChar(ch) +
                        "' in the pattern in the 'data' keyword"
                    );
                }
                addChar(ch);
            }
        }
    }

    if ( hex_mode || after_bslash ) {
        throw KeywordError("The 'data' keyword's pattern has ended in the middle of the parsing");
    }
}

static uint
addOffset(uint offset, int add)
{
    if (add<0 && offset<static_cast<uint>(-add)) return 0;
    return offset + add;
}

pair<uint, uint>
DataKeyword::getStartAndEndOffsets(uint buf_size, const I_KeywordRuntimeState *prev) const
{
    uint relative_offset = is_relative?prev->getOffset(ctx):0;
    int offset_attr = offset.evalAttr(prev);
    uint start_offset = addOffset(relative_offset, offset_attr);

    if (depth.isSet()) {
        uint depth_size = addOffset(start_offset, depth.evalAttr(prev));
        buf_size = std::min(buf_size, depth_size);
    }
    if (is_caret) {
        buf_size = std::min(buf_size, start_offset+static_cast<uint>(pattern.size()));
    }

    return make_pair(start_offset, buf_size);
}

uint
DataKeyword::bytesMatched(const Buffer &buf, uint offset) const
{
    if (is_case_insensitive) {
        for (uint i = 0;  i<pattern.size(); i++) {
            if (pattern[pattern.size()-(i+1)] != tolower(buf[offset-(i+1)])) return i;
        }
    } else {
        for (uint i = 0 ; i < pattern.size() ; i++ ) {
            if (pattern[pattern.size()-(i+1)] != buf[offset-(i+1)] ) return i;
        }
    }
    return pattern.size();
}

MatchStatus
DataKeyword::isMatch(const I_KeywordRuntimeState *prev) const
{
    dbgAssert(pattern.size()>0) << "Trying to run on an uninitialized keyword data";

    dbgDebug(D_KEYWORD) << "Searching for " << dumpHex(pattern);

    auto part = Singleton::Consume<I_Environment>::by<KeywordComp>()->get<Buffer>(static_cast<string>(ctx));
    if (!part.ok()) {
        if (is_negative) return runNext(prev);
        return MatchStatus::NoMatchFinal;
    }

    const auto &buf = part.unpack();

    dbgTrace(D_KEYWORD) << "Full buffer: " << dumpHex(buf);

    uint offset, max_offset;

    tie(offset, max_offset) = getStartAndEndOffsets(buf.size(), prev);
    offset += pattern.size();

    bool match_found = false;
    while (offset<=max_offset) {
        // Short circuit for the common, simple case where the last byte doesn't match
        if (skip[buf[offset-1]]) {
            offset += skip[buf[offset - 1]];
            continue;
        }

        // Full search Boyer-Moore
        uint match_size = bytesMatched(buf, offset);
        if (match_size == pattern.size()) {
            if (is_negative) {
                return isConstant()?MatchStatus::NoMatchFinal:MatchStatus::NoMatch;
            }
            match_found = true;
            OffsetRuntimeState new_offset(prev, ctx, offset);
            auto next_keyword_result = runNext(&new_offset);
            if (next_keyword_result!=MatchStatus::NoMatch) return next_keyword_result;
            offset += moveOnMatch();
        } else {
            offset += moveOnNoMatch(match_size, buf[offset-(match_size+1)]);
        }
    }

    // No matchs is a success for negative keywords
    if (is_negative && !match_found) return runNext(prev);

    // If there were no matchs and the keyword is an effected by other keywords, then we know that the rule won't match
    if (isConstant() && !match_found) return MatchStatus::NoMatchFinal;

    return MatchStatus::NoMatch;
}

unique_ptr<SingleKeyword>
genDataKeyword(const vector<KeywordAttr> &attr, VariablesMapping &known_vars)
{
    return make_unique<DataKeyword>(attr, known_vars);
}
