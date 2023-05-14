#include "single_keyword.h"

#include <algorithm>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include "output.h"
#include "debug.h"

using namespace std;

USE_DEBUG_FLAG(D_KEYWORD);

class PCREKeyword : public SingleKeyword
{
public:
    explicit PCREKeyword(const vector<KeywordAttr> &attr, const VariablesMapping &known_vars);
    MatchStatus isMatch(const I_KeywordRuntimeState *prev) const override;

private:
    void
    setOffset(const KeywordAttr &attr, const VariablesMapping &vars)
    {
        offset.setAttr(attr, vars, "pcre");
    }

    void
    setDepth(const KeywordAttr &attr, const VariablesMapping &vars)
    {
        depth.setAttr(attr, vars, "pcre");
    }

    void
    setRelative(const KeywordAttr &attr, const VariablesMapping &)
    {
        is_relative.setAttr(attr, "pcre");
    }

    void
    setCaseInsensitive(const KeywordAttr &attr, const VariablesMapping &)
    {
        is_case_insensitive.setAttr(attr, "pcre");
    }

    void
    setContext(const KeywordAttr &attr, const VariablesMapping &)
    {
        ctx.setAttr(attr, "pcre");
    }

    string parseString(const string &str);
    pair<string, string> findExprInStr(const string &str, size_t start, size_t end);
    void parseOptions(const string &str);
    void compilePCRE(const string &str);

    pair<uint, uint> getStartOffsetAndLength(uint buf_size, const I_KeywordRuntimeState *prev) const;

    bool
    isConstant() const
    {
        return !is_relative && offset.isConstant() && depth.isConstant();
    }

    class PCREDelete
    {
    public:
        void
        operator()(pcre2_code *ptr)
        {
            pcre2_code_free(ptr);
        }
    };
    unique_ptr<pcre2_code, PCREDelete> pcre_machine;

    class PCREResultDelete
    {
    public:
        void
        operator()(pcre2_match_data *ptr)
        {
            pcre2_match_data_free(ptr);
        }
    };
    unique_ptr<pcre2_match_data, PCREResultDelete> pcre_result;

    NumericAttr offset;
    NumericAttr depth;
    BoolAttr is_negative;
    BoolAttr is_relative;

    BoolAttr is_case_insensitive;
    BoolAttr is_multiline;
    BoolAttr is_dotall;
    BoolAttr is_extended;
    BoolAttr is_dollar_endonly;
    BoolAttr is_anchor;
    BoolAttr is_ungreedy;

    CtxAttr ctx;

    string pcre_expr;

    static const map<string, void(PCREKeyword::*)(const KeywordAttr &, const VariablesMapping &)> setops;
};

const map<string, void(PCREKeyword::*)(const KeywordAttr&, const VariablesMapping&)> PCREKeyword::setops = {
    { "relative", &PCREKeyword::setRelative        },
    { "offset",   &PCREKeyword::setOffset          },
    { "depth",    &PCREKeyword::setDepth           },
    { "nocase",   &PCREKeyword::setCaseInsensitive },
    { "part",     &PCREKeyword::setContext         },
};

PCREKeyword::PCREKeyword(const vector<KeywordAttr> &attrs, const VariablesMapping &known_vars)
        :
    offset(),
    depth()
{
    auto &expr_param = attrs[0].getParams();
    if (expr_param.size() != 1) throw KeywordError("More than one element in the 'pcre' keyword pattern");
    auto expr = parseString(expr_param[0]);
    dbgDebug(D_KEYWORD) << "Creating a new 'pcre' expression: " << expr;

    for (uint i = 1; i<attrs.size(); i++) {
        auto curr = setops.find(attrs[i].getAttrName());
        if (curr == setops.end()) {
            throw KeywordError("Unknown attribute '" + attrs[i].getAttrName() + "' in the 'pcre' keyword");
        }
        auto set_func = curr->second;
        (this->*set_func)(attrs[i], known_vars);
    }

    compilePCRE(expr);
}

string
PCREKeyword::parseString(const string &str)
{
    size_t start_offset = 0, end_offset = str.size();

    if (start_offset<end_offset && str[start_offset]=='!') {
        is_negative.setAttr("pcre", "negative");
        start_offset++;
    }

    if (start_offset+1>=end_offset || str[start_offset]!='"' || str[end_offset-1]!='"') {
        throw KeywordError("The 'pcre' expression should be enclosed in quotation marks");
    }
    start_offset++;
    end_offset--;

    string expr, options;
    tie(expr, options) = findExprInStr(str, start_offset, end_offset);

    parseOptions(options);

    return expr;
}

pair<string, string>
PCREKeyword::findExprInStr(const string &str, size_t start, size_t end)
{
    if (start>=end) throw KeywordError("The 'pcre' string is empty");

    // There are two way to write the regular expression:
    // Either between '/' charecters: "/regexp/"  (this is the default delimiter)
    // Or use 'm' to set a delimiter: "mDregexpD" (here 'D' is used as the delimiter)
    // The switch will set the parameter 'start' so the 'str[start]' is the first delimiter.
    switch (str[start]) {
        case '/': {
            break;
        }
        case 'm': {
            start++;
            if (start>=end) {
                throw KeywordError("Failed to detect a delimiter in the 'pcre' keyword regular expression");
            }
            break;
        }
        default:
            KeywordError("Bad start for the 'pcre' regular expression");
    }

    size_t expr_end = str.find_last_of(str[start], end-1);
    start++;
    if (expr_end<=start) throw KeywordError("The 'pcre' regular expression is empty");

    auto options_start = expr_end+1;
    return make_pair(str.substr(start, expr_end-start), str.substr(options_start, end-options_start));
}

void
PCREKeyword::parseOptions(const string &options)
{
    for (auto ch : options) {
        switch (ch) {
            case 'i': {
                is_case_insensitive.setAttr("pcre", "nocase");
                break;
            }
            case 'R': {
                is_relative.setAttr("pcre", "relative");
                break;
            }
            case 'm': {
                is_multiline.setAttr("pcre", "multiline");
                break;
            }
            case 's': {
                is_dotall.setAttr("pcre", "dotall");
                break;
            }
            case 'x': {
                is_extended.setAttr("pcre", "extended");
                break;
            }
            case 'E': {
                is_dollar_endonly.setAttr("pcre", "dollar_endonly");
                break;
            }
            case 'A': {
                is_anchor.setAttr("pcre", "anchor");
                break;
            }
            case 'G': {
                is_ungreedy.setAttr("pcre", "ungreedy");
                break;
            }
            default:
                throw KeywordError("Unknown option " +  dumpHexChar(ch) + " in the 'pcre' keyword");
        }
    }
}

void
PCREKeyword::compilePCRE(const string &expr)
{
    uint32_t options = PCRE2_NO_AUTO_CAPTURE;
    if (is_case_insensitive) options |= PCRE2_CASELESS;
    if (is_multiline)        options |= PCRE2_MULTILINE;
    if (is_dotall)           options |= PCRE2_DOTALL;
    if (is_extended)         options |= PCRE2_EXTENDED;
    if (is_dollar_endonly)   options |= PCRE2_DOLLAR_ENDONLY;
    if (is_anchor)           options |= PCRE2_ANCHORED;
    if (is_ungreedy)         options |= PCRE2_UNGREEDY;

    int error;
    PCRE2_SIZE error_offset;
    auto pattern = reinterpret_cast<PCRE2_SPTR>(expr.c_str());
    pcre_machine.reset(pcre2_compile(pattern, expr.size(), options, &error, &error_offset, nullptr));
    if (pcre_machine == nullptr) {
        vector<u_char> msg;
        msg.reserve(128);
        pcre2_get_error_message(error, msg.data(), msg.capacity());

        throw KeywordError(
            "Failed to compile the 'pcre' at offset "
            + to_string(error_offset)
            + " with error: "
            + reinterpret_cast<char *>(msg.data())
        );
    }

    pcre_result.reset(pcre2_match_data_create_from_pattern(pcre_machine.get(), nullptr));
    if (pcre_result == nullptr) {
        throw KeywordError("Failed to allocate PCRE results container");
    }

    pcre_expr = expr;
}

static uint
addOffset(uint offset, int add)
{
    if (add<0 && offset<static_cast<uint>(-add)) return 0;
    return offset + add;
}

pair<uint, uint>
PCREKeyword::getStartOffsetAndLength(uint buf_size, const I_KeywordRuntimeState *prev) const
{
    uint keyword_offset = is_relative?prev->getOffset(ctx):0;
    uint start_offset = addOffset(keyword_offset, offset.evalAttr(prev));

    if (start_offset>=buf_size) return make_pair(0, 0);

    uint length = buf_size-start_offset;

    if (depth.isSet()) {
        length = min(length, static_cast<uint>(depth.evalAttr(prev)));
    }

    return make_pair(start_offset, length);
}

MatchStatus
PCREKeyword::isMatch(const I_KeywordRuntimeState *prev) const
{
    dbgAssert(pcre_machine!=nullptr) << "Trying to run on an uninitialized keyword 'pcre'";

    auto part = Singleton::Consume<I_Environment>::by<KeywordComp>()->get<Buffer>(static_cast<string>(ctx));

    if (!part.ok()) {
        if (is_negative) {
            return runNext(prev);
        }
        return MatchStatus::NoMatchFinal;
    }

    uint offset, length;
    tie(offset, length) = getStartOffsetAndLength((*part).size(), prev);
    auto buf = (*part).getPtr(offset, length);

    if (!buf.ok()) {
        dbgTrace(D_KEYWORD) << "Could not get the buffer for the 'pcre' keyword";
        return MatchStatus::NoMatchFinal;
    }
    const unsigned char *ptr = *buf;

    bool match_found = false;
    uint buf_offset_found;
    for (uint buf_pos = 0; buf_pos<length; buf_pos = buf_offset_found) {
        dbgDebug(D_KEYWORD) << "Looking for expression: " << pcre_expr;
        dbgTrace(D_KEYWORD) << "Running pcre_exec for expression: " << ptr;
        int result = pcre2_match(
            pcre_machine.get(),
            ptr,
            length,
            buf_pos,
            0,
            pcre_result.get(),
            nullptr
        );

        if (result<0) {
            // No match (possiblely due to an error)
            dbgDebug(D_KEYWORD) << "No match, possiblely due to an error in 'pcre_exec'";
            break;
        } else {
            dbgDebug(D_KEYWORD) << "Match found";
        }

        if (is_negative) {
            return isConstant()?MatchStatus::NoMatchFinal:MatchStatus::NoMatch;
        }
        match_found = true;
        buf_offset_found = pcre2_get_ovector_pointer(pcre_result.get())[0];
        OffsetRuntimeState new_offset(prev, ctx, offset+buf_offset_found);
        auto next_keyword_result = runNext(&new_offset);
        if (next_keyword_result!=MatchStatus::NoMatch) return next_keyword_result;
        if (buf_offset_found<=buf_pos) buf_offset_found = buf_pos+1; // Deal with empty matches
    }

    // No matchs is a success for negative keywords
    if (is_negative && !match_found) {
        return runNext(prev);
    }

    // If there were no matchs and the keyword is an effected by other keywords, then we know that the rule won't match
    if (isConstant() && !match_found) {
        return MatchStatus::NoMatchFinal;
    }

    return MatchStatus::NoMatch;
}

unique_ptr<SingleKeyword>
genPCREKeyword(const vector<KeywordAttr> &attr, VariablesMapping &known_vars)
{
    return make_unique<PCREKeyword>(attr, known_vars);
}
