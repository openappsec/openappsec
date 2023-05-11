#include "keyword_comp.h"

#include <vector>
#include "sentinel_runtime_state.h"

using namespace std;

static const string whitespaces = " \t";

static string
getSubStrNoPadding(const string &str, uint start, uint end)
{
    auto r_start = str.find_first_not_of(whitespaces, start);
    auto r_end = str.find_last_not_of(whitespaces, end-1);

    if (r_end==string::npos || r_start==string::npos || r_start>r_end) {
        throw KeywordError("Found an empty section in the '"+ str + "'");
    }

    return str.substr(r_start, r_end-r_start+1);
}

static vector<string>
split(const string &str, const string &delim, uint start = 0)
{
    vector<string> res;
    uint part_start = start;
    bool escape = false;
    bool in_string = false;

    for (uint index = start; index<str.size(); index++) {
        if (escape) {
            escape = false;
            continue;
        }

        switch (str[index]) {
            case '\\': {
                escape = true;
                break;
            }
            case '"': {
                in_string = !in_string;
                break;
            }
            default:
                if (!in_string && delim.find(str[index])!=string::npos) {
                    res.push_back(getSubStrNoPadding(str, part_start, index));
                    part_start = index+1;
                }
        }
    }

    if (escape||in_string) throw KeywordError("Split has ended in the middle of the parsing");

    if (str.find_first_not_of(whitespaces, part_start)!=string::npos) {
        res.push_back(getSubStrNoPadding(str, part_start, str.size()));
    }

    return res;
}

KeywordAttr::KeywordAttr(const string &str) : params(split(str, whitespaces))
{
}

KeywordParsed::KeywordParsed(string const &keyword) {
    auto index = keyword.find_first_of(':');
    if (index!=string::npos) {
        for (auto &str : split(keyword, ",", index+1)) {
            attr.push_back(KeywordAttr(str));
        }
    } else {
        index = keyword.size();
    }

    name = getSubStrNoPadding(keyword, 0, index);
    if (name.find_first_of(whitespaces)!=string::npos) {
        throw KeywordError("'" + name + "' - cannot be a keyword name");
    }
}

uint
SentinelRuntimeState::getOffset(const std::string &) const
{
    return 0;
}

// LCOV_EXCL_START Reason: this function is tested in one_element_list_negative_test but marked as not covered.
uint
SentinelRuntimeState::getVariable(uint var_id) const
{
    dbgAssert(false) << "Could not find the variable ID: " << var_id;
    return 0;
}
// LCOV_EXCL_STOP

class SentinelKeyword : public SingleKeyword
{
public:
    MatchStatus
    isMatch() const
    {
        SentinelRuntimeState curr_state;
        return runNext(&curr_state);
    }

private:
    // LCOV_EXCL_START Reason: Unreachable function.
    MatchStatus
    isMatch(const I_KeywordRuntimeState *state) const override
    {
        return runNext(state);
    }
    // LCOV_EXCL_STOP
};

class KeywordComp::Impl : Singleton::Provide<I_KeywordsRule>::From<KeywordComp>
{
public:
    Maybe<shared_ptr<VirtualRule>>
    genRule(const string &rule)
    {
        shared_ptr<VirtualRule> res;
        try {
            res = KeywordsRuleImpl::genRule(rule);
        } catch (const KeywordError &e) {
            return genError(e.getErr());;
        }
        return move(res);
    }

private:
    class KeywordsRuleImpl : public VirtualRule
    {
    public:
        bool isMatch() const override { return start.isMatch() == MatchStatus::Match; }

        static unique_ptr<KeywordsRuleImpl>
        genRule(const string &rule)
        {
            auto res = make_unique<KeywordsRuleImpl>();

            auto pos = rule.find_last_not_of(whitespaces);
            if (pos==string::npos) {
                // Empty rule
                return res;
            }

            if (rule[pos]!=';') throw KeywordError(rule + " - end of text pass rule");

            VariablesMapping known_vars;

            auto key_vec = split(rule, ";");
            for (auto &keyword : key_vec) {
                res->start.appendKeyword(getKeywordByName(keyword, known_vars));
            }

            return res;
        }

    private:
        SentinelKeyword start;
    };
};

KeywordComp::KeywordComp() : Component("KeywordComp"), pimpl(make_unique<KeywordComp::Impl>()) {}

KeywordComp::~KeywordComp() {}

string I_KeywordsRule::keywords_tag = "keywords_rule_tag";
