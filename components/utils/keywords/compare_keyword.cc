#include "single_keyword.h"
#include "output.h"
#include "debug.h"

#include <map>
#include <strings.h>
#include "limits.h"

using namespace std;

USE_DEBUG_FLAG(D_KEYWORD);

class CompareKeyword : public SingleKeyword
{
public:
    explicit CompareKeyword(const vector<KeywordAttr> &attr, const VariablesMapping &vars);
    MatchStatus isMatch(const I_KeywordRuntimeState* prev) const override;

private:
    bool
    isConstant() const
    {
        return first_val.isConstant() && second_val.isConstant();
    }

    NumericAttr    first_val;
    NumericAttr    second_val;
    ComparisonAttr comparison;
};

CompareKeyword::CompareKeyword(const vector<KeywordAttr> &attrs, const VariablesMapping &vars)
{
    if (attrs.size() != 3) throw KeywordError("Invalid number of attributes in the 'compare' keyword");
    
    auto &first_val_param = attrs[0].getParams();
    if (first_val_param.size() != 1) {
        throw KeywordError("More than one element in the first value in the 'compare' keyword");
    }
    first_val.setAttr("first_val", first_val_param[0], vars, "compare");

    auto &comparison_param = attrs[1].getParams();
    if (comparison_param.size() != 1) {
        throw KeywordError("More than one element in the comparison operator in the 'compare' keyword");
    }
    comparison.setAttr(comparison_param[0], "compare");

    auto &second_val_param = attrs[2].getParams();
    if (second_val_param.size() != 1) {
        throw KeywordError("More than one element in the second value in the 'compare' keyword");
    }
    second_val.setAttr("second_val", second_val_param[0], vars, "compare");
}

MatchStatus
CompareKeyword::isMatch(const I_KeywordRuntimeState *prev) const
{
    int keyword_first_val = first_val.evalAttr(prev);
    int keyword_second_val = second_val.evalAttr(prev);

    if (comparison(keyword_first_val, keyword_second_val)) return runNext(prev);

    // If there was no matches and the keyword is effected by other keywords, then we know that the rule won't match
    return isConstant() ? MatchStatus::NoMatchFinal : MatchStatus::NoMatch;
}

unique_ptr<SingleKeyword>
genCompareKeyword(const vector<KeywordAttr> &attr, VariablesMapping &known_vars)
{
    return make_unique<CompareKeyword>(attr, known_vars);
}
