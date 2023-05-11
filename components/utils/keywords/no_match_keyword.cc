#include "single_keyword.h"
#include "table_opaque.h"
#include "debug.h"

#include <map>
#include <strings.h>

#include "cereal/types/set.hpp"

using namespace std;

USE_DEBUG_FLAG(D_KEYWORD);

class NoMatchKeyword : public SingleKeyword
{
public:
    explicit NoMatchKeyword(const vector<KeywordAttr> &attr, VariablesMapping &)
    {
        if (!attr.empty()) throw KeywordError("The 'no_match' keyword doesn't take attributes");
    }

    MatchStatus isMatch(const I_KeywordRuntimeState *) const override { return MatchStatus::NoMatchFinal; }
};

unique_ptr<SingleKeyword>
genNoMatchKeyword(const vector<KeywordAttr> &attr, VariablesMapping &known_vars)
{
    return make_unique<NoMatchKeyword>(attr, known_vars);
}
