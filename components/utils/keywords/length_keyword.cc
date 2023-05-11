#include "single_keyword.h"
#include "output.h"
#include "debug.h"
#include "flags.h"

#include <map>
#include <strings.h>

using namespace std;

USE_DEBUG_FLAG(D_KEYWORD);

class LengthKeyword : public SingleKeyword
{
public:
    explicit LengthKeyword(const vector<KeywordAttr> &attr, VariablesMapping &vars);
    MatchStatus isMatch(const I_KeywordRuntimeState* prev) const override;

private:
    enum class Mode { EXACT, MIN, MAX, COUNT };
    using ModeFlags = Flags<Mode>;

    void
    setRelative(const KeywordAttr &attr, const VariablesMapping &)
    {
        is_relative.setAttr(attr, "length");
    }

    void
    setExact(const KeywordAttr &, const VariablesMapping &)
    {
        if (!mode.empty()) throw KeywordError("Redefining 'length' keyword operation");
        mode.setFlag(Mode::EXACT);
    }

    void
    setMin(const KeywordAttr &, const VariablesMapping &)
    {
        if (!mode.empty()) throw KeywordError("Redefining 'length' keyword operation");
        mode.setFlag(Mode::MIN);
    }


    void
    setMax(const KeywordAttr &, const VariablesMapping &)
    {
        if (!mode.empty()) throw KeywordError("Redefining 'length' keyword operation");
        mode.setFlag(Mode::MAX);
    }


    void
    setContext(const KeywordAttr &attr, const VariablesMapping &)
    {
        ctx.setAttr(attr, "length");
    }

    bool
    isConstant() const
    {
        return !is_relative && compare_size.isConstant();
    }

    BoolAttr    is_relative;
    ModeFlags   mode;
    CtxAttr     ctx;
    uint        var_id;
    NumericAttr compare_size;

    static const map<string, void(LengthKeyword::*)(const KeywordAttr &, const VariablesMapping &)> setops;
};

const map<string, void(LengthKeyword::*)(const KeywordAttr &, const VariablesMapping &)> LengthKeyword::setops = {
    { "relative",   &LengthKeyword::setRelative },
    { "exact",      &LengthKeyword::setExact    },
    { "min",        &LengthKeyword::setMin      },
    { "max",        &LengthKeyword::setMax      },
    { "part",       &LengthKeyword::setContext  }
};

LengthKeyword::LengthKeyword(const vector<KeywordAttr> &attrs, VariablesMapping &vars)
{
    if (attrs.size() == 0) throw KeywordError("Invalid number of attributes in the 'length' keyword");
    
    //parisng first attribute (Required) - variable name
    auto &var_name_param = attrs[0].getParams();

    if (var_name_param.size() != 1) {
        throw KeywordError("More than one element in the variable name in the 'length' keyword");
    }
    
    const string &string_var_name = var_name_param[0];

    if (string_var_name == "relative") {
        throw KeywordError("The 'relative' cannot be the variable name in the 'length' keyword");
    }
    if (string_var_name == "part") {
        throw KeywordError("The 'part' cannot be the variable name in the 'length' keyword");
    }
    if (string_var_name == "exact") {
        throw KeywordError("The 'exact' cannot be the variable name in the 'length' keyword");
    }
    if (string_var_name == "min") {
        throw KeywordError("The 'min' cannot be the variable name in the 'length' keyword");
    }
    if (string_var_name == "max") {
        throw KeywordError("The 'max' cannot be the variable name in the 'length' keyword");
    }

    //parsing the other optional attributes
    for (uint i = 1; i < attrs.size(); i++) {
        auto curr = setops.find(attrs[i].getAttrName());
        if (curr == setops.end()) {
            throw KeywordError("Unknown attribute '" + attrs[i].getAttrName() + "' in the 'length' keyword");
        }
        auto set_func = curr->second;
        (this->*set_func)(attrs[i], vars);
    }

    if (mode.empty()) {
        if (isdigit(string_var_name[0]) || string_var_name[0] == '-') {
            throw KeywordError("Malformed variable name in the 'length' keyword");
        }

        var_id = vars.addNewVariable(string_var_name);
    } else {
        compare_size.setAttr("length value", string_var_name, vars, "length", 10, true);
    }
}

MatchStatus
LengthKeyword::isMatch(const I_KeywordRuntimeState *prev) const
{
    auto part = Singleton::Consume<I_Environment>::by<KeywordComp>()->get<Buffer>(static_cast<string>(ctx));

    if (!part.ok()) return MatchStatus::NoMatchFinal;

    uint offset = is_relative ? prev->getOffset(ctx) : 0;
    uint size = (*part).size();

    if (offset <= size) {
        if (mode.isSet(Mode::EXACT)) {
            if (size - offset == static_cast<uint>(compare_size.evalAttr(prev))) return runNext(prev);
        } else if (mode.isSet(Mode::MIN)) {
            if (size - offset >= static_cast<uint>(compare_size.evalAttr(prev))) return runNext(prev);
        } else if (mode.isSet(Mode::MAX)) {
            if (size - offset <= static_cast<uint>(compare_size.evalAttr(prev))) return runNext(prev);
        } else {
            VariableRuntimeState new_length_var(prev, var_id, size-offset);
            return runNext(&new_length_var);
        }
    }

    // If there was no matches and the keyword is effected by other keywords, then we know that the rule won't match
    return isConstant() ? MatchStatus::NoMatchFinal : MatchStatus::NoMatch;
}

unique_ptr<SingleKeyword>
genLengthKeyword(const vector<KeywordAttr> &attr, VariablesMapping &known_vars)
{
    return make_unique<LengthKeyword>(attr, known_vars);
}
