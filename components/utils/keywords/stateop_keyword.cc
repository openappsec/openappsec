#include "single_keyword.h"
#include "table_opaque.h"
#include "debug.h"
#include "flags.h"

#include <map>
#include <strings.h>

#include "cereal/types/set.hpp"

using namespace std;

USE_DEBUG_FLAG(D_KEYWORD);

class StateopKeyword : public SingleKeyword
{
public:
    explicit StateopKeyword(const vector<KeywordAttr> &attr, VariablesMapping &vars);
    MatchStatus isMatch(const I_KeywordRuntimeState* prev) const override;

private:
    enum class Operation { ISSET, SET, UNSET, COUNT };
    using OpFlags = Flags<Operation>;

    void
    setState(const KeywordAttr &attr, const VariablesMapping &)
    {
        auto &var_name_param = attr.getParams();

        if (var_name_param.size() != 2) {
            throw KeywordError("More than one element in the state name in the 'stateop' keyword");
        }

        var_name = var_name_param[1];
    }

    void
    setTesting(const KeywordAttr &, const VariablesMapping &)
    {
        if (!mode.empty()) throw KeywordError("Redefining 'stateop' keyword operation");
        mode.setFlag(Operation::ISSET);
    }

    void
    setSetting(const KeywordAttr &, const VariablesMapping &)
    {
        if (!mode.empty()) throw KeywordError("Redefining 'stateop' keyword operation");
        mode.setFlag(Operation::SET);
    }

    void
    setUnsetting(const KeywordAttr &, const VariablesMapping &)
    {
        if (!mode.empty()) throw KeywordError("Redefining 'stateop' keyword operation");
        mode.setFlag(Operation::UNSET);
    }

    string  var_name;
    OpFlags mode;

    static const map<string, void(StateopKeyword::*)(const KeywordAttr &, const VariablesMapping &)> setops;
};

const map<string, void(StateopKeyword::*)(const KeywordAttr &, const VariablesMapping &)> StateopKeyword::setops = {
    { "isset", &StateopKeyword::setTesting   },
    { "set",   &StateopKeyword::setSetting   },
    { "unset", &StateopKeyword::setUnsetting },
    { "state", &StateopKeyword::setState     }
};

StateopKeyword::StateopKeyword(const vector<KeywordAttr> &attrs, VariablesMapping &vars)
{
    if (attrs.size() != 2) throw KeywordError("Invalid number of attributes in the 'stateop' keyword");
    
    for (uint i = 0; i < attrs.size(); i++) {
        auto curr = setops.find(attrs[i].getAttrName());
        if (curr == setops.end()) {
            throw KeywordError("Unknown attribute '" + attrs[i].getAttrName() + "' in the 'stateop' keyword");
        }
        auto set_func = curr->second;
        (this->*set_func)(attrs[i], vars);
    }

    if (var_name == "" || mode.empty()) {
        throw KeywordError("Bad 'stateop' attribute configuration");
    }
}

class KeywordStateop : public TableOpaqueSerialize<KeywordStateop>
{
public:
    KeywordStateop() : TableOpaqueSerialize<KeywordStateop>(this) {}

    bool hasVariable(const string &state) { return states.find(state) != states.end(); }
    void addVariable(const string &state) { states.insert(state); }
    void removeVariable(const string &state) { states.erase(state); }

    // LCOV_EXCL_START - sync functions, can only be tested once the sync module exists
    template <typename T>
    void
    serialize(T &ar, uint32_t)
    {
        ar(states);
    }

    static std::string name() { return "KeywordStateop"; }
    static std::unique_ptr<TableOpaqueBase> prototype() { return std::make_unique<KeywordStateop>(); }
    static uint currVer() { return 0; }
    static uint minVer() { return 0; }
    // LCOV_EXCL_STOP

private:
    set<string> states;
};

MatchStatus
StateopKeyword::isMatch(const I_KeywordRuntimeState *prev) const
{
    auto table = Singleton::Consume<I_Table>::by<KeywordComp>();

    if (mode.isSet(Operation::ISSET)) {
        if (!table->hasState<KeywordStateop>()) return MatchStatus::NoMatchFinal;
        auto &state = table->getState<KeywordStateop>();
        if (state.hasVariable(var_name)) return runNext(prev);
        else return MatchStatus::NoMatchFinal;
    } else if (mode.isSet(Operation::SET)) {
        if (!table->hasState<KeywordStateop>()) table->createState<KeywordStateop>();
        table->getState<KeywordStateop>().addVariable(var_name);
        return runNext(prev);
    } else if (mode.isSet(Operation::UNSET)) {
        if (table->hasState<KeywordStateop>()) table->getState<KeywordStateop>().removeVariable(var_name);
        return runNext(prev);
    } else {
        dbgAssert(false) << "Impossible 'stateop' keyword without operation";
    }

    // If there was no matches and the keyword is effected by other keywords, then we know that the rule won't match
    return MatchStatus::NoMatchFinal;
}

unique_ptr<SingleKeyword>
genStateopKeyword(const vector<KeywordAttr> &attr, VariablesMapping &known_vars)
{
    return make_unique<StateopKeyword>(attr, known_vars);
}
