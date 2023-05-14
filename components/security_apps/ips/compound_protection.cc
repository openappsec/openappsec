#include "compound_protection.h"

#include <algorithm>

#include "rule_detection.h"
#include "ips_entry.h"
#include "ips_comp.h"
#include "debug.h"

using namespace std;
using MatchType = IPSSignatureSubTypes::BaseSignature::MatchType;

USE_DEBUG_FLAG(D_IPS);

CompoundProtection::Impl::Impl(const string &_sig_name, SignaturesVector &&sig_vec, Operation oper)
        :
    sig_name(_sig_name),
    sub_signatures(move(sig_vec)),
    operation(oper),
    table(Singleton::Consume<I_Table>::by<IPSComp>())
{
    for (const auto &sig : sub_signatures) {
        const auto &sub_sig_context = sig->getContext();
        for (auto &new_context : sub_sig_context) {
            bool is_new_context = true;
            for (auto &old_context : contexts) {
                if (new_context == old_context) {
                    is_new_context = false;
                    break;
                }
            }
            if (is_new_context) contexts.push_back(new_context);
        }
    }
}

MatchType
CompoundProtection::Impl::getMatch(const set<PMPattern> &matched) const
{
    switch (operation) {
        case Operation::OR: return getMatchOr(matched);
        case Operation::AND: return getMatchAnd(matched);
        case Operation::ORDERED_AND: return getMatchOrderedAnd(matched);
    }

    dbgAssert(false) << "Unknown compound operation: " << static_cast<uint>(operation);
    return MatchType::NO_MATCH;
}

set<PMPattern>
CompoundProtection::Impl::patternsInSignature() const
{
    set<PMPattern> res;

    for (auto &sig : sub_signatures) {
        const auto &sub_sig_patterns = sig->patternsInSignature();
        for (auto &pat : sub_sig_patterns) {
            res.insert(pat);
        }
    }

    return res;
}

MatchType
CompoundProtection::Impl::getMatchOr(const set<PMPattern> &matched) const
{
    MatchType res = MatchType::NO_MATCH;
    for (auto &sig : sub_signatures) {
        switch (getSubMatch(sig, matched)) {
            case MatchType::NO_MATCH: break;
            case MatchType::CACHE_MATCH: {
                res = MatchType::CACHE_MATCH;
                break;
            }
            case MatchType::MATCH: return MatchType::MATCH;
        }
    }
    return res;
}

MatchType
CompoundProtection::Impl::getMatchAnd(const set<PMPattern> &matched) const
{
    MatchType res = MatchType::CACHE_MATCH;
    for (auto &sig : sub_signatures) {
        switch (getSubMatch(sig, matched)) {
            case MatchType::NO_MATCH: {
                res = MatchType::NO_MATCH;
                break;
            }
            case MatchType::CACHE_MATCH: break;
            case MatchType::MATCH: {
                if (res == MatchType::CACHE_MATCH) res = MatchType::MATCH;
                break;
            }
        }
    }
    return res;
}

MatchType
CompoundProtection::Impl::getMatchOrderedAnd(const set<PMPattern> &matched) const
{
    MatchType res = MatchType::CACHE_MATCH;
    for (auto &sig : sub_signatures) {
        switch (getSubMatch(sig, matched)) {
            case MatchType::NO_MATCH: return MatchType::NO_MATCH;
            case MatchType::CACHE_MATCH: break;
            case MatchType::MATCH: {
                res = MatchType::MATCH;
                break;
            }
        }
    }
    return res;
}

static bool
isStringInVector(const Maybe<string, Context::Error> &str, const vector<string> &vec)
{
    if (!str.ok()) return false;
    return find(vec.begin(), vec.end(), *str) != vec.end();
}

MatchType
CompoundProtection::Impl::getSubMatch(
    const std::shared_ptr<IPSSignatureSubTypes::BaseSignature> &sub_sig,
    const set<PMPattern> &matched
) const
{
    if (isFlagSet(sub_sig->getSigId())) return MatchType::CACHE_MATCH;

    auto env = Singleton::Consume<I_Environment>::by<IPSComp>();
    auto curr_ctx = env->get<string>(I_KeywordsRule::getKeywordsRuleTag());
    if (!isStringInVector(curr_ctx, sub_sig->getContext())) return MatchType::NO_MATCH;

    auto res = sub_sig->getMatch(matched);
    if (res != MatchType::NO_MATCH) setFlag(sub_sig->getSigId());
    return res;
}

bool
CompoundProtection::Impl::isFlagSet(const std::string &id) const
{
    if (!table->hasState<IPSEntry>()) {
        dbgWarning(D_IPS) << "No entry was found, limited compound functionality";
        return false;
    }
    return table->getState<IPSEntry>().isFlagSet(id);
}

void
CompoundProtection::Impl::setFlag(const std::string &id) const
{
    if (!table->hasState<IPSEntry>()) {
        dbgWarning(D_IPS) << "No entry was found, limited compound functionality";
        return;
    }
    table->getState<IPSEntry>().setFlag(id);
}

class OperandsReader
{
public:
    OperandsReader(const string &sig_name) : base_sig_name(sig_name) {}

    void
    load(cereal::JSONInputArchive &ar)
    {
        cereal::size_type cereal_size;
        ar(cereal::make_size_tag(cereal_size));
        rules.resize(static_cast<size_t>(cereal_size));

        uint index = 0;
        for (auto &rule : rules) {
            stringstream ss;
            ss << base_sig_name << "##" << index;
            ++index;
            RuleDetection detection(ss.str());
            ar(detection);
            rule = detection.getRule();
        }
    }

    vector<shared_ptr<IPSSignatureSubTypes::BaseSignature>> && extrackRules() { return move(rules); }

private:
    string base_sig_name;
    vector<shared_ptr<IPSSignatureSubTypes::BaseSignature>> rules;
};

shared_ptr<IPSSignatureSubTypes::BaseSignature>
CompoundProtection::get(const string &sig_name, cereal::JSONInputArchive &ar)
{
    string operation;
    OperandsReader operands(sig_name);

    ar(
        cereal::make_nvp("operation", operation),
        cereal::make_nvp("operands", operands)
    );

    return make_shared<Impl>(sig_name, operands.extrackRules(), getOperation(operation));
}

CompoundProtection::Operation
CompoundProtection::getOperation(const string &operation)
{
    if (operation == "or") return Operation::OR;
    if (operation == "and") return Operation::AND;
    if (operation == "ordered_and") return Operation::ORDERED_AND;

    reportConfigurationError("Unknown compound operation: " + operation);
    return Operation::OR;
}
