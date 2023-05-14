#include "simple_protection.h"
#include "ips_comp.h"
#include "debug.h"
#include "helper.h"

using namespace std;

USE_DEBUG_FLAG(D_IPS);

SimpleProtection::Impl::Impl(
        const string &_sig_name,
        const string &ssm,
        const string &keyword,
        const vector<string> &_context
    )
        :
    sig_name(_sig_name),
    context(_context)
{
    string deobfuscated_keyword = IPSHelper::deobfuscateKeyword(keyword);
    if (deobfuscated_keyword != "") {
        auto compiled = Singleton::Consume<I_KeywordsRule>::by<IPSComp>()->genRule(deobfuscated_keyword);
        if (!compiled.ok()) {
            reportConfigurationError(
                "Failed to complie keywords '" + keyword + "' in signature " + sig_name + ": " + compiled.getErr()
            );
        }
        rule = compiled.unpackMove();
    }

    auto deobfuscated_ssm = IPSHelper::deobfuscateString(ssm);
    if (deobfuscated_ssm != "") {
        auto temp_pattern = PMHook::lineToPattern(deobfuscated_ssm);
        if (!temp_pattern.ok()) reportConfigurationError("Failed first tier pattern: " + temp_pattern.getErr());
        pattern = temp_pattern.unpackMove();
    }

    if (deobfuscated_keyword == "" && deobfuscated_ssm == "") {
        reportConfigurationError("Both Simple String and Keyword are empty in a simple protection " + sig_name);
    }
}

using MatchType = IPSSignatureSubTypes::BaseSignature::MatchType;

MatchType
SimpleProtection::Impl::getMatch(const set<PMPattern> &matches) const
{
    dbgTrace(D_IPS) << "Entering signature";
    if (!pattern.empty() && matches.find(pattern) == matches.end()) return MatchType::NO_MATCH;

    dbgTrace(D_IPS) << "Checking for rule";
    if (!rule) return MatchType::MATCH;

    dbgTrace(D_IPS) << "Running keywords";
    return rule->isMatch() ? MatchType::MATCH : MatchType::NO_MATCH;
}

set<PMPattern>
SimpleProtection::Impl::patternsInSignature() const
{
    set<PMPattern> res;
    if (!pattern.empty()) res.insert(pattern);
    return res;
}
