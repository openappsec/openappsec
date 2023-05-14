#ifndef __SIMPLE_PROTECTION_H__
#define __SIMPLE_PROTECTION_H__

#include <memory>

#include "ips_signatures.h"
#include "i_keywords_rule.h"

class SimpleProtection
{
    class Impl : public IPSSignatureSubTypes::BaseSignature
    {
    public:
        Impl(
            const std::string &sig_name,
            const std::string &ssm,
            const std::string &keyword,
            const std::vector<std::string> &context
        );

        const std::string & getSigId() const override { return sig_name; }
        MatchType getMatch(const std::set<PMPattern> &matched) const override;
        std::set<PMPattern> patternsInSignature() const override;
        const std::vector<std::string> & getContext() const override { return context; }

    private:
        std::string sig_name;
        std::vector<std::string> context;
        std::shared_ptr<I_KeywordsRule::VirtualRule> rule;
        PMPattern pattern;
    };

public:
    template <typename Archive>
    static std::shared_ptr<IPSSignatureSubTypes::BaseSignature> get(const std::string &sig_name, Archive &ar)
    {
        std::string ssm, keyword;
        std::vector<std::string> context;

        ar(
            cereal::make_nvp("SSM",      ssm),
            cereal::make_nvp("keywords", keyword),
            cereal::make_nvp("context",  context)
        );

        return std::make_shared<Impl>(sig_name, ssm, keyword, context);
    }
};
#endif // __SIMPLE_PROTECTION_H__
