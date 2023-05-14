#ifndef __COMPOUND_PROTECTION_H__
#define __COMPOUND_PROTECTION_H__

#include <memory>

#include "ips_signatures.h"
#include "i_table.h"

class CompoundProtection
{
    enum class Operation { OR, AND, ORDERED_AND };
    using BaseSignature = IPSSignatureSubTypes::BaseSignature;

    class Impl : public IPSSignatureSubTypes::BaseSignature
    {
        using SignaturesVector = std::vector<std::shared_ptr<BaseSignature>>;

    public:
        Impl(const std::string &sig_name, SignaturesVector &&sig_vec, Operation oper);

        const std::string & getSigId() const override { return sig_name; }
        MatchType getMatch(const std::set<PMPattern> &matched) const override;
        std::set<PMPattern> patternsInSignature() const override;
        const std::vector<std::string> & getContext() const override { return contexts; }

    private:
        MatchType getMatchOr(const std::set<PMPattern> &matched) const;
        MatchType getMatchAnd(const std::set<PMPattern> &matched) const;
        MatchType getMatchOrderedAnd(const std::set<PMPattern> &matched) const;

        MatchType getSubMatch(const std::shared_ptr<BaseSignature> &sub_sig, const std::set<PMPattern> &matched) const;
        bool isFlagSet(const std::string &id) const;
        void setFlag(const std::string &id) const;

        std::string sig_name;
        SignaturesVector sub_signatures;
        std::vector<std::string> contexts;
        Operation operation;
        I_Table *table;
    };

public:
    static std::shared_ptr<BaseSignature> get(const std::string &sig_name, cereal::JSONInputArchive &ar);

private:
    static Operation getOperation(const std::string &operation);
};

#endif // __COMPOUND_PROTECTION_H__
