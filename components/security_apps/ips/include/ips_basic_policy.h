#ifndef __IPS_BASIC_POLICY_H__
#define __IPS_BASIC_POLICY_H__

#include <cereal/archives/json.hpp>
#include <string>
#include <vector>
#include "ips_enums.h"
#include "debug.h"
#include "maybe_res.h"
#include "ips_signatures.h"

class RuleSelector
{
public:
    class Rule
    {
    public:
        void serialize(cereal::JSONInputArchive &ar);

        bool isSignaturedMatched(const IPSSignatureSubTypes::CompleteSignature &signature) const;
        const IPSSignatureSubTypes::SignatureAction & getAction() const { return action; };
        void readAction(cereal::JSONInputArchive &ar, const std::string &action_type);
        void print(std::ostream &os) const;

    private:
        void readPerformanceImpact(cereal::JSONInputArchive &ar);
        void readSeverityLevel(cereal::JSONInputArchive &ar);
        void readConfidenceLevel(cereal::JSONInputArchive &ar);
        void readServerProtections(cereal::JSONInputArchive &ar);
        void readClientProtections(cereal::JSONInputArchive &ar);
        void readProtectionsFromYear(cereal::JSONInputArchive &ar);
        void readProtectionTags(cereal::JSONInputArchive &ar);
        void readProtectionIds(cereal::JSONInputArchive &ar);

        IPSSignatureSubTypes::SignatureAction action = IPSSignatureSubTypes::SignatureAction::IGNORE;
        Maybe<IPSSignatureSubTypes::IPSLevel> performance_impact = genError("undefined");
        Maybe<IPSSignatureSubTypes::IPSLevel> severity_level = genError("undefined");
        Maybe<IPSSignatureSubTypes::IPSLevel> confidence_level = genError("undefined");
        Maybe<bool> server_protections = genError("undefined");
        Maybe<bool> client_protections = genError("undefined");
        Maybe<int> protections_from_year = genError("undefined");
        Maybe<std::vector<std::string>> protection_tags = genError("undefined");
        Maybe<std::vector<std::string>> protection_ids = genError("undefined");
    };

public:
    std::vector<IPSSignatureSubTypes::SignatureAndAction> selectSignatures() const;
    void print(std::ostream &os) const;
    void load(cereal::JSONInputArchive &ar);

private:
    void readRules(cereal::JSONInputArchive &ar);
    void readDefaultAction(cereal::JSONInputArchive &ar);

    std::vector<Rule> rules;
};

#endif // __IPS_BASIC_POLICY_H__
