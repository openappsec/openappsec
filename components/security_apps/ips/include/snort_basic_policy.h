#ifndef __SNORT_BASIC_POLICY_H__
#define __SNORT_BASIC_POLICY_H__

#include <cereal/archives/json.hpp>
#include <vector>
#include <string>

#include "ips_enums.h"
#include "ips_signatures.h"

class SnortRuleSelector
{
public:
    std::vector<IPSSignatureSubTypes::SignatureAndAction> selectSignatures() const;
    void load(cereal::JSONInputArchive &ar);

private:
    IPSSignatureSubTypes::SignatureAction action = IPSSignatureSubTypes::SignatureAction::IGNORE;
    std::vector<std::string> file_names;
};

#endif // __SNORT_BASIC_POLICY_H__
