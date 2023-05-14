#ifndef __RULE_DETECTION_H__
#define __RULE_DETECTION_H__

#include "simple_protection.h"
#include "compound_protection.h"

class RuleDetection
{
public:
    RuleDetection(const std::string &_sig_name) : sig_name(_sig_name) {}

    template <typename T>
    void serialize(T &ar)
    {
        std::string type;
        ar(cereal::make_nvp("type", type));

        if (type == "simple") rule = SimpleProtection::get(sig_name, ar);
        else if (type == "compound") rule = CompoundProtection::get(sig_name, ar);
        else reportConfigurationError("Unknown rule type: " + type);
    };

    std::shared_ptr<IPSSignatureSubTypes::BaseSignature> getRule() { return rule; }

private:
    std::shared_ptr<IPSSignatureSubTypes::BaseSignature> rule;
    std::string sig_name;
};

#endif // __RULE_DETECTION_H__
