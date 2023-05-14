#include "snort_basic_policy.h"
#include <cereal/types/string.hpp>
#include <cereal/types/vector.hpp>
#include <ostream>
#include <stdexcept>
#include <iomanip>
#include "ips_signatures.h"
#include "helper.h"
#include "config.h"
#include "common.h"

USE_DEBUG_FLAG(D_IPS);

using namespace std;

void
SnortRuleSelector::load(cereal::JSONInputArchive &ar)
{
    string mode;
    ar(cereal::make_nvp("mode", mode), cereal::make_nvp("files", file_names));

    if (mode == "Inactive") action = IPSSignatureSubTypes::SignatureAction::IGNORE;
    else if (mode == "Disabled") action = IPSSignatureSubTypes::SignatureAction::IGNORE;
    else if (mode == "Detect") action = IPSSignatureSubTypes::SignatureAction::DETECT;
    else if (mode == "Prevent") action = IPSSignatureSubTypes::SignatureAction::PREVENT;
    else reportConfigurationError("invalid action value " + mode);
}

vector<IPSSignatureSubTypes::SignatureAndAction>
SnortRuleSelector::selectSignatures() const
{
    vector<IPSSignatureSubTypes::SignatureAndAction> res;

    if (action == IPSSignatureSubTypes::SignatureAction::IGNORE) return res;

    auto signatures = getResource<SnortSignaturesResource>("IPSSnortSigs", "protections");
    if (!signatures.ok()) return res;

    for (auto &file : file_names) {
        for (auto &signature : (*signatures).getSignatures(file)) {
            res.emplace_back(signature, action);
        }
    }
    return res;
}
