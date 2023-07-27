#include "ips_basic_policy.h"
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
RuleSelector::load(cereal::JSONInputArchive &ar)
{
    readRules(ar);
    readDefaultAction(ar);
}

vector<IPSSignatureSubTypes::SignatureAndAction>
RuleSelector::selectSignatures() const
{
    vector<IPSSignatureSubTypes::SignatureAndAction> res;

    if (!IPSHelper::hasDeobfuscation()) return res;

    auto all_signatures = getResource<IPSSignaturesResource>("IPS", "protections");
    if (!all_signatures.ok()) return res;
    auto signatures_version = getResourceWithDefault<string>("", "IPS", "VersionId");

    for (auto &signature : (*all_signatures).getSignatures()) {
        for (auto &rule : rules) {
            if (rule.isSignaturedMatched(*signature)) {
                if (rule.getAction() != IPSSignatureSubTypes::SignatureAction::IGNORE) {
                    signature->setIndicators("Check Point", signatures_version);
                    res.emplace_back(signature, rule.getAction());
                }
                break;
            }
        }
    }

    return res;
}

void
RuleSelector::readRules(cereal::JSONInputArchive &ar)
{
    ar(cereal::make_nvp("rules", rules));
}

void
RuleSelector::readDefaultAction(cereal::JSONInputArchive &ar)
{
    Rule rule;
    rule.readAction(ar, "defaultAction");
    rules.push_back(rule);
}

void
RuleSelector::Rule::serialize(cereal::JSONInputArchive &ar)
{
    readAction(ar, "action");
    readPerformanceImpact(ar);
    readSeverityLevel(ar);
    readConfidenceLevel(ar);
    readServerProtections(ar);
    readClientProtections(ar);
    readProtectionsFromYear(ar);
    readProtectionTags(ar);
    readProtectionIds(ar);
}

bool
RuleSelector::Rule::isSignaturedMatched(const IPSSignatureSubTypes::CompleteSignature &signature) const
{
    if (confidence_level.ok() && signature.getConfidence() != confidence_level.unpack()) return false;
    if (severity_level.ok() && signature.getSeverity() < severity_level.unpack()) return false;
    if (performance_impact.ok() && signature.getPerformance() > performance_impact.unpack()) return false;
    if (!signature.isYearAtLeast(protections_from_year)) return false;

    return true;
}

static ostream &
operator<<(ostream &os, const RuleSelector::Rule & rule)
{
    rule.print(os);
    return os;
}

void
RuleSelector::Rule::print(ostream &os) const
{
    os << "[Rule] " << "action: " << static_cast<int>(action);
    if (performance_impact.ok()) {
        os << " performanceImpact: " << static_cast<int>(performance_impact.unpack());
    }
    if (severity_level.ok()) {
        os << " severityLevel: " << static_cast<int>(severity_level.unpack());
    }
    if (confidence_level.ok()) {
        os << " confidenceLevel: " << static_cast<int>(confidence_level.unpack());
    }
    if (server_protections.ok()) {
        os << boolalpha << " serverProtections: " << server_protections.unpack();
    }
    if (client_protections.ok()) {
        os << boolalpha << " clientProtections: " << client_protections.unpack();
    }
    if (protections_from_year.ok()) {
        os << " protectionsFromYear: " << protections_from_year.unpack();
    }
    if (protection_ids.ok()) {
        os << " protectionIds: " << makeSeparatedStr(protection_ids.unpack(), ", ");
    }
    if (protection_tags.ok()) {
        os << " protectionTags: " << makeSeparatedStr(protection_tags.unpack(), ", ");
    }
}

void
RuleSelector::Rule::readAction(cereal::JSONInputArchive &ar, const string &action_type)
{
    string str;
    ar(cereal::make_nvp(action_type, str));

    if (str == "Inactive") action = IPSSignatureSubTypes::SignatureAction::IGNORE;
    else if (str == "Detect") action = IPSSignatureSubTypes::SignatureAction::DETECT;
    else if (str == "Prevent") action = IPSSignatureSubTypes::SignatureAction::PREVENT;
    else reportConfigurationError("invalid action value " + str);
}

void
RuleSelector::Rule::readPerformanceImpact(cereal::JSONInputArchive &ar)
{
    try {
        string str;
        ar(cereal::make_nvp("performanceImpact", str));

        if (str == "Very low") performance_impact = IPSSignatureSubTypes::IPSLevel::VERY_LOW;
        else if (str == "Low or lower") performance_impact =  IPSSignatureSubTypes::IPSLevel::LOW;
        else if (str == "Medium or lower") performance_impact =  IPSSignatureSubTypes::IPSLevel::MEDIUM;
        else if (str == "High or lower") performance_impact =  IPSSignatureSubTypes::IPSLevel::HIGH;
        else reportConfigurationError("invalid performanceImpact value " + str);
    } catch (const cereal::Exception &e) {
        ar.setNextName(nullptr);
    }
}

void
RuleSelector::Rule::readSeverityLevel(cereal::JSONInputArchive &ar)
{
    try {
        string str;
        ar(cereal::make_nvp("severityLevel", str));

        if (str == "Critical") severity_level = IPSSignatureSubTypes::IPSLevel::CRITICAL;
        else if (str == "High or above") severity_level = IPSSignatureSubTypes::IPSLevel::HIGH;
        else if (str == "Medium or above") severity_level = IPSSignatureSubTypes::IPSLevel::MEDIUM;
        else if (str == "Low or above") severity_level = IPSSignatureSubTypes::IPSLevel::LOW;
        else reportConfigurationError("invalid severityLevel value " + str);
    } catch (const cereal::Exception &e) {
        ar.setNextName(nullptr);
    }
}

void
RuleSelector::Rule::readConfidenceLevel(cereal::JSONInputArchive &ar)
{
    try {
        string str;
        ar(cereal::make_nvp("confidenceLevel", str));

        if (str == "Low") confidence_level  = IPSSignatureSubTypes::IPSLevel::LOW;
        else if (str == "Medium") confidence_level = IPSSignatureSubTypes::IPSLevel::MEDIUM;
        else if (str == "High") confidence_level = IPSSignatureSubTypes::IPSLevel::HIGH;
        else reportConfigurationError("invalid confidenceLevel value " + str);
    } catch (const cereal::Exception &e) {
        ar.setNextName(nullptr);
    }
}

void
RuleSelector::Rule::readServerProtections(cereal::JSONInputArchive &ar)
{
    try {
        bool _server_protections;
        ar(cereal::make_nvp("serverProtections", _server_protections));
        server_protections = _server_protections;
    } catch (const cereal::Exception &e) {
        ar.setNextName(nullptr);
    }
}

void
RuleSelector::Rule::readClientProtections(cereal::JSONInputArchive &ar)
{
    try {
        bool _client_protections;
        ar(cereal::make_nvp("clientProtections", _client_protections));
        client_protections = _client_protections;
    } catch (const cereal::Exception &e) {
        ar.setNextName(nullptr);
    }
}

void
RuleSelector::Rule::readProtectionsFromYear(cereal::JSONInputArchive &ar)
{
    try {
        int year;
        ar(cereal::make_nvp("protectionsFromYear", year));
        if (year < 1999 || year > 2021) {
            reportConfigurationError("invalid protectionsFromYear value " + to_string(year));
        }
        else {
            protections_from_year = year;
        }
    } catch (const cereal::Exception &e) {
        ar.setNextName(nullptr);
    }
}

void
RuleSelector::Rule::readProtectionTags(cereal::JSONInputArchive &ar)
{
    try {
        vector<string> _protection_tags;
        ar(cereal::make_nvp("protectionTags", _protection_tags));
        protection_tags = _protection_tags;
    } catch (const cereal::Exception &e) {
        ar.setNextName(nullptr);
    }
}

void
RuleSelector::Rule::readProtectionIds(cereal::JSONInputArchive &ar)
{
    try {
        vector<string> _protection_ids;
        ar(cereal::make_nvp("protectionIds", _protection_ids));
        protection_ids = _protection_ids;
    } catch (const cereal::Exception &e) {
        ar.setNextName(nullptr);
    }
}

void
RuleSelector::print(ostream &os) const
{
    os << makeSeparatedStr(rules, ";");
}
