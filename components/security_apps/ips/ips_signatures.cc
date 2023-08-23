#include "ips_signatures.h"

#include <sstream>
#include <algorithm>

#include "ips_comp.h"
#include "ips_basic_policy.h"
#include "snort_basic_policy.h"
#include "generic_rulebase/parameters_config.h"
#include "generic_rulebase/triggers_config.h"
#include "rule_detection.h"
#include "helper.h"
#include "config.h"
#include "context.h"
#include "ips_entry.h"
#include "ips_metric.h"
#include "ips_common_types.h"

USE_DEBUG_FLAG(D_IPS);

using namespace IPSSignatureSubTypes;
using namespace ReportIS;
using namespace std;
using MatchType = BaseSignature::MatchType;

static const LogTriggerConf default_triger;

static const map<IPSLevel, Severity> severities = {
    { IPSLevel::CRITICAL,   Severity::CRITICAL },
    { IPSLevel::HIGH,        Severity::HIGH },
    { IPSLevel::MEDIUM_HIGH, Severity::HIGH },
    { IPSLevel::MEDIUM,      Severity::MEDIUM },
    { IPSLevel::MEDIUM_LOW,  Severity::LOW },
    { IPSLevel::LOW,         Severity::LOW },
    { IPSLevel::VERY_LOW,    Severity::INFO }
};

static const map<string, IPSLevel> levels = {
    { "Critical",    IPSLevel::CRITICAL },
    { "High",        IPSLevel::HIGH },
    { "Medium High", IPSLevel::MEDIUM_HIGH },
    { "Medium",      IPSLevel::MEDIUM },
    { "Medium Low",  IPSLevel::MEDIUM_LOW },
    { "Low",         IPSLevel::LOW },
    { "Very Low",    IPSLevel::VERY_LOW }
};

static IPSLevel
getLevel(const string &level_string, const string &attr_name)
{
    auto index = levels.find(level_string);
    if (index == levels.end()) {
        reportConfigurationError(
            "Unknown level: '" + level_string + "' in attribute " + attr_name
        );
    }
    return index->second;
}

void
IPSSignatureMetaData::setIndicators(const string &_source, const string &_version)
{
    source = _source;
    version = _version;
}

string
IPSSignatureMetaData::getSeverityString() const
{
    switch (severity) {
        case IPSLevel::VERY_LOW:
            return "Very Low";
        case IPSLevel::LOW:
            return "Low";
        case IPSLevel::MEDIUM_LOW:
            return "Medium Low";
        case IPSLevel::MEDIUM:
            return "Medium";
        case IPSLevel::MEDIUM_HIGH:
            return "Medium High";
        case IPSLevel::HIGH:
            return "High";
        case IPSLevel::CRITICAL:
            return "Critical";
    }

    dbgAssert(false) << "Illegal severity value: " << static_cast<uint>(severity);
    return "Critical";
}

string
IPSSignatureMetaData::getConfidenceString() const
{
    if (confidence <= IPSLevel::LOW) return "Low";
    if (confidence >= IPSLevel::HIGH) return "High";
    return "Medium";
}

string
IPSSignatureMetaData::getPerformanceString() const
{
    switch (performance) {
        case IPSLevel::VERY_LOW:
            return "Very Low";
        case IPSLevel::LOW:
            return "Low";
        case IPSLevel::MEDIUM_LOW:
            return "Medium Low";
        case IPSLevel::MEDIUM:
            return "Medium";
        case IPSLevel::MEDIUM_HIGH:
            return "Medium High";
        case IPSLevel::HIGH:
            return "High";
        case IPSLevel::CRITICAL:
            return "Critical";
    }

    dbgAssert(false) << "Illegal performance value: " << static_cast<uint>(performance);
    return "Critical";
}

void
IPSSignatureMetaData::load(cereal::JSONInputArchive &ar)
{
    string severity_string, confidence_string, performance_string;
    ar(
        cereal::make_nvp("maintrainId",       protection_id),
        cereal::make_nvp("protectionName",    sig_name),
        cereal::make_nvp("severity",          severity_string),
        cereal::make_nvp("lastUpdate",        update),
        cereal::make_nvp("confidenceLevel",   confidence_string),
        cereal::make_nvp("performanceImpact", performance_string),
        cereal::make_nvp("cveList",           cve_list),
        cereal::make_nvp("tags",              tag_list)
    );

    severity = getLevel(severity_string, "severity");
    confidence = getLevel(confidence_string, "confidence");
    performance = getLevel(performance_string, "performance");

    try {
        ar(cereal::make_nvp("logAttackName", event_log));
    } catch (cereal::Exception &) {
        event_log = "IPS Signature '" + sig_name + "' Found";
        ar.setNextName(nullptr);
    }

    try {
        ar(cereal::make_nvp("silent", is_silent));
    } catch (cereal::Exception &) {
        ar.setNextName(nullptr);
    }
}

static const size_t protection_type_pos = strlen("Protection_Type_");
static const size_t vul_type_pos = strlen("Vul_Type_");

string
IPSSignatureSubTypes::IPSSignatureMetaData::getIncidentType() const
{
    for (auto &tag : tag_list) {
        if (tag.compare(0, vul_type_pos, "Vul_Type_") == 0) {
            auto incident_type = tag.substr(vul_type_pos);
            replace(incident_type.begin(), incident_type.end(), '_', ' ');
            if (incident_type == "Vulnerability") return "Vulnerability exploit attempt";
            return incident_type;
        }
    }

    for (auto &tag : tag_list) {
        if (tag.compare(0, protection_type_pos, "Protection_Type_") == 0) {
            auto incident_type = tag.substr(protection_type_pos);
            replace(incident_type.begin(), incident_type.end(), '_', ' ');
            if (incident_type == "Vulnerability") return "Vulnerability exploit attempt";
            return incident_type;
        }
    }

    return "";
}

static const size_t year_start_pos = strlen("Threat_Year_");

bool
IPSSignatureMetaData::isYearAtLeast(const Maybe<int> &year) const
{
    if (!year.ok()) return true;
    auto protection_year = getYear();
    if (!protection_year.ok()) return true;

    return *protection_year >= *year;
}

Maybe<int>
IPSSignatureMetaData::getYear() const
{
    for (auto &tag : tag_list) {
        if (tag.compare(0, year_start_pos, "Threat_Year_") == 0) {
            if (tag.size() != year_start_pos + 4) {
                dbgWarning(D_IPS) << "Threat year tag (" << tag << ") doen't meet expected format";
                return false;
            }
            int protection_year =
                (tag[year_start_pos] - '0') * 1000 +
                (tag[year_start_pos + 1] - '0') * 100 +
                (tag[year_start_pos + 2] - '0') * 10 +
                (tag[year_start_pos + 3] - '0');
            return protection_year;
        }
    }

    return genError("Year not found");
}

void
CompleteSignature::load(cereal::JSONInputArchive &ar)
{
    ar(cereal::make_nvp("protectionMetadata", metadata));
    RuleDetection rule_detection(metadata.getName());
    ar(cereal::make_nvp("detectionRules", rule_detection));
    rule = rule_detection.getRule();
}

MatchType
CompleteSignature::getMatch(const set<PMPattern> &matches) const
{
    return rule->getMatch(matches);
}

set<PMPattern>
CompleteSignature::patternsInSignature() const
{
    return rule->patternsInSignature();
}

void
CompleteSignature::setIndicators(const string &source, const string &version)
{
    metadata.setIndicators(source, version);
}

template <typename ErrorType>
static string
getSubString(const Maybe<Buffer, ErrorType> &buf, uint max_size = 0)
{
    if (max_size == 0) max_size = buf.unpack().size();
    const Buffer &real_buf = buf.unpack();
    auto res = real_buf.size() <= max_size ? real_buf : real_buf.getSubBuffer(0, max_size);
    return static_cast<string>(res);
}

ActionResults
SignatureAndAction::getAction(const IPSEntry &ips_state) const
{
    dbgDebug(D_IPS) << "matching exceptions";

    unordered_map<string, set<string>> exceptions_dict;
    exceptions_dict["protectionName"].insert(signature->getName());

    ScopedContext ctx;
    ctx.registerValue<string>("protectionName", signature->getName());

    auto env = Singleton::Consume<I_Environment>::by<IPSComp>();
    auto host = env->get<string>(HttpTransactionData::host_name_ctx);
    if (host.ok()) exceptions_dict["hostName"].insert(*host);

    auto client_ip = env->get<IPAddr>(HttpTransactionData::client_ip_ctx);
    if (client_ip.ok()) {
        stringstream client_ip_str;
        client_ip_str << client_ip.unpack();
        exceptions_dict["sourceIP"].insert(client_ip_str.str());
    }

    auto path = ips_state.getBuffer("HTTP_PATH_DECODED");
    if (path.size()) exceptions_dict["url"].insert(static_cast<string>(path));

    auto env_source_identifier = env->get<string>(HttpTransactionData::source_identifier);
    if (env_source_identifier.ok()) {
        exceptions_dict["sourceIdentifier"].insert(*env_source_identifier);
    }

    I_GenericRulebase *i_rulebase = Singleton::Consume<I_GenericRulebase>::by<IPSComp>();
    auto behaviors = i_rulebase->getBehavior(exceptions_dict);

    set<BehaviorValue> override_actions;
    vector<string> override_ids;
    for (auto const &behavior : behaviors) {
        if (behavior.getKey() == BehaviorKey::ACTION) {
            override_actions.insert(behavior.getValue());
            const string &override_id = behavior.getId();
            if (!override_id.empty()) override_ids.push_back(override_id);
        }
    }

    if (override_actions.find(BehaviorValue::IGNORE) != override_actions.end()) {
        dbgDebug(D_IPS) << "Exception matched - action=Detect";
        return make_tuple(IPSSignatureSubTypes::SignatureAction::DETECT, string("Skip"), override_ids);
    }
    if (override_actions.find(BehaviorValue::ACCEPT) != override_actions.end()) {
        dbgDebug(D_IPS) << "Exception matched - action=Detect";
        return make_tuple(IPSSignatureSubTypes::SignatureAction::DETECT, string("Accept"), override_ids);
    }
    if (override_actions.find(BehaviorValue::REJECT) != override_actions.end()) {
        dbgDebug(D_IPS) << "Exception matched - action=Prevent";
        return make_tuple(IPSSignatureSubTypes::SignatureAction::PREVENT, string("Drop"), override_ids);
    }
    return make_tuple(action, string("None"), override_ids);
}

static const auto req_body = LogTriggerConf::WebLogFields::webBody;
static const auto headers = LogTriggerConf::WebLogFields::webHeaders;
static const auto url_path = LogTriggerConf::WebLogFields::webUrlPath;
static const auto url_query = LogTriggerConf::WebLogFields::webUrlQuery;
static const auto res_body = LogTriggerConf::WebLogFields::responseBody;
static const auto res_code = LogTriggerConf::WebLogFields::responseCode;

bool
SignatureAndAction::matchSilent(const Buffer &sample) const
{
    dbgTrace(D_IPS) << "Matched silent signature";
    MatchEvent(signature, IPSSignatureSubTypes::SignatureAction::IGNORE).notify();

    ScopedContext ctx;
    ctx.registerValue("Audience Team", AudienceTeam::SIGNATURE_DEVELOPERS);

    LogGen log(
        "Silent Protection",
        Audience::INTERNAL,
        Severity::INFO,
        Priority::MEDIUM,
        LogField("practiceType", "Threat Prevention"),
        Tags::IPS,
        StreamType::JSON_FOG
    );
    log << LogField("signatureVersion", signature->getUpdateVersion())
        << LogField("protectionId", signature->getName())
        << LogField("indicatorsSource", signature->getSource())
        << LogField("indicatorsVersion", signature->getFeedVersion())
        << LogField("incidentType", signature->getIncidentType())
        << LogField("matchedSample", static_cast<string>(sample), LogFieldOption::XORANDB64);

    auto env = Singleton::Consume<I_Environment>::by<IPSComp>();
    auto table = Singleton::Consume<I_Table>::by<IPSComp>();
    auto &ips_state = table->getState<IPSEntry>();

    auto method = env->get<string>(HttpTransactionData::method_ctx);
    if (method.ok()) log << LogField("httpMethod", method.unpack());

    auto path  = env->get<Buffer>("HTTP_PATH_DECODED");
    if (path.ok()) log << LogField("httpUriPath", getSubString(path, 1536), LogFieldOption::XORANDB64);

    auto req_header = ips_state.getTransactionData(IPSCommonTypes::requests_header_for_log);
    if (req_header.ok()) log << LogField("httpRequestHeaders", getSubString(req_header), LogFieldOption::XORANDB64);

    auto res_code = env->get<Buffer>("HTTP_RESPONSE_CODE");
    if (res_code.ok()) log << LogField("httpResponseCode", static_cast<string>(res_code.unpack()));

    auto req_body = env->get<Buffer>("HTTP_REQUEST_BODY");
    auto res_body = env->get<Buffer>("HTTP_RESPONSE_BODY");
    uint req_size = req_body.ok() ? req_body.unpack().size() : 0;
    uint res_size = res_body.ok() ? res_body.unpack().size() : 0;
    if (req_size + res_size > 1536) {
        if (req_size + 500 > 1536) {
            res_size = std::min(500u, res_size);
            req_size = 1536 - res_size;
        } else {
            res_size = 1536 - req_size;
        }
    }
    if (req_size) log << LogField("httpRequestBody", getSubString(req_body, req_size), LogFieldOption::XORANDB64);
    if (res_size) log << LogField("httpResponseBody", getSubString(res_body, res_size), LogFieldOption::XORANDB64);

    return false;
}

bool
SignatureAndAction::isMatchedPrevent(const Buffer &context_buffer, const set<PMPattern> &pattern) const
{
    if (signature->getMatch(pattern) != MatchType::MATCH) {
        dbgTrace(D_IPS) << "Signature doesn't match";
        return false;
    }

    if (signature->isSilent()) return matchSilent(context_buffer);

    auto table = Singleton::Consume<I_Table>::by<IPSComp>();
    auto &ips_state = table->getState<IPSEntry>();

    auto override_action = getAction(ips_state);

    MatchEvent(signature, get<0>(override_action)).notify();

    if (get<0>(override_action) == IPSSignatureSubTypes::SignatureAction::IGNORE) {
        dbgDebug(D_IPS) << "Ignored signature";
        return false;
    }

    dbgDebug(D_IPS) << "Signature matched - sending log";

    auto &trigger = getConfigurationWithDefault(default_triger, "rulebase", "log");
    bool is_prevent = get<0>(override_action) == IPSSignatureSubTypes::SignatureAction::PREVENT;

    auto severity = signature->getSeverity() < IPSLevel::HIGH ? Severity::HIGH : Severity::CRITICAL;
    if (get<0>(override_action) == IPSSignatureSubTypes::SignatureAction::DETECT) severity = Severity::INFO;

    LogGen log = trigger(
        "Web Request",
        LogTriggerConf::SecurityType::ThreatPrevention,
        severity,
        Priority::HIGH,
        is_prevent,
        LogField("practiceType", "Threat Prevention"),
        Tags::IPS
    );
    log
        << LogField("matchedSignatureConfidence", signature->getConfidenceString())
        << LogField("matchedSignaturePerformance", signature->getPerformanceString())
        << LogField("matchedSignatureSeverity", signature->getSeverityString())
        << LogField("matchedSignatureCVE", makeSeparatedStr(signature->getCveList(), ", "))
        << LogField("signatureVersion", signature->getUpdateVersion())
        << LogField("protectionId", signature->getName())
        << LogField("indicatorsSource", signature->getSource())
        << LogField("indicatorsVersion", signature->getFeedVersion())
        << LogField("waapIncidentType", signature->getIncidentType());

    if (context_buffer.size() < 1024) {
        log << LogField("matchedSample", static_cast<string>(context_buffer), LogFieldOption::XORANDB64);
    } else {
        auto sample = context_buffer;
        sample.keepHead(1024);
        log << LogField("matchedSample", static_cast<string>(sample), LogFieldOption::XORANDB64);
    }

    auto year = signature->getYear();
    if (year.ok()) log << LogField("matchedSignatureYear", to_string(*year));

    auto env = Singleton::Consume<I_Environment>::by<IPSComp>();
    auto host = env->get<string>(HttpTransactionData::host_name_ctx);
    if (host.ok()) log << LogField("httpHostName", host.unpack());
    auto client_ip = env->get<IPAddr>(HttpTransactionData::client_ip_ctx);

    if (client_ip.ok()) {
        stringstream client_ip_str;
        client_ip_str << client_ip.unpack();
        log << LogField("sourceIP", client_ip_str.str());
    }

    auto proxy_ip = env->get<string>(HttpTransactionData::proxy_ip_ctx);
    if (proxy_ip.ok()) {
        log << LogField("proxyIP", static_cast<string>(proxy_ip.unpack()));
    }

    auto source_identifier = env->get<string>(HttpTransactionData::source_identifier);
    if (source_identifier.ok()) {
        log << LogField("httpSourceId", static_cast<string>(source_identifier.unpack()));
    }

    auto req_header = ips_state.getTransactionData(IPSCommonTypes::requests_header_for_log);
    if (req_header.ok() && trigger.isWebLogFieldActive(headers)) {
        log << LogField("httpRequestHeaders", static_cast<string>(req_header.unpack()), LogFieldOption::XORANDB64);
    }

    auto client_port = env->get<uint16_t>(HttpTransactionData::client_port_ctx);
    if (client_port.ok()) log << LogField("sourcePort", client_port.unpack());
    auto method = env->get<string>(HttpTransactionData::method_ctx);
    if (method.ok()) log << LogField("httpMethod", method.unpack());
    uint max_size = getConfigurationWithDefault<uint>(1536, "IPS", "Max Field Size");
    auto path  = env->get<Buffer>("HTTP_PATH_DECODED");
    if (path.ok() && trigger.isWebLogFieldActive(url_path)) {
        log << LogField("httpUriPath", getSubString(path, max_size), LogFieldOption::XORANDB64);
    }
    auto query = env->get<Buffer>("HTTP_QUERY_DECODED");
    if (query.ok() && trigger.isWebLogFieldActive(url_query)) {
        log << LogField("httpUriQuery", getSubString(query, max_size), LogFieldOption::XORANDB64);
    }

    auto res_code = env->get<Buffer>("HTTP_RESPONSE_CODE");
    if (res_code.ok() && trigger.isWebLogFieldActive(::res_code)) {
        log << LogField("httpResponseCode", static_cast<string>(res_code.unpack()));
    }

    auto req_body = env->get<Buffer>("HTTP_REQUEST_BODY");
    auto res_body = env->get<Buffer>("HTTP_RESPONSE_BODY");
    uint req_size = req_body.ok() && trigger.isWebLogFieldActive(::req_body) ? req_body.unpack().size() : 0;
    uint res_size = res_body.ok() && trigger.isWebLogFieldActive(::res_body) ? res_body.unpack().size() : 0;
    if (req_size + res_size > max_size) {
        if (req_size + 500 > max_size) {
            res_size = std::min(500u, res_size);
            req_size = max_size - res_size;
        } else {
            res_size = max_size - req_size;
        }
    }
    if (req_size) log << LogField("httpRequestBody", getSubString(req_body, req_size), LogFieldOption::XORANDB64);
    if (res_size) log << LogField("httpResponseBody", getSubString(res_body, res_size), LogFieldOption::XORANDB64);

    log << LogField("waapOverride", get<1>(override_action));

    if (!get<2>(override_action).empty()) log.addToOrigin(LogField("exceptionIdList", get<2>(override_action)));
    
    log << LogField("securityAction", is_prevent ? "Prevent" : "Detect");

    return is_prevent;
}

void
IPSSignaturesResource::load(cereal::JSONInputArchive &ar)
{
    if (!IPSHelper::hasDeobfuscation()) return;

    vector<CompleteSignature> sigs;
    cereal::load(ar, sigs);

    all_signatures.reserve(sigs.size());
    for (auto &sig : sigs) {
        all_signatures.emplace_back(make_shared<CompleteSignature>(move(sig)));
    }
}

class CompleteSignatureWrapper
{
public:
    void
    load(cereal::JSONInputArchive &ar)
    {
        try {
            sig.load(ar);
            is_loaded = true;
        } catch (const cereal::Exception &e) {
            ar.finishNode();
            reportError(e.what());
        } catch (const Config::ConfigException &e) {
            ar.finishNode();
            reportError(e.getError());
        }
    }

    bool isOk() const { return is_loaded; }
    void setIndicators(const string &source, const string &version) { sig.setIndicators(source, version); }
    shared_ptr<CompleteSignature> getPtr() { return make_shared<CompleteSignature>(move(sig)); }

private:
    void
    reportError(const string &err)
    {
        dbgError(D_IPS) << "Failed to load signature due to: " << err;

        if (sig.getName() != "") {
            string remediation =
                "Verify the validity of the '" +
                sig.getName() +
                "' signature.";

            LogGen(
                "Could not load a Snort signature from configured file",
                ReportIS::Level::ACTION,
                ReportIS::Audience::SECURITY,
                ReportIS::Severity::CRITICAL,
                ReportIS::Priority::URGENT,
                LogField("EventTopic", "Snort Signatures"),
                ReportIS::Tags::POLICY_INSTALLATION
            ) << LogField("EventRemediation", remediation);
        }
    }

    CompleteSignature sig;
    bool is_loaded = false;
};

void
SnortSignaturesResourceFile::load(cereal::JSONInputArchive &ar)
{
    string time;
    vector<CompleteSignatureWrapper> sigs;
    ar(
        cereal::make_nvp("modificationTime", time),
        cereal::make_nvp("name", name),
        cereal::make_nvp("protections", sigs)
    );

    all_signatures.reserve(sigs.size());
    for (auto &sig : sigs) {
        if (sig.isOk()) {
            sig.setIndicators(name, time);
            all_signatures.emplace_back(sig.getPtr());
        }
    }
}

void
SnortSignaturesResource::load(cereal::JSONInputArchive &ar)
{
    cereal::load(ar, files);
}

void
IPSSignaturesPerContext::addSignature(const IPSSignatureSubTypes::SignatureAndAction &sig)
{
    auto patterns = sig.patternsInSignature();

    if (patterns.empty()) {
        signatures_without_lss.push_back(sig);
        return;
    }

    for (auto &pat : patterns) {
        signatures_per_lss[pat].push_back(sig);
    }
}

void
IPSSignaturesPerContext::calcFirstTier(const string &ctx_name)
{
    std::set<PMPattern> patterns;
    for (const auto &lss_to_sig : signatures_per_lss) {
        patterns.emplace(lss_to_sig.first);
    }

    first_tier = Singleton::Consume<I_FirstTierAgg>::by<IPSSignaturesPerContext>()->getHook(ctx_name, patterns);
}

set<PMPattern>
IPSSignaturesPerContext::getFirstTierMatches(const Buffer &buffer) const
{
    return first_tier->ok() ? first_tier->scanBuf(buffer) : set<PMPattern>();
}

bool
IPSSignaturesPerContext::isMatchedPrevent(const Buffer &context_buffer) const
{
    auto first_tier_res = getFirstTierMatches(context_buffer);

    for (auto &pat : first_tier_res) {
        auto find = signatures_per_lss.find(pat);
        if (find == signatures_per_lss.end()) continue;
        for (auto &sig : find->second) {
            if (sig.isMatchedPrevent(context_buffer, first_tier_res)) return true;
        }
    }

    for (auto &sig : signatures_without_lss) {
        if (sig.isMatchedPrevent(context_buffer, first_tier_res)) return true;
    }

    return false;
}

void
IPSSignatures::load(cereal::JSONInputArchive &ar)
{
    ar(
        cereal::make_nvp("assetName", asset_name),
        cereal::make_nvp("practiceName", practice_name)
    );

    try {
        ar(cereal::make_nvp("assetId", asset_id));
    } catch (const cereal::Exception &e) {
        ar.setNextName(nullptr);
        asset_id = "";
    }

    try {
        ar(cereal::make_nvp("practiceId", practice_id));
    } catch (const cereal::Exception &e) {
        ar.setNextName(nullptr);
        practice_id = "";
    }

    try {
        ar(cereal::make_nvp("sourceIdentifier", source_id));
        for (auto &ch : source_id) {
            ch = tolower(ch);
        }
    } catch (const cereal::Exception &e) {
        ar.setNextName(nullptr);
        source_id = "";
    }

    RuleSelector ruleSelector;
    ruleSelector.load(ar);
    std::vector<IPSSignatureSubTypes::SignatureAndAction> signatures = ruleSelector.selectSignatures();

    if (signatures.empty()) {
        dbgDebug(D_IPS) << "[IPS] Could not find any match between rules and signatures.";
        return;
    }

    for (const auto &sig : signatures) {
        auto &sig_contexts = sig.getContext();
        for (auto &sig_context : sig_contexts) {
            signatures_per_context[sig_context].addSignature(sig);
        }
    }

    for (auto &sig_per_ctx : signatures_per_context) {
        sig_per_ctx.second.calcFirstTier(sig_per_ctx.first);
    }
}

bool
IPSSignatures::isMatchedPrevent(const string &context_name, const Buffer &context_buffer) const
{
    auto curr_sig = signatures_per_context.find(context_name);

    if (curr_sig == signatures_per_context.end()) {
        dbgDebug(D_IPS) << "[IPS] No signatures for " << context_name;
        return false;
    }

    auto &config = getConfiguration<IPSSignatures>("IPS", "IpsProtections");
    ScopedContext ctx;
    auto SOURCE = EnvKeyAttr::LogSection::SOURCE;
    if (config.ok()) {
        ctx.registerValue<string>("practiceName", (*config).getPractice(), SOURCE);
        ctx.registerValue<string>("practiceId", (*config).getPracticeId(), SOURCE);
    }
    ctx.registerValue<string>("practiceSubType", "Web IPS", SOURCE);
    auto is_matched = curr_sig->second.isMatchedPrevent(context_buffer);

    return is_matched;
}

bool
IPSSignatures::isEmpty(const std::string &context) const
{
    return signatures_per_context.find(context) == signatures_per_context.end();
}

void
SnortSignatures::load(cereal::JSONInputArchive &ar)
{
    ar(
        cereal::make_nvp("assetName", asset_name),
        cereal::make_nvp("practiceName", practice_name)
    );

    try {
        ar(cereal::make_nvp("assetId", asset_id));
    } catch (const cereal::Exception &e) {
        ar.setNextName(nullptr);
        asset_id = "";
    }

    try {
        ar(cereal::make_nvp("practiceId", practice_id));
    } catch (const cereal::Exception &e) {
        ar.setNextName(nullptr);
        practice_id = "";
    }

    try {
        ar(cereal::make_nvp("sourceIdentifier", source_id));
        for (auto &ch : source_id) {
            ch = tolower(ch);
        }
    } catch (const cereal::Exception &e) {
        ar.setNextName(nullptr);
        source_id = "";
    }

    SnortRuleSelector ruleSelector;
    ruleSelector.load(ar);
    std::vector<IPSSignatureSubTypes::SignatureAndAction> signatures = ruleSelector.selectSignatures();

    if (signatures.empty()) {
        dbgDebug(D_IPS) << "[Snort] Could not find any match between rules and signatures.";
        return;
    }

    for (const auto &sig : signatures) {
        auto &sig_contexts = sig.getContext();
        for (auto &sig_context : sig_contexts) {
            signatures_per_context[sig_context].addSignature(sig);
        }
    }

    for (auto &sig_per_ctx: signatures_per_context) {
        sig_per_ctx.second.calcFirstTier(sig_per_ctx.first);
    }
}

bool
SnortSignatures::isMatchedPrevent(const string &context_name, const Buffer &context_buffer) const
{
    auto curr_sig = signatures_per_context.find(context_name);

    if (curr_sig == signatures_per_context.end()) {
        dbgDebug(D_IPS) << "[Snort] No signatures for " << context_name;
        return false;
    }

    auto &config = getConfiguration<SnortSignatures>("IPSSnortSigs", "SnortProtections");
    ScopedContext ctx;
    auto SOURCE = EnvKeyAttr::LogSection::SOURCE;
    if (config.ok()) {
        ctx.registerValue<string>("assetName", (*config).getAsset(), SOURCE);
        ctx.registerValue<string>("assetId", (*config).getAssetId(), SOURCE);
        ctx.registerValue<string>("practiceName", (*config).getPractice(), SOURCE);
        ctx.registerValue<string>("practiceId", (*config).getPracticeId(), SOURCE);
    }
    ctx.registerValue<string>("practiceSubType", "Web Snort", SOURCE);
    auto is_matched = curr_sig->second.isMatchedPrevent(context_buffer);

    return is_matched;
}

bool
SnortSignatures::isEmpty(const std::string &context) const
{
    return signatures_per_context.find(context) == signatures_per_context.end();
}
