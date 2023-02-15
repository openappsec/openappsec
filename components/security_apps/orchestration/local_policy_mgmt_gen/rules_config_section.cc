#include "rules_config_section.h"

using namespace std;

USE_DEBUG_FLAG(D_K8S_POLICY);

// LCOV_EXCL_START Reason: no test exist
AssetUrlParser
AssetUrlParser::parse(const string &uri)
{
    AssetUrlParser result;

    using iterator_t = string::const_iterator;

    if (uri.length() == 0) return result;

    iterator_t uri_end = uri.end();

    // get query start
    iterator_t query_start = find(uri.begin(), uri_end, '?');

    // protocol
    iterator_t protocol_start = uri.begin();
    iterator_t protocol_end = find(protocol_start, uri_end, ':');            //"://");

    if (protocol_end != uri_end) {
        string http_protocol = &*(protocol_end);
        if ((http_protocol.length() > 3) && (http_protocol.substr(0, 3) == "://")) {
            result.protocol = string(protocol_start, protocol_end);
            protocol_end += 3;   //      ://
        } else {
            protocol_end = uri.begin();  // no protocol
        }
    } else {
        protocol_end = uri.begin();  // no protocol
    }

    // URL
    iterator_t host_start = protocol_end;
    iterator_t path_start = find(host_start, uri_end, '/');

    iterator_t host_end = find(protocol_end, (path_start != uri_end) ? path_start : query_start, ':');

    result.asset_url = string(host_start, host_end);

    // port
    if ((host_end != uri_end) && ((&*(host_end))[0] == ':')) { // we have a port
        host_end++;
        iterator_t portEnd = (path_start != uri_end) ? path_start : query_start;
        result.port = string(host_end, portEnd);
    }

    // URI
    if (path_start != uri_end) result.asset_uri = string(path_start, query_start);

    // query
    if (query_start != uri_end) result.query_string = string(query_start, uri.end());

    return result;
}   // Parse

PracticeSection::PracticeSection(
    const string &_id,
    const string &_type,
    const string &_practice_name
)
{
    auto maybe_type = string_to_practice_type.find(_type);
    if (maybe_type == string_to_practice_type.end()) {
        dbgError(D_K8S_POLICY) << "Illegal pracrtice type: " << _type;
        return;
    }

    type = _type;
    name = _practice_name;
    id = _id;
}

void
PracticeSection::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("practiceId",   id),
        cereal::make_nvp("practiceName", name),
        cereal::make_nvp("practiceType", type)
    );
}

const string &
PracticeSection::getPracticeId() const
{
    return id;
}

const string &
PracticeSection::getPracticeName() const
{
    return name;
}

ParametersSection::ParametersSection(
    const string &_id,
    const string &_name)
        :
    name(_name),
    id(_id)
{
    if (_id.empty() && _name.empty()) {
        dbgError(D_K8S_POLICY) << "Illegal Parameter values. Name and ID are empty";
        return;
    }
}

void
ParametersSection::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("parameterId",   id),
        cereal::make_nvp("parameterName", name),
        cereal::make_nvp("parameterType", type)
    );
}

const string &
ParametersSection::getId() const
{
    return id;
}

RulesTriggerSection::RulesTriggerSection(
    const string &_name,
    const string &_id,
    const string &_type)
        :
    name(_name),
    id(_id)
{
    if (_name.empty() && _id.empty()) {
        dbgError(D_K8S_POLICY) << "Illegal values for trigger. Name and ID are empty";
        return;
    }
    auto maybe_type = string_to_trigger_type.find(_type);
    if (maybe_type == string_to_trigger_type.end()) {
        dbgError(D_K8S_POLICY) << "Illegal trigger type in rule: " << _type;
        return;
    }
    type = _type;
}

void
RulesTriggerSection::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("triggerId",   id),
        cereal::make_nvp("triggerName", name),
        cereal::make_nvp("triggerType", type)
    );
}

const string &
RulesTriggerSection::getId() const
{
    return id;
}

const string &
RulesTriggerSection::getName() const
{
    return id;
}

RulesConfigRulebase::RulesConfigRulebase(
    const string &_name,
    const string &_url,
    const string &_uri,
    vector<PracticeSection> _practices,
    vector<ParametersSection> _parameters,
    vector<RulesTriggerSection> _triggers)
        :
    name(_name),
    practices(_practices),
    parameters(_parameters),
    triggers(_triggers)
{
    try {
        bool any = _name == "Any" && _url == "Any" && _uri == "Any";
        id = any ? "Any" : _url+_uri;
        if (_uri != "/") {
            context = any ? "All()" : "Any("
                "All("
                    "Any("
                        "EqualHost(" + _url + ")"
                    "),"
                    "EqualListeningPort(80)" +
                    string(_uri.empty() ? "" : ",BeginWithUri(" + _uri + ")") +
                "),"
                "All("
                    "Any("
                        "EqualHost(" + _url + ")"
                    "),"
                    "EqualListeningPort(443)" +
                    string(_uri.empty() ? "" : ",BeginWithUri(" + _uri + ")") +
                ")"
            ")";
        } else {
            context = any ? "All()" : "Any("
                "All("
                    "Any("
                        "EqualHost(" + _url + ")"
                    "),"
                    "EqualListeningPort(80)"
                "),"
                "All("
                    "Any("
                        "EqualHost(" + _url + ")"
                    "),"
                    "EqualListeningPort(443)"
                ")"
            ")";
        }
    } catch (const boost::uuids::entropy_error &e) {
        dbgWarning(D_K8S_POLICY) << "Failed to generate rule UUID. Error: " << e.what();
    }
}

void
RulesConfigRulebase::save(cereal::JSONOutputArchive &out_ar) const
{
    string empty_str = "";
    out_ar(
        cereal::make_nvp("assetId",    id),
        cereal::make_nvp("assetName",  name),
        cereal::make_nvp("ruleId",     id),
        cereal::make_nvp("ruleName",   name),
        cereal::make_nvp("context",    context),
        cereal::make_nvp("priority",   1),
        cereal::make_nvp("isCleanup",  false),
        cereal::make_nvp("parameters", parameters),
        cereal::make_nvp("practices",  practices),
        cereal::make_nvp("triggers",   triggers),
        cereal::make_nvp("zoneId",     empty_str),
        cereal::make_nvp("zoneName",   empty_str)
    );
}

const string &
RulesConfigRulebase::getRuleId() const
{
    return id;
}

const string &
RulesConfigRulebase::getAssetName() const
{
    return name;
}

const string &
RulesConfigRulebase::getRuleName() const
{
    return name;
}

const string &
RulesConfigRulebase::getAssetId() const
{
    return id;
}

const string &
RulesConfigRulebase::getPracticeId() const
{
    return practices[0].getPracticeId();
}

const string &
RulesConfigRulebase::getPracticeName() const
{
    return practices[0].getPracticeName();
}

const vector<PracticeSection> &
RulesConfigRulebase::getPractice() const
{
    return practices;
}

const vector<ParametersSection> &
RulesConfigRulebase::getParameters() const
{
    return parameters;
}

const vector<RulesTriggerSection> &
RulesConfigRulebase::getTriggers() const
{
    return triggers;
}

RulesConfigWrapper::RulesConfig::RulesConfig(const vector<RulesConfigRulebase> &_rules_config)
        :
    rules_config(_rules_config)
{
    sort(rules_config.begin(), rules_config.end(), sortBySpecific);
}

void
RulesConfigWrapper::RulesConfig::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("rulesConfig", rules_config)
    );
}

bool
RulesConfigWrapper::RulesConfig::sortBySpecific(
    const RulesConfigRulebase &first,
    const RulesConfigRulebase &second
)
{
    return sortBySpecificAux(first.getAssetName(), second.getAssetName());
}

bool
RulesConfigWrapper::RulesConfig::sortBySpecificAux(const string &first, const string &second)
{
    if (first.empty()) return false;
    if (second.empty()) return true;

    AssetUrlParser first_parsed = AssetUrlParser::parse(first);
    AssetUrlParser second_parsed = AssetUrlParser::parse(second);

    // sort by URL
    if (first_parsed.asset_url == "Any" && second_parsed.asset_url != "Any") return false;
    if (second_parsed.asset_url == "Any" && first_parsed.asset_url != "Any") return true;

    // sort by port
    if (first_parsed.port == "*" && second_parsed.port != "*") return false;
    if (second_parsed.port == "*" && first_parsed.port != "*") return true;

    // sort by URI
    if (first_parsed.asset_uri == "*" && second_parsed.asset_uri != "*") return false;
    if (second_parsed.asset_uri == "*" && first_parsed.asset_uri != "*") return true;

    if (first_parsed.asset_uri.empty()) return false;
    if (second_parsed.asset_uri.empty()) return true;

    if (second_parsed.asset_uri.find(first_parsed.asset_uri) != string::npos) return false;
    if (first_parsed.asset_uri.find(second_parsed.asset_uri) != string::npos) return true;

    if (first_parsed.asset_url.empty()) return false;
    if (second_parsed.asset_url.empty()) return false;

    return second < first;
}

void
RulesConfigWrapper::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("rulebase", rules_config_rulebase)
    );
}

// LCOV_EXCL_STOP
