// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "rules_config_section.h"

using namespace std;

USE_DEBUG_FLAG(D_LOCAL_POLICY);

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
        dbgError(D_LOCAL_POLICY) << "Illegal pracrtice type: " << _type;
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

// LCOV_EXCL_START Reason: no test exist
ParametersSection::ParametersSection(
    const string &_id,
    const string &_name)
        :
    name(_name),
    id(_id)
{
    if (_id.empty() && _name.empty()) {
        dbgError(D_LOCAL_POLICY) << "Illegal Parameter values. Name and ID are empty";
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
// LCOV_EXCL_STOP

RulesTriggerSection::RulesTriggerSection(
    const string &_name,
    const string &_id,
    const string &_type)
        :
    name(_name),
    id(_id)
{
    if (_name.empty() && _id.empty()) {
        dbgError(D_LOCAL_POLICY) << "Illegal values for trigger. Name and ID are empty";
        return;
    }
    auto maybe_type = string_to_trigger_type.find(_type);
    if (maybe_type == string_to_trigger_type.end()) {
        dbgError(D_LOCAL_POLICY) << "Illegal trigger type in rule: " << _type;
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

RulesConfigRulebase::RulesConfigRulebase(
    const string &_name,
    const string &_url,
    const string &_port,
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
        if (any) {
            context ="All()";
            return;
        }
        string host_check = "Any(EqualHost(" + _url + ")),";
        string uri_check = (_uri.empty() || _uri == "/" ) ? "" : ",BeginWithUri(" + _uri + ")";
        auto ports = _port.empty() ? vector<string>({"80", "443"}) : vector<string>({_port});
        context = "Any(";
        for (auto &port : ports) {
            string check_last = (ports.size() == 1 || port == "443") ? ")" : "),";
            context += "All(" + host_check + "EqualListeningPort(" + port + ")" + uri_check + check_last;
        }
        context += ")";
    } catch (const boost::uuids::entropy_error &e) {
        dbgWarning(D_LOCAL_POLICY) << "Failed to generate rule UUID. Error: " << e.what();
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
RulesConfigRulebase::getContext() const
{
    return context;
}

const string &
RulesConfigRulebase::getAssetName() const
{
    return name;
}

const string &
RulesConfigRulebase::getAssetId() const
{
    return id;
}

UsersIdentifier::UsersIdentifier(const string &_source_identifier, vector<string> _identifier_values)
        :
    source_identifier(_source_identifier),
    identifier_values(_identifier_values)
{}

// LCOV_EXCL_START Reason: no test exist
const string &
UsersIdentifier::getIdentifier() const
{
    return source_identifier;
}
// LCOV_EXCL_STOP

void
UsersIdentifier::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("sourceIdentifier", source_identifier),
        cereal::make_nvp("identifierValues", identifier_values)
    );
}

UsersIdentifiersRulebase::UsersIdentifiersRulebase(
    const string &_context,
    const string &_source_identifier,
    const vector<string> &_identifier_values,
    const vector<UsersIdentifier> &_source_identifiers)
        :
    context(_context),
    source_identifier(_source_identifier),
    identifier_values(_identifier_values),
    source_identifiers(_source_identifiers)
{}

// LCOV_EXCL_START Reason: no test exist
const string &
UsersIdentifiersRulebase::getIdentifier() const
{
    if (source_identifiers.empty()) return source_identifier;
    return source_identifiers[0].getIdentifier();
}
// LCOV_EXCL_STOP

void
UsersIdentifiersRulebase::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("context",         context),
        cereal::make_nvp("sourceIdentifier", source_identifier),
        cereal::make_nvp("identifierValues", identifier_values),
        cereal::make_nvp("sourceIdentifiers", source_identifiers)
    );
}

RulesRulebase::RulesRulebase(
    const vector<RulesConfigRulebase> &_rules_config,
    const vector<UsersIdentifiersRulebase> &_users_identifiers)
        :
    rules_config(_rules_config),
    users_identifiers(_users_identifiers)
{
    sort(rules_config.begin(), rules_config.end(), sortBySpecific);
}

void
RulesRulebase::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("rulesConfig", rules_config),
        cereal::make_nvp("usersIdentifiers", users_identifiers)
    );
}

bool
RulesRulebase::sortBySpecific(
    const RulesConfigRulebase &first,
    const RulesConfigRulebase &second
)
{
    return sortBySpecificAux(first.getAssetName(), second.getAssetName());
}

bool
RulesRulebase::sortBySpecificAux(const string &first, const string &second)
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
