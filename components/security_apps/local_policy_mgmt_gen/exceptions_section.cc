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

#include "exceptions_section.h"

using namespace std;

USE_DEBUG_FLAG(D_LOCAL_POLICY);

// LCOV_EXCL_START Reason: no test exist
using AttributeGetter = function<vector<string>(const AppsecExceptionSpec&)>;
static const vector<pair<string, AttributeGetter>> attributes = {
    {"countryCode",      [](const AppsecExceptionSpec& e){ return e.getCountryCode(); }},
    {"countryName",      [](const AppsecExceptionSpec& e){ return e.getCountryName(); }},
    {"hostName",         [](const AppsecExceptionSpec& e){ return e.getHostName(); }},
    {"paramName",        [](const AppsecExceptionSpec& e){ return e.getParamName(); }},
    {"paramValue",       [](const AppsecExceptionSpec& e){ return e.getParamValue(); }},
    {"protectionName",   [](const AppsecExceptionSpec& e){ return e.getProtectionName(); }},
    {"sourceIdentifier", [](const AppsecExceptionSpec& e){ return e.getSourceIdentifier(); }},
    {"sourceIp",         [](const AppsecExceptionSpec& e){ return e.getSourceIp(); }},
    {"url",              [](const AppsecExceptionSpec& e){ return e.getUrl(); }}
};
static const set<string> valid_actions = {"skip", "accept", "drop", "suppressLog"};
static const unordered_map<string, string> key_to_action = {
    { "accept", "accept"},
    { "drop", "reject"},
    { "skip", "ignore"},
    { "suppressLog", "ignore"}
};

void
AppsecExceptionSpec::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec exception spec";
    parseAppsecJSONKey<string>("action", action, archive_in, "skip");
    if (valid_actions.count(action) == 0) {
        dbgWarning(D_LOCAL_POLICY) << "AppSec exception action invalid: " << action;
    }

    parseAppsecJSONKey<vector<string>>("countryCode", country_code, archive_in);
    if (!country_code.empty()) conditions_number++;

    parseAppsecJSONKey<vector<string>>("countryName", country_name, archive_in);
    if (!country_name.empty()) conditions_number++;

    parseAppsecJSONKey<vector<string>>("hostName", host_name, archive_in);
    if (!host_name.empty()) conditions_number++;

    parseAppsecJSONKey<vector<string>>("paramName", param_name, archive_in);
    if (!param_name.empty()) conditions_number++;

    parseAppsecJSONKey<vector<string>>("paramValue", param_value, archive_in);
    if (!param_value.empty()) conditions_number++;

    parseAppsecJSONKey<vector<string>>("protectionName", protection_name, archive_in);
    if (!protection_name.empty()) conditions_number++;

    parseAppsecJSONKey<vector<string>>("sourceIdentifier", source_identifier, archive_in);
    if (!source_identifier.empty()) conditions_number++;

    parseAppsecJSONKey<vector<string>>("sourceIp", source_ip, archive_in);
    if (!source_ip.empty()) conditions_number++;

    parseAppsecJSONKey<vector<string>>("url", url, archive_in);
    if (!url.empty()) conditions_number++;
}

const string &
AppsecExceptionSpec::getAction() const
{
    return action;
}

const vector<string> &
AppsecExceptionSpec::getCountryCode() const
{
    return country_code;
}

const vector<string> &
AppsecExceptionSpec::getCountryName() const
{
    return country_name;
}

const vector<string> &
AppsecExceptionSpec::getHostName() const
{
    return host_name;
}

const vector<string> &
AppsecExceptionSpec::getParamName() const
{
    return param_name;
}

const vector<string> &
AppsecExceptionSpec::getParamValue() const
{
    return param_value;
}

const vector<string> &
AppsecExceptionSpec::getProtectionName() const
{
    return protection_name;
}

const vector<string> &
AppsecExceptionSpec::getSourceIdentifier() const
{
    return source_identifier;
}

const vector<string> &
AppsecExceptionSpec::getSourceIp() const
{
    return source_ip;
}

const vector<string> &
AppsecExceptionSpec::getUrl() const
{
    return url;
}

bool
AppsecExceptionSpec::isOneCondition() const
{
    return conditions_number == 1;
}

void
AppsecException::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec exception";
    parseAppsecJSONKey<string>("name", name, archive_in);
    archive_in(CEREAL_NVP(exception_spec));
}

void
AppsecException::setName(const string &_name)
{
    name = _name;
}

const string &
AppsecException::getName() const
{
    return name;
}

const vector<AppsecExceptionSpec> &
AppsecException::getExceptions() const
{
    return exception_spec;
}

ExceptionMatch::ExceptionMatch(const AppsecExceptionSpec &parsed_exception)
        :
    match_type(MatchType::Operator),
    op("and")
{
    bool single_condition = parsed_exception.isOneCondition();
    for (auto &attrib : attributes) {
        auto &attrib_name = attrib.first;
        auto &attrib_getter = attrib.second;
        auto exceptions_value = attrib_getter(parsed_exception);
        if (exceptions_value.empty()) continue;
        if (single_condition) {
            if (exceptions_value.size() == 1) {
                match_type = MatchType::Condition;
                op = "equals";
                key = attrib_name;
                value = exceptions_value;
                return;
            } else {
                match_type = MatchType::Operator;
                op = "or";
                for (auto new_value : exceptions_value) {
                    items.push_back(ExceptionMatch(attrib_name, {new_value}));
                }
                return;
            }
        }
        items.push_back(ExceptionMatch(attrib_name, exceptions_value));
    }
}

ExceptionMatch::ExceptionMatch(const std::string &_key, const std::vector<std::string> &values)
{
    if (values.size() == 1) {
        match_type = MatchType::Condition;
        op = "equals";
        key = _key;
        value = values;
    } else {
        match_type = MatchType::Operator;
        op = "or";
        for (auto new_value : values) {
            items.push_back(ExceptionMatch(_key, {new_value}));
        }
    }
}

ExceptionMatch::ExceptionMatch(const NewAppsecException &parsed_exception)
        :
    match_type(MatchType::Operator),
    op("and")
{
    if (!parsed_exception.getCountryCode().empty()) {
        items.push_back(ExceptionMatch("countryCode", parsed_exception.getCountryCode()));
    }
    if (!parsed_exception.getCountryName().empty()) {
        items.push_back(ExceptionMatch("countryName", parsed_exception.getCountryName()));
    }
    if (!parsed_exception.getHostName().empty()) {
        items.push_back(ExceptionMatch("hostName", parsed_exception.getHostName()));
    }
    if (!parsed_exception.getParamName().empty()) {
        items.push_back(ExceptionMatch("paramName", parsed_exception.getParamName()));
    }
    if (!parsed_exception.getParamValue().empty()) {
        items.push_back(ExceptionMatch("paramValue", parsed_exception.getParamValue()));
    }
    if (!parsed_exception.getProtectionName().empty()) {
        items.push_back(ExceptionMatch("protectionName", parsed_exception.getProtectionName()));
    }
    if (!parsed_exception.getSourceIdentifier().empty()) {
        items.push_back(ExceptionMatch("sourceIdentifier", parsed_exception.getSourceIdentifier()));
    }
    if (!parsed_exception.getSourceIp().empty()) {
        items.push_back(ExceptionMatch("sourceIP", parsed_exception.getSourceIp()));
    }
    if (!parsed_exception.getUrl().empty()) {
        items.push_back(ExceptionMatch("url", parsed_exception.getUrl()));
    }

    // when there is only one operand, there's no need for an additional 'and'/'or' condition enclosing it
    if (items.size() == 1) {
        auto & other = items[0];
        match_type = other.match_type;
        op = other.op;
        key = other.key;
        value = other.value;
        items = other.items;
    }
}

void
ExceptionMatch::save(cereal::JSONOutputArchive &out_ar) const
{
    switch (match_type) {
        case (MatchType::Condition): {
            string type_str = "condition";
            out_ar(
                cereal::make_nvp("key",   key),
                cereal::make_nvp("op",    op),
                cereal::make_nvp("type",  type_str),
                cereal::make_nvp("value", value)
            );
            break;
        }
        case (MatchType::Operator): {
            string type_str = "operator";
            out_ar(
                cereal::make_nvp("op",    op),
                cereal::make_nvp("type",  type_str),
                cereal::make_nvp("items", items)
            );
            break;
        }
        default: {
            dbgError(D_LOCAL_POLICY) << "No match for exception match type: " << static_cast<int>(match_type);
        }
    }
}

const string &
ExceptionMatch::getOperator() const
{
    return op;
}

const string &
ExceptionMatch::getKey() const
{
    return key;
}

const string &
ExceptionMatch::getValue() const
{
    return value[0];
}

const vector<ExceptionMatch> &
ExceptionMatch::getMatch() const
{
    return items;
}

ExceptionBehavior::ExceptionBehavior(const string &_value)
{
    key = _value == "suppressLog" ? "log" : "action";
    try {
        value = key_to_action.at(_value);
        id = to_string(boost::uuids::random_generator()());
    } catch (const boost::uuids::entropy_error &e) {
        dbgWarning(D_LOCAL_POLICY) << "Failed to generate exception behavior UUID. Error: " << e.what();
    } catch (std::exception &e) {
        dbgWarning(D_LOCAL_POLICY) << "Failed to find exception name: " << _value << ". Error: " << e.what();
    }
}

void
ExceptionBehavior::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("key",   key),
        cereal::make_nvp("value", value),
        cereal::make_nvp("id",    id)
    );
}

const string &
ExceptionBehavior::getBehaviorId() const
{
    return id;
}

const string &
ExceptionBehavior::getBehaviorKey() const
{
    return key;
}

const string &
ExceptionBehavior::getBehaviorValue() const
{
    return value;
}

InnerException::InnerException(ExceptionBehavior _behavior, ExceptionMatch _match)
        :
    behavior(_behavior),
    match(_match)
{
}

void
InnerException::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("behavior", behavior),
        cereal::make_nvp("match",    match)
    );
}

const string &
InnerException::getBehaviorId() const
{
    return behavior.getBehaviorId();
}

const string &
InnerException::getBehaviorKey() const
{
    return behavior.getBehaviorKey();
}

const string &
InnerException::getBehaviorValue() const
{
    return behavior.getBehaviorValue();
}

const ExceptionMatch &
InnerException::getMatch() const
{
    return match;
}

ExceptionsRulebase::ExceptionsRulebase(
    vector<InnerException> _exceptions)
        :
    exceptions(_exceptions)
{
    string context_id_str = "";
    for (const InnerException & exception : exceptions) {
        string curr_id = "parameterId(" + exception.getBehaviorId() + "), ";
        context_id_str += curr_id;
    }
    context_id_str = context_id_str.substr(0, context_id_str.size() - 2);
    context = "Any(" + context_id_str + ")";
}

void
ExceptionsRulebase::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("context",    context),
        cereal::make_nvp("exceptions", exceptions)
    );
}

void
ExceptionsWrapper::Exception::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(cereal::make_nvp("exception", exception));
}

void
ExceptionsWrapper::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("rulebase", exception_rulebase)
    );
}
