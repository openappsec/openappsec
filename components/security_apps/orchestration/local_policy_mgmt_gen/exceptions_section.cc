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
static const set<string> valid_actions = {"skip", "accept", "drop", "suppressLog"};

void
AppsecExceptionSpec::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec exception spec";
    parseAppsecJSONKey<string>("name", name, archive_in);
    parseAppsecJSONKey<string>("action", action, archive_in);
    if (valid_actions.count(action) == 0) {
        dbgWarning(D_LOCAL_POLICY) << "AppSec exception action invalid: " << action;
    }

    parseAppsecJSONKey<vector<string>>("countryCode", country_code, archive_in);
    parseAppsecJSONKey<vector<string>>("countryName", country_name, archive_in);
    parseAppsecJSONKey<vector<string>>("hostName", host_name, archive_in);
    parseAppsecJSONKey<vector<string>>("paramName", param_name, archive_in);
    parseAppsecJSONKey<vector<string>>("paramValue", param_value, archive_in);
    parseAppsecJSONKey<vector<string>>("protectionName", protection_name, archive_in);
    parseAppsecJSONKey<vector<string>>("sourceIdentifier", source_identifier, archive_in);
    parseAppsecJSONKey<vector<string>>("sourceIp", source_ip, archive_in);
    parseAppsecJSONKey<vector<string>>("url", url, archive_in);
}

void
AppsecExceptionSpec::setName(const string &_name)
{
    name = _name;
}

const string &
AppsecExceptionSpec::getName() const
{
    return name;
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

ExceptionMatch::ExceptionMatch(const AppsecExceptionSpec &parsed_exception)
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
        items.push_back(ExceptionMatch("sourceIp", parsed_exception.getSourceIp()));
    }
    if (!parsed_exception.getUrl().empty()) {
        items.push_back(ExceptionMatch("url", parsed_exception.getUrl()));
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
        items.push_back(ExceptionMatch("sourceIp", parsed_exception.getSourceIp()));
    }
    if (!parsed_exception.getUrl().empty()) {
        items.push_back(ExceptionMatch("url", parsed_exception.getUrl()));
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

ExceptionBehavior::ExceptionBehavior(
    const string &_key,
    const string &_value)
        :
    key(_key),
    value(_value)
{
    try {
        id = to_string(boost::uuids::random_generator()());
    } catch (const boost::uuids::entropy_error &e) {
        dbgWarning(D_LOCAL_POLICY) << "Failed to generate exception behavior UUID. Error: " << e.what();
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

const string
ExceptionBehavior::getBehaviorId() const
{
    return id;
}

void
InnerException::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("behavior", behavior),
        cereal::make_nvp("match",    match)
    );
}

const string
InnerException::getBehaviorId() const
{
    return behavior.getBehaviorId();
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
