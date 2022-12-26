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

#ifndef __EXCEPTPIONS_SECTION_H__
#define __EXCEPTPIONS_SECTION_H__

#include <string>
#include <cereal/archives/json.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "config.h"
#include "debug.h"
#include "rest.h"
#include "k8s_policy_common.h"

USE_DEBUG_FLAG(D_K8S_POLICY);
// LCOV_EXCL_START Reason: no test exist
class AppsecExceptionSpec
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_K8S_POLICY) << "Loading AppSec exception spec";
        parseAppsecJSONKey<std::string>("action", action, archive_in);
        parseAppsecJSONKey<std::vector<std::string>>("countryCode", country_code, archive_in);
        parseAppsecJSONKey<std::vector<std::string>>("countryName", country_name, archive_in);
        parseAppsecJSONKey<std::vector<std::string>>("hostName", host_name, archive_in);
        parseAppsecJSONKey<std::vector<std::string>>("paramName", param_name, archive_in);
        parseAppsecJSONKey<std::vector<std::string>>("paramValue", param_value, archive_in);
        parseAppsecJSONKey<std::vector<std::string>>("protectionName", protection_name, archive_in);
        parseAppsecJSONKey<std::vector<std::string>>("sourceIdentifier", source_identifier, archive_in);
        parseAppsecJSONKey<std::vector<std::string>>("sourceIp", source_ip, archive_in);
        parseAppsecJSONKey<std::vector<std::string>>("url", url, archive_in);
    }

    const std::string & getAction() const { return action; }
    const std::vector<std::string> & getCountryCode() const { return country_code; }
    const std::vector<std::string> & getCountryName() const { return country_name; }
    const std::vector<std::string> & getHostName() const { return host_name; }
    const std::vector<std::string> & getParamName() const { return param_name; }
    const std::vector<std::string> & getParamValue() const { return param_value; }
    const std::vector<std::string> & getProtectionName() const { return protection_name; }
    const std::vector<std::string> & getSourceIdentifier() const { return source_identifier; }
    const std::vector<std::string> & getSourceIp() const { return source_ip; }
    const std::vector<std::string> & getUrl() const { return url; }

private:
    std::string action;
    std::vector<std::string> country_code;
    std::vector<std::string> country_name;
    std::vector<std::string> host_name;
    std::vector<std::string> param_name;
    std::vector<std::string> param_value;
    std::vector<std::string> protection_name;
    std::vector<std::string> source_identifier;
    std::vector<std::string> source_ip;
    std::vector<std::string> url;
};

std::ostream &
operator<<(std::ostream &os, const AppsecExceptionSpec &obj)
{
    os
        << "action: "
        << makeSeparatedStr(obj.getAction(), ",")
        << "countryCode: "
        << makeSeparatedStr(obj.getCountryCode(), ",")
        << "countryName: "
        << makeSeparatedStr(obj.getCountryName(), ",")
        << "hostName: "
        << makeSeparatedStr(obj.getHostName(), ",")
        << "paramName: "
        << makeSeparatedStr(obj.getParamName(), ",")
        << "paramValue: "
        << makeSeparatedStr(obj.getParamValue(), ",")
        << "protectionName: "
        << makeSeparatedStr(obj.getProtectionName(), ",")
        << "sourceIdentifier: "
        << makeSeparatedStr(obj.getSourceIdentifier(), ",")
        << "sourceIp: "
        << makeSeparatedStr(obj.getSourceIp(), ",")
        << "url: "
        << makeSeparatedStr(obj.getUrl(), ",");

    return os;
}

class ExceptionMatch
{
public:
    ExceptionMatch(const AppsecExceptionSpec &parsed_exception)
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

    ExceptionMatch(const std::string &_key, const std::vector<std::string> &_value)
            :
        match_type(MatchType::Condition),
        key(_key),
        op("in"),
        value(_value)
    {}

    void
    serialize(cereal::JSONOutputArchive &out_ar) const
    {
        switch (match_type) {
            case (MatchType::Condition): {
                std::string type_str = "condition";
                out_ar(
                    cereal::make_nvp("key",   key),
                    cereal::make_nvp("op",    op),
                    cereal::make_nvp("type",  type_str),
                    cereal::make_nvp("value", value)
                );
                break;
            }
            case (MatchType::Operator): {
                std::string type_str = "operator";
                out_ar(
                    cereal::make_nvp("op",    op),
                    cereal::make_nvp("type",  type_str),
                    cereal::make_nvp("items", items)
                );
                break;
            }
            default: {
                dbgError(D_K8S_POLICY) << "No match for exception match type: " << static_cast<int>(match_type);
            }
        }
    }

private:
    MatchType match_type;
    std::string key;
    std::string op;
    std::vector<std::string> value;
    std::vector<ExceptionMatch> items;
};

class ExceptionBehavior
{
public:
    ExceptionBehavior(
        const std::string &_key,
        const std::string &_value)
            :
        key(_key),
        value(_value)
    {
        try {
            id = to_string(boost::uuids::random_generator()());
        } catch (const boost::uuids::entropy_error &e) {
            dbgWarning(D_K8S_POLICY) << "Failed to generate exception behavior UUID. Error: " << e.what();
        }
    }

    void
    serialize(cereal::JSONOutputArchive &out_ar) const
    {
        out_ar(
            cereal::make_nvp("key",   key),
            cereal::make_nvp("value", value),
            cereal::make_nvp("id",    id)
        );
    }

    const std::string getBehaviorId() const { return id; }

private:
    std::string key;
    std::string id;
    std::string value;
};

class InnerException
{
public:
    InnerException(
        ExceptionBehavior _behavior,
        ExceptionMatch _match)
            :
        behavior(_behavior),
        match(_match) {}

    void
    serialize(cereal::JSONOutputArchive &out_ar) const
    {
        out_ar(
            cereal::make_nvp("behavior", behavior),
            cereal::make_nvp("match",    match)
        );
    }

    const std::string getBehaviorId() const { return behavior.getBehaviorId(); }

    bool
    operator<(const InnerException &other) const
    {
        return getBehaviorId() < other.getBehaviorId();
    }

private:
    ExceptionBehavior behavior;
    ExceptionMatch match;
};

class ExceptionsRulebase
{
public:
    ExceptionsRulebase(
        std::vector<InnerException> _exceptions)
            :
        exceptions(_exceptions)
    {
        std::string context_id_str = "";
        for (const InnerException exception : exceptions) {
            std::string curr_id = "parameterId(" + exception.getBehaviorId() + "), ";
            context_id_str += curr_id;
        }
        context_id_str = context_id_str.substr(0, context_id_str.size() - 2);
        context = "Any(" + context_id_str + ")";
    }

    void
    serialize(cereal::JSONOutputArchive &out_ar) const
    {
        out_ar(
            cereal::make_nvp("context",    context),
            cereal::make_nvp("exceptions", exceptions)
        );
    }

private:
    std::string context;
    std::vector<InnerException> exceptions;
};

class ExceptionsWrapper
{
public:
    class Exception
    {
    public:
        Exception(const std::vector<ExceptionsRulebase> &_exception) : exception(_exception) {}

        void
        serialize(cereal::JSONOutputArchive &out_ar) const
        {
            out_ar(cereal::make_nvp("exception", exception));
        }

    private:
        std::vector<ExceptionsRulebase> exception;
    };
    ExceptionsWrapper(const std::vector<ExceptionsRulebase> &_exception) : exception_rulebase(Exception(_exception))
    {}

    void
    serialize(cereal::JSONOutputArchive &out_ar) const
    {
        out_ar(
            cereal::make_nvp("rulebase", exception_rulebase)
        );
    }

private:
    Exception exception_rulebase;
};
// LCOV_EXCL_STOP
#endif // __EXCEPTPIONS_SECTION_H__
