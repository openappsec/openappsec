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
    void load(cereal::JSONInputArchive &archive_in);

    const std::string & getName() const;
    const std::string & getAction() const;
    const std::vector<std::string> & getCountryCode() const;
    const std::vector<std::string> & getCountryName() const;
    const std::vector<std::string> & getHostName() const;
    const std::vector<std::string> & getParamName() const;
    const std::vector<std::string> & getParamValue() const;
    const std::vector<std::string> & getProtectionName() const;
    const std::vector<std::string> & getSourceIdentifier() const;
    const std::vector<std::string> & getSourceIp() const;
    const std::vector<std::string> & getUrl() const;

private:
    std::string name;
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

class ExceptionMatch
{
public:
    ExceptionMatch() {}
    ExceptionMatch(const AppsecExceptionSpec &parsed_exception);
    ExceptionMatch(const std::string &_key, const std::vector<std::string> &_value)
            :
        match_type(MatchType::Condition),
        key(_key),
        op("in"),
        value(_value)
    {}

    void save(cereal::JSONOutputArchive &out_ar) const;

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
    ExceptionBehavior() {}
    ExceptionBehavior(
        const std::string &_key,
        const std::string &_value
    );

    void save(cereal::JSONOutputArchive &out_ar) const;
    const std::string getBehaviorId() const;

private:
    std::string key;
    std::string id;
    std::string value;
};

class InnerException
{
public:
    InnerException() {}
    InnerException(
        ExceptionBehavior _behavior,
        ExceptionMatch _match)
            :
        behavior(_behavior),
        match(_match) {}

    void save(cereal::JSONOutputArchive &out_ar) const;
    const std::string getBehaviorId() const;
    bool operator<(const InnerException &other) const;

private:
    ExceptionBehavior behavior;
    ExceptionMatch match;
};

class ExceptionsRulebase
{
public:
    ExceptionsRulebase(std::vector<InnerException> _exceptions);
    void save(cereal::JSONOutputArchive &out_ar) const;

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

        void save(cereal::JSONOutputArchive &out_ar) const;

    private:
        std::vector<ExceptionsRulebase> exception;
    };
    ExceptionsWrapper(const std::vector<ExceptionsRulebase> &_exception) : exception_rulebase(Exception(_exception))
    {}

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    Exception exception_rulebase;
};
// LCOV_EXCL_STOP
#endif // __EXCEPTPIONS_SECTION_H__
