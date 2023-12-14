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

#ifndef __NEW_APPSEC_POLICY_CRD_PARSER_H__
#define __NEW_APPSEC_POLICY_CRD_PARSER_H__

#include <string>
#include <cereal/archives/json.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "config.h"
#include "debug.h"
#include "rest.h"
#include "local_policy_common.h"

// LCOV_EXCL_START Reason: no test exist

class NewParsedRule
{
public:
    NewParsedRule() {}
    NewParsedRule(const std::string &_host) : host(_host) {}

    void load(cereal::JSONInputArchive &archive_in);

    const std::vector<std::string> & getLogTriggers() const;
    const std::vector<std::string> & getExceptions() const;
    const std::vector<std::string> & getPractices() const;
    const std::vector<std::string> & getAccessControlPractices() const;
    const std::string & getSourceIdentifiers() const;
    const std::string & getCustomResponse() const;
    const std::string & getTrustedSources() const;
    const std::string & getUpgradeSettings() const;
    const std::string & getHost() const;
    const std::string & getMode() const;

    void setHost(const std::string &_host);
    void setMode(const std::string &_mode);

private:
    std::vector<std::string>    log_triggers;
    std::vector<std::string>    exceptions;
    std::vector<std::string>    threat_prevention_practices;
    std::vector<std::string>    access_control_practices;
    std::string                 source_identifiers;
    std::string                 custom_response;
    std::string                 trusted_sources;
    std::string                 upgrade_settings;
    std::string                 host;
    std::string                 mode;
};

class NewAppsecPolicySpec : Singleton::Consume<I_Environment>
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const NewParsedRule & getDefaultRule() const;
    const std::vector<NewParsedRule> & getSpecificRules() const;
    const std::string & getAppSecClassName() const;
    bool isAssetHostExist(const std::string &full_url) const;
    void addSpecificRule(const NewParsedRule &_rule);

private:
    std::string appsec_class_name;
    NewParsedRule default_rule;
    std::vector<NewParsedRule> specific_rules;
};


#endif // __NEW_APPSEC_POLICY_CRD_PARSER_H__
// LCOV_EXCL_STOP
