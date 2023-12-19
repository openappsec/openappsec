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

#ifndef __APPSEC_PRACTICE_SECTION_H__
#define __APPSEC_PRACTICE_SECTION_H__

#include <list>
#include <cereal/archives/json.hpp>
#include <cereal/types/list.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "config.h"
#include "debug.h"
#include "customized_cereal_map.h"
#include "local_policy_common.h"
#include "triggers_section.h"
#include "exceptions_section.h"
#include "trusted_sources_section.h"
#include "reverse_proxy_section.h"
#include "new_practice.h"

class AppSecWebBotsURI
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const std::string & getURI() const;

private:
    std::string uri;
};

class AppSecPracticeAntiBot
{
public:
    std::vector<std::string> getIjectedUris() const;
    std::vector<std::string> getValidatedUris() const;

    void load(cereal::JSONInputArchive &archive_in);
    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    std::string override_mode;
    std::vector<AppSecWebBotsURI> injected_uris;
    std::vector<AppSecWebBotsURI> validated_uris;
};

class AppSecWebAttackProtections
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const std::string getCsrfProtectionMode() const;
    const std::string & getErrorDisclosureMode() const;
    bool getNonValidHttpMethods() const;
    const std::string getOpenRedirectMode() const;

private:
    std::string csrf_protection;
    std::string open_redirect;
    std::string error_disclosure;
    bool non_valid_http_methods;
};

class AppSecPracticeWebAttacks
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    int getMaxBodySizeKb() const;
    int getMaxHeaderSizeBytes() const;
    int getMaxObjectDepth() const;
    int getMaxUrlSizeBytes() const;
    const std::string & getMinimumConfidence() const;
    const AppSecWebAttackProtections & getprotections() const;
    const std::string & getMode(const std::string &default_mode = "Inactive") const;

private:
    int max_body_size_kb;
    int max_header_size_bytes;
    int max_object_depth;
    int max_url_size_bytes;
    std::string mode;
    std::string minimum_confidence;
    AppSecWebAttackProtections protections;
};

class AppSecPracticeSnortSignatures
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const std::string & getOverrideMode() const;
    const std::vector<std::string> & getConfigMap() const;

private:
    std::string override_mode;
    std::vector<std::string> config_map;
};

class AppSecPracticeOpenSchemaAPI
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const std::string & getOverrideMode() const;
    const std::vector<std::string> & getConfigMap() const;

private:
    std::string override_mode;
    std::vector<std::string> config_map;
};

class AppSecPracticeSpec
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const AppSecPracticeOpenSchemaAPI & getOpenSchemaValidation() const;
    const AppSecPracticeSnortSignatures & getSnortSignatures() const;
    const AppSecPracticeWebAttacks & getWebAttacks() const;
    const AppSecPracticeAntiBot & getAntiBot() const;
    const std::string & getName() const;
    void setName(const std::string &_name);

private:
    AppSecPracticeOpenSchemaAPI       openapi_schema_validation;
    AppSecPracticeSnortSignatures     snort_signatures;
    AppSecPracticeWebAttacks          web_attacks;
    AppSecPracticeAntiBot             anti_bot;
    std::string                       practice_name;
};

class PracticeAdvancedConfig
{
public:
    PracticeAdvancedConfig() {}

    PracticeAdvancedConfig(const AppSecPracticeSpec &parsed_appsec_spec)
        :
        http_header_max_size(parsed_appsec_spec.getWebAttacks().getMaxHeaderSizeBytes()),
        http_illegal_methods_allowed(0),
        http_request_body_max_size(parsed_appsec_spec.getWebAttacks().getMaxBodySizeKb()),
        json_max_object_depth(parsed_appsec_spec.getWebAttacks().getMaxObjectDepth()),
        url_max_size(parsed_appsec_spec.getWebAttacks().getMaxUrlSizeBytes())
    {}

    // LCOV_EXCL_START Reason: no test exist
    PracticeAdvancedConfig(
        int _http_header_max_size,
        int _http_request_body_max_size,
        int _json_max_object_depth,
        int _url_max_size)
        :
        http_header_max_size(_http_header_max_size),
        http_illegal_methods_allowed(0),
        http_request_body_max_size(_http_request_body_max_size),
        json_max_object_depth(_json_max_object_depth),
        url_max_size(_url_max_size)
    {}
    // LCOV_EXCL_STOP


    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    int http_header_max_size;
    int http_illegal_methods_allowed;
    int http_request_body_max_size;
    int json_max_object_depth;
    int url_max_size;
};

class TriggersInWaapSection
{
public:
    TriggersInWaapSection(const LogTriggerSection &log_section)
        :
        trigger_type("log"),
        id(log_section.getTriggerId()),
        name(log_section.getTriggerName()),
        log(log_section)
    {}

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    std::string trigger_type;
    std::string id;
    std::string name;
    LogTriggerSection log;
};

class ParsedMatch
{
public:
    ParsedMatch() {}
    ParsedMatch(const std::string &_operator, const std::string &_tag, const std::string &_value);

    ParsedMatch(const ExceptionMatch &exceptions);

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    std::string operator_type;
    std::string tag;
    std::string value;
    std::vector<ParsedMatch> parsed_match;
};

class AppSecOverride
{
public:
    AppSecOverride(const SourcesIdentifiers &parsed_trusted_sources);
    AppSecOverride(const InnerException &parsed_exceptions);

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    std::string id;
    std::vector<std::map<std::string, std::string>> parsed_behavior;
    ParsedMatch parsed_match;
};

class AppsecPracticeAntiBotSection
{
public:
    AppsecPracticeAntiBotSection() {};
    // LCOV_EXCL_START Reason: no test exist
    AppsecPracticeAntiBotSection(const NewAppSecPracticeAntiBot &anti_bot) :
        injected_uris(anti_bot.getIjectedUris()),
        validated_uris(anti_bot.getValidatedUris())
            {};
    // LCOV_EXCL_STOP

    AppsecPracticeAntiBotSection(const AppSecPracticeAntiBot &anti_bot) :
        injected_uris(anti_bot.getIjectedUris()),
        validated_uris(anti_bot.getValidatedUris())
            {};

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    std::vector<std::string> injected_uris;
    std::vector<std::string> validated_uris;
};

class WebAppSection
{
public:
    WebAppSection() {}

    WebAppSection(
        const std::string &_application_urls,
        const std::string &_asset_id,
        const std::string &_asset_name,
        const std::string &_rule_id,
        const std::string &_rule_name,
        const std::string &_practice_id,
        const std::string &_practice_name,
        const std::string &_context,
        const AppSecPracticeSpec &parsed_appsec_spec,
        const LogTriggerSection &parsed_log_trigger,
        const std::string &default_mode,
        const AppSecTrustedSources &parsed_trusted_sources,
        const std::vector<InnerException> &parsed_exceptions
    );

    WebAppSection(
        const std::string &_application_urls,
        const std::string &_asset_id,
        const std::string &_asset_name,
        const std::string &_rule_id,
        const std::string &_rule_name,
        const std::string &_practice_id,
        const std::string &_practice_name,
        const std::string &_context,
        const std::string &_web_attack_mitigation_severity,
        const std::string &_web_attack_mitigation_mode,
        const PracticeAdvancedConfig &_practice_advanced_config,
        const AppsecPracticeAntiBotSection &_anti_bots,
        const LogTriggerSection &parsed_log_trigger,
        const AppSecTrustedSources &parsed_trusted_sources);

    void save(cereal::JSONOutputArchive &out_ar) const;

    bool operator< (const WebAppSection &other) const;

private:
    std::string application_urls;
    std::string asset_id;
    std::string asset_name;
    std::string rule_id;
    std::string rule_name;
    std::string practice_id;
    std::string practice_name;
    std::string context;
    std::string web_attack_mitigation_action;
    std::string web_attack_mitigation_severity;
    std::string web_attack_mitigation_mode;
    bool web_attack_mitigation;
    std::vector<TriggersInWaapSection> triggers;
    PracticeAdvancedConfig practice_advanced_config;
    AppsecPracticeAntiBotSection anti_bots;
    std::vector<AppSecTrustedSources> trusted_sources;
    std::vector<AppSecOverride> overrides;
};

class WebAPISection
{
public:
    WebAPISection(
        const std::string &_application_urls,
        const std::string &_asset_id,
        const std::string &_asset_name,
        const std::string &_rule_id,
        const std::string &_rule_name,
        const std::string &_practice_id,
        const std::string &_practice_name,
        const std::string &_web_attack_mitigation_action,
        const std::string &_web_attack_mitigation_severity,
        const std::string &_web_attack_mitigation_mode,
        bool _web_attack_mitigation,
        const PracticeAdvancedConfig &_practice_advanced_config)
        :
        application_urls(_application_urls),
        asset_id(_asset_id),
        asset_name(_asset_name),
        rule_id(_rule_id),
        rule_name(_rule_name),
        practice_id(_practice_id),
        practice_name(_practice_name),
        context("practiceId(" + practice_id +")"),
        web_attack_mitigation_action(_web_attack_mitigation_action),
        web_attack_mitigation_severity(_web_attack_mitigation_severity),
        web_attack_mitigation_mode(_web_attack_mitigation_mode),
        web_attack_mitigation(_web_attack_mitigation),
        practice_advanced_config(_practice_advanced_config)
    {}

    void save(cereal::JSONOutputArchive &out_ar) const;

    bool operator< (const WebAPISection &other) const;

private:
    std::string application_urls;
    std::string asset_id;
    std::string asset_name;
    std::string rule_id;
    std::string rule_name;
    std::string practice_id;
    std::string practice_name;
    std::string context;
    std::string web_attack_mitigation_action;
    std::string web_attack_mitigation_severity;
    std::string web_attack_mitigation_mode;
    bool web_attack_mitigation;
    PracticeAdvancedConfig practice_advanced_config;
};

class AppSecRulebase
{
public:
    AppSecRulebase(
        std::vector<WebAppSection> _webApplicationPractices,
        std::vector<WebAPISection> _webAPIPractices);

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    std::vector<WebAppSection> webApplicationPractices;
    std::vector<WebAPISection> webAPIPractices;
};


class AppSecWrapper
{
public:
    AppSecWrapper(const AppSecRulebase &_app_sec)
        :
        app_sec_rulebase(_app_sec)
    {}

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    AppSecRulebase app_sec_rulebase;
};

class ParsedRule
{
public:
    ParsedRule() {}
    ParsedRule(const std::string &_host) : host(_host) {}

    void load(cereal::JSONInputArchive &archive_in);
    const std::vector<std::string> & getExceptions() const;
    const std::vector<std::string> & getLogTriggers() const;
    const std::vector<std::string> & getPractices() const;
    const std::string & getHost() const;
    const std::string & getMode() const;
    const std::string &rpmGetUpstream() const;
    const std::string &rpmGetRPSettings() const;
    bool rpmIsHttps() const;
    void setHost(const std::string &_host);
    void setMode(const std::string &_mode);
    const std::string & getCustomResponse() const;
    const std::string & getSourceIdentifiers() const;
    const std::string & getTrustedSources() const;

private:
    std::vector<std::string> exceptions;
    std::vector<std::string> log_triggers;
    std::vector<std::string> practices;
    std::string host;
    std::string mode;
    std::string custom_response;
    std::string source_identifiers;
    std::string trusted_sources;
    std::string rpm_upstream;
    std::string rpm_settings;
    bool rpm_is_ssl = false;
};

class AppsecPolicySpec : Singleton::Consume<I_Environment>
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const ParsedRule & getDefaultRule() const;
    const std::vector<ParsedRule> & getSpecificRules() const;
    bool isAssetHostExist(const std::string &full_url) const;
    void addSpecificRule(const ParsedRule &_rule);

private:
    ParsedRule default_rule;
    std::vector<ParsedRule> specific_rules;
};

class AppsecLinuxPolicy : Singleton::Consume<I_Environment>
{
public:
    AppsecLinuxPolicy() {}
    AppsecLinuxPolicy(
        const AppsecPolicySpec &_policies,
        const std::vector<AppSecPracticeSpec> &_practices,
        const std::vector<AppsecTriggerSpec> &_log_triggers,
        const std::vector<AppSecCustomResponseSpec> &_custom_responses,
        const std::vector<AppsecException> &_exceptions,
        const std::vector<TrustedSourcesSpec> &_trusted_sources,
        const std::vector<SourceIdentifierSpecWrapper> &_sources_identifiers)
        :
        policies(_policies),
        practices(_practices),
        log_triggers(_log_triggers),
        custom_responses(_custom_responses),
        exceptions(_exceptions),
        trusted_sources(_trusted_sources),
        sources_identifiers(_sources_identifiers) {}

    void serialize(cereal::JSONInputArchive &archive_in);

    const AppsecPolicySpec & getAppsecPolicySpec() const;
    const std::vector<AppSecPracticeSpec> & getAppSecPracticeSpecs() const;
    const std::vector<AppsecTriggerSpec> & getAppsecTriggerSpecs() const;
    const std::vector<AppSecCustomResponseSpec> & getAppSecCustomResponseSpecs() const;
    const std::vector<AppsecException> & getAppsecExceptions() const;
    const std::vector<TrustedSourcesSpec> & getAppsecTrustedSourceSpecs() const;
    const std::vector<SourceIdentifierSpecWrapper> & getAppsecSourceIdentifierSpecs() const;
    const std::vector<RPMSettings> &rpmGetRPSettings() const;
    void addSpecificRule(const ParsedRule &_rule);

private:
    AppsecPolicySpec policies;
    std::vector<AppSecPracticeSpec> practices;
    std::vector<AppsecTriggerSpec> log_triggers;
    std::vector<AppSecCustomResponseSpec> custom_responses;
    std::vector<AppsecException> exceptions;
    std::vector<TrustedSourcesSpec> trusted_sources;
    std::vector<SourceIdentifierSpecWrapper> sources_identifiers;
    std::vector<RPMSettings> rpm_settings;
};

#endif // __APPSEC_PRACTICE_SECTION_H__
