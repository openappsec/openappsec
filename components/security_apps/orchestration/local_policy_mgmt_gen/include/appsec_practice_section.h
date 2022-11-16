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
#include "k8s_policy_common.h"
#include "triggers_section.h"
#include "exceptions_section.h"
#include "trusted_sources_section.h"

USE_DEBUG_FLAG(D_K8S_POLICY);

class AppSecWebBotsURI
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_K8S_POLICY) << "Loading AppSec Web Bots URI";
        parseAppsecJSONKey<std::string>("uri", uri, archive_in);
    }

    const std::string & getURI() const { return uri; }

private:
    std::string uri;
};

std::ostream &
operator<<(std::ostream &os, const AppSecWebBotsURI &obj)
{
    os << obj.getURI();
    return os;
}

std::ostream &
operator<<(std::ostream &os, const std::vector<AppSecWebBotsURI> &obj)
{
    os << "[" << std::endl;
    makeSeparatedStr(obj, ",");
    os << std::endl << "]";
    return os;
}

class AppSecPracticeAntiBot
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_K8S_POLICY) << "Loading AppSec Web Bots";
        parseAppsecJSONKey<std::vector<AppSecWebBotsURI>>("injected-URIs", injected_uris, archive_in);
        parseAppsecJSONKey<std::vector<AppSecWebBotsURI>>("validated-URIs", validated_uris, archive_in);
        parseAppsecJSONKey<std::string>("override-mode", override_mode, archive_in, "Inactive");
    }

    void
    save(cereal::JSONOutputArchive &out_ar) const
    {
        std::vector<std::string> injected;
        std::vector<std::string> validated;
        for (const AppSecWebBotsURI &uri : getInjectedURIs()) injected.push_back(uri.getURI());
        for (const AppSecWebBotsURI &uri : getValidatedURIs()) injected.push_back(uri.getURI());
        out_ar(
            cereal::make_nvp("injected", injected),
            cereal::make_nvp("validated", validated)
        );
    }

    const std::vector<AppSecWebBotsURI> & getInjectedURIs() const { return injected_uris; }
    const std::vector<AppSecWebBotsURI> & getValidatedURIs() const { return validated_uris; }
    const std::string & getOverrideMode() const { return override_mode; }

private:
    std::string override_mode;
    std::vector<AppSecWebBotsURI> injected_uris;
    std::vector<AppSecWebBotsURI> validated_uris;
};

std::ostream &
operator<<(std::ostream &os, const AppSecPracticeAntiBot &obj)
{
    os
        << "injected-URIs: "
        << obj.getInjectedURIs()
        << " validated-URIs: "
        << obj.getValidatedURIs()
        << ", override_mode: "
        << obj.getOverrideMode();
    return os;
}

class AppSecWebAttackProtections
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_K8S_POLICY) << "Loading AppSec Web Attack Protections";
        parseAppsecJSONKey<std::string>("csrf-enabled", csrf_protection, archive_in, "inactive");
        parseAppsecJSONKey<std::string>("error-disclosure-enabled", error_disclosure, archive_in, "inactive");
        parseAppsecJSONKey<std::string>("open-redirect-enabled", open_redirect, archive_in, "inactive");
        parseAppsecJSONKey<bool>("non-valid-http-methods", non_valid_http_methods, archive_in, false);
    }

    const std::string
    getCsrfProtectionMode() const
    {
        if (key_to_practices_val.find(csrf_protection) == key_to_practices_val.end()) {
            dbgError(D_K8S_POLICY)
                << "Failed to find a value for "
                << csrf_protection
                << ". Setting CSRF protection to Inactive";
            return "Inactive";
        }
        return key_to_practices_val.at(csrf_protection);
    }

    const std::string & getErrorDisclosureMode() const { return error_disclosure; }

    bool getNonValidHttpMethods() const { return non_valid_http_methods; }

    const std::string
    getOpenRedirectMode() const
    {
        if (key_to_practices_val.find(open_redirect) == key_to_practices_val.end()) {
            dbgError(D_K8S_POLICY)
                << "Failed to find a value for "
                << open_redirect
                << ". Setting Open Redirect mode to Inactive";
            return "Inactive";
        }
        return key_to_practices_val.at(open_redirect);
    }

private:
    std::string csrf_protection;
    std::string open_redirect;
    std::string error_disclosure;
    bool non_valid_http_methods;
};

std::ostream &
operator<<(std::ostream &os, const AppSecWebAttackProtections &obj)
{
    os
        << " csrf-protection: "
        << obj.getCsrfProtectionMode()
        << " error-disclosure: "
        << obj.getErrorDisclosureMode()
        << " non-valid-http-methods: "
        << obj.getNonValidHttpMethods()
        << " open-redirect: "
        << obj.getOpenRedirectMode();
    return os;
}

class AppSecPracticeWebAttacks
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_K8S_POLICY) << "Loading AppSec practice spec";
        parseAppsecJSONKey<AppSecWebAttackProtections>("protections", protections, archive_in);
        parseAppsecJSONKey<std::string>("override-mode", mode, archive_in, "Unset");
        if (getMode() == "Prevent") {
            parseAppsecJSONKey<std::string>("minimum-confidence", minimum_confidence, archive_in, "critical");
        } else {
            minimum_confidence = "Transparent";
        }
        parseAppsecJSONKey<int>("max-body-size-kb", max_body_size_kb, archive_in, 1000000);
        parseAppsecJSONKey<int>("max-header-size-bytes", max_header_size_bytes, archive_in, 102400);
        parseAppsecJSONKey<int>("max-object-depth", max_object_depth, archive_in, 40);
        parseAppsecJSONKey<int>("max-url-size-bytes", max_url_size_bytes, archive_in, 32768);
    }

    int getMaxBodySizeKb() const { return max_body_size_kb; }
    int getMaxHeaderSizeBytes() const { return max_header_size_bytes; }
    int getMaxObjectDepth() const { return max_object_depth; }
    int getMaxUrlSizeBytes() const { return max_url_size_bytes; }
    const std::string & getMinimumConfidence() const { return minimum_confidence; }
    const AppSecWebAttackProtections & getprotections() const { return protections; }

    const std::string &
    getMode(const std::string &default_mode = "Inactive") const
    {
        if (mode == "Unset" || (key_to_practices_val.find(mode) == key_to_practices_val.end())) {
            dbgError(D_K8S_POLICY) << "Couldn't find a value for key: " << mode << ". Returning " << default_mode;
            return default_mode;
        }
        return key_to_practices_val.at(mode);
    }

private:
    int max_body_size_kb;
    int max_header_size_bytes;
    int max_object_depth;
    int max_url_size_bytes;
    std::string minimum_confidence;
    std::string mode;
    AppSecWebAttackProtections protections;
};

std::ostream &
operator<<(std::ostream &os, const AppSecPracticeWebAttacks &obj)
{
    os
        << "mode: "
        << obj.getMode()
        << " max-body-size-kb: "
        << obj.getMaxBodySizeKb()
        << " max-header-size-bytes: "
        << obj.getMaxHeaderSizeBytes()
        << " max-object-depth: "
        << obj.getMaxObjectDepth()
        << " max-url-size-bytes: "
        << obj.getMaxUrlSizeBytes()
        << " minimum-confidence: "
        << obj.getMinimumConfidence()
        << " protections: "
        << obj.getprotections();
    return os;
}

class AppSecPracticeSnortSignatures
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_K8S_POLICY) << "Loading AppSec Snort Signatures practice";
        parseAppsecJSONKey<std::string>("override-mode", override_mode, archive_in, "Inactive");
        parseAppsecJSONKey<std::vector<std::string>>("files", config_map, archive_in);
    }

    const std::string & getOverrideMode() const { return override_mode; }

    const std::vector<std::string> & getConfigMap() const { return config_map; }

private:
    std::string override_mode;
    std::vector<std::string> config_map;
};

std::ostream &
operator<<(std::ostream &os, const AppSecPracticeSnortSignatures &obj)
{
    os
        << "override mode: "
        << obj.getOverrideMode()
        << ". Config map: [" << std::endl
        << makeSeparatedStr(obj.getConfigMap(), ",")
        << std::endl << "]";
    return os;
}

class AppSecPracticeOpenSchemaAPI
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_K8S_POLICY) << "Loading AppSecPracticeOpenSchemaAPI practice";
        parseAppsecJSONKey<std::string>("override-mode", override_mode, archive_in, "Inactive");
        parseAppsecJSONKey<std::vector<std::string>>("files", config_map, archive_in);
    }

    const std::string & getOverrideMode() const { return override_mode; }

    const std::vector<std::string> & getConfigMap() const { return config_map; }

private:
    std::string override_mode;
    std::vector<std::string> config_map;
};

std::ostream &
operator<<(std::ostream &os, const AppSecPracticeOpenSchemaAPI &obj)
{
    os
        << "override mode: "
        << obj.getOverrideMode()
        << ". Config map: [" << std::endl
        << makeSeparatedStr(obj.getConfigMap(), ",")
        << std::endl << "]";
    return os;
}

class AppSecPracticeSpec
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_K8S_POLICY) << "Loading AppSec practice spec";
        parseAppsecJSONKey<AppSecPracticeOpenSchemaAPI>(
            "openapi-schema-validation",
            openapi_schema_validation,
            archive_in
        );
        parseAppsecJSONKey<AppSecPracticeSnortSignatures>("snort-signatures", snort_signatures, archive_in);
        parseAppsecJSONKey<AppSecPracticeWebAttacks>("web-attacks", web_attacks, archive_in);
        parseAppsecJSONKey<AppSecPracticeAntiBot>("anti-bot", anti_bot, archive_in);
        parseAppsecJSONKey<std::string>("name", practice_name, archive_in);
    }

    const AppSecPracticeOpenSchemaAPI & getOpenSchemaValidation() const { return openapi_schema_validation; }
    const AppSecPracticeSnortSignatures & getSnortSignatures() const { return snort_signatures; }
    const AppSecPracticeWebAttacks & getWebAttacks() const { return web_attacks; }
    const AppSecPracticeAntiBot & getAntiBot() const { return anti_bot; }
    const std::string & getName() const { return practice_name; }

private:
    AppSecPracticeOpenSchemaAPI       openapi_schema_validation;
    AppSecPracticeSnortSignatures     snort_signatures;
    AppSecPracticeWebAttacks          web_attacks;
    AppSecPracticeAntiBot             anti_bot;
    std::string                       practice_name;
};

std::ostream &
operator<<(std::ostream &os, const AppSecPracticeSpec &obj)
{
    os
        << "Open Schema API:" << std::endl
        << obj.getOpenSchemaValidation()
        << std::endl << "Snort Signatures:" << std::endl
        << obj.getOpenSchemaValidation()
        << std::endl << "Web Attacks:" << std::endl
        << obj.getWebAttacks()
        << std::endl << "Web Bots:" << std::endl
        << obj.getAntiBot();
    return os;
}

class PracticeAdvancedConfig
{
public:
    PracticeAdvancedConfig(const AppSecPracticeSpec &parsed_appsec_spec)
            :
        http_header_max_size(parsed_appsec_spec.getWebAttacks().getMaxHeaderSizeBytes()),
        http_illegal_methods_allowed(0),
        http_request_body_max_size(parsed_appsec_spec.getWebAttacks().getMaxBodySizeKb()),
        json_max_object_depth(parsed_appsec_spec.getWebAttacks().getMaxObjectDepth()),
        url_max_size(parsed_appsec_spec.getWebAttacks().getMaxUrlSizeBytes())
    {}

    void
    save(cereal::JSONOutputArchive &out_ar) const
    {
        out_ar(
            cereal::make_nvp("httpHeaderMaxSize",         http_header_max_size),
            cereal::make_nvp("httpIllegalMethodsAllowed", http_illegal_methods_allowed),
            cereal::make_nvp("httpRequestBodyMaxSize",    http_request_body_max_size),
            cereal::make_nvp("jsonMaxObjectDepth",        json_max_object_depth),
            cereal::make_nvp("urlMaxSize",                url_max_size)
        );
    }

    void setIllegalMethodsAllowed(int val) { http_illegal_methods_allowed = val; };

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

    void
    save(cereal::JSONOutputArchive &out_ar) const
    {
        out_ar(
            cereal::make_nvp("$triggerType", trigger_type),
            cereal::make_nvp("id", id),
            cereal::make_nvp("name", name),
            cereal::make_nvp("log", log)
        );
    }

private:
    std::string trigger_type;
    std::string id;
    std::string name;
    LogTriggerSection log;
};

class AppSecOverride
{
public:
    AppSecOverride(const SourcesIdentifiers &parsed_trusted_sources)
    {
        std::string source_ident = parsed_trusted_sources.getSourceIdent();
        std::map<std::string, std::string> behavior = {{"httpSourceId", source_ident}};
        parsed_behavior.push_back(behavior);
        parsed_match = {{"operator", "BASIC"}, {"tag", "sourceip"}, {"value", "0.0.0.0/0"}};
    }

    void
    save(cereal::JSONOutputArchive &out_ar) const
    {
        std::string parameter_type = "TrustedSource";
        out_ar(
            cereal::make_nvp("parsedBehavior", parsed_behavior),
            cereal::make_nvp("parsedMatch",    parsed_match)
        );
    }
private:
    std::vector<std::map<std::string, std::string>> parsed_behavior;
    std::map<std::string, std::string> parsed_match;
};

class WebAppSection
{
public:
    WebAppSection(
        const std::string &_application_urls,
        const std::string &_asset_id,
        const std::string &_asset_name,
        const std::string &_rule_id,
        const std::string &_rule_name,
        const std::string &_practice_id,
        const std::string &_practice_name,
        const AppSecPracticeSpec &parsed_appsec_spec,
        const LogTriggerSection &parsed_log_trigger,
        const std::string &default_mode,
        const AppSecTrustedSources &parsed_trusted_sources)
            :
        application_urls(_application_urls),
        asset_id(_asset_id),
        asset_name(_asset_name),
        rule_id(_rule_id),
        rule_name(_rule_name),
        practice_id(_practice_id),
        practice_name(_practice_name),
        context("practiceId(" + practice_id +")"),
        web_attack_mitigation_severity(parsed_appsec_spec.getWebAttacks().getMinimumConfidence()),
        web_attack_mitigation_mode(parsed_appsec_spec.getWebAttacks().getMode(default_mode)),
        practice_advanced_config(parsed_appsec_spec),
        anti_bots(parsed_appsec_spec.getAntiBot()),
        trusted_sources({parsed_trusted_sources})
        {
            web_attack_mitigation = true;
            web_attack_mitigation_action =
                web_attack_mitigation_severity == "critical" ? "low" :
                web_attack_mitigation_severity == "high" ? "balanced" :
                web_attack_mitigation_severity == "medium" ? "high" :
                "Error";

            triggers.push_back(TriggersInWaapSection(parsed_log_trigger));
            for (const SourcesIdentifiers &source_ident : parsed_trusted_sources.getSourcesIdentifiers()) {
                overrides.push_back(AppSecOverride(source_ident));
            }
        }

    void
    serialize(cereal::JSONOutputArchive &out_ar) const
    {
        std::string disabled_str = "Disabled";
        std::string detect_str = "Detect";
        std::vector<std::string> empty_list;
        out_ar(
            cereal::make_nvp("context",                     context),
            cereal::make_nvp("webAttackMitigation",         web_attack_mitigation),
            cereal::make_nvp("webAttackMitigationSeverity", web_attack_mitigation_severity),
            cereal::make_nvp("webAttackMitigationAction",   web_attack_mitigation_action),
            cereal::make_nvp("webAttackMitigationMode",     web_attack_mitigation_mode),
            cereal::make_nvp("practiceAdvancedConfig",      practice_advanced_config),
            cereal::make_nvp("csrfProtection",              disabled_str),
            cereal::make_nvp("openRedirect",                disabled_str),
            cereal::make_nvp("errorDisclosure",             disabled_str),
            cereal::make_nvp("practiceId",                  practice_id),
            cereal::make_nvp("practiceName",                practice_name),
            cereal::make_nvp("assetId",                     asset_id),
            cereal::make_nvp("assetName",                   asset_name),
            cereal::make_nvp("ruleId",                      rule_id),
            cereal::make_nvp("ruleName",                    rule_name),
            cereal::make_nvp("triggers",                    triggers),
            cereal::make_nvp("applicationUrls",             application_urls),
            cereal::make_nvp("overrides",                   overrides),
            cereal::make_nvp("trustedSources",              trusted_sources),
            cereal::make_nvp("waapParameters",              empty_list),
            cereal::make_nvp("botProtection",               false),
            cereal::make_nvp("antiBot",                     anti_bots),
            cereal::make_nvp("botProtection_v2",            detect_str)
        );
    }

    const std::string & getPracticeId() const { return practice_id; }

    bool
    operator<(const WebAppSection &other) const
    {
        return getPracticeId() < other.getPracticeId();
    }

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
    AppSecPracticeAntiBot anti_bots;
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
        const AppSecPracticeSpec &parsed_appsec_spec)
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
        practice_advanced_config(parsed_appsec_spec)
        {}

    void
    serialize(cereal::JSONOutputArchive &out_ar) const
    {
        std::string disabled_str = "Disabled";
        std::vector<std::string> empty_list;
        out_ar(
            cereal::make_nvp("application_urls",               application_urls),
            cereal::make_nvp("asset_id",                       asset_id),
            cereal::make_nvp("asset_name",                     asset_name),
            cereal::make_nvp("context",                        context),
            cereal::make_nvp("practiceAdvancedConfig",         practice_advanced_config),
            cereal::make_nvp("practice_id",                    practice_id),
            cereal::make_nvp("practice_name",                  practice_name),
            cereal::make_nvp("ruleId",                         rule_id),
            cereal::make_nvp("ruleName",                       rule_name),
            cereal::make_nvp("schemaValidation",               false),
            cereal::make_nvp("schemaValidation_v2",            disabled_str),
            cereal::make_nvp("web_attack_mitigation",          web_attack_mitigation),
            cereal::make_nvp("web_attack_mitigation_action",   web_attack_mitigation_action),
            cereal::make_nvp("web_attack_mitigation_severity", web_attack_mitigation_severity),
            cereal::make_nvp("web_attack_mitigation_mode",     web_attack_mitigation_mode),
            cereal::make_nvp("oas",                            empty_list),
            cereal::make_nvp("trustedSources",                 empty_list),
            cereal::make_nvp("triggers",                       empty_list),
            cereal::make_nvp("waapParameters",                 empty_list),
            cereal::make_nvp("overrides",                      empty_list)
        );
    }

    const std::string & getPracticeId() const { return practice_id; }

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
        std::vector<WebAPISection> _webAPIPractices)
            :
        webApplicationPractices(_webApplicationPractices),
        webAPIPractices(_webAPIPractices) {}

    void
    serialize(cereal::JSONOutputArchive &out_ar) const
    {
        out_ar(
            cereal::make_nvp("WebAPISecurity",         webAPIPractices),
            cereal::make_nvp("WebApplicationSecurity", webApplicationPractices)
        );
    }

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

    void
    serialize(cereal::JSONOutputArchive &out_ar) const
    {
        out_ar(cereal::make_nvp("WAAP", app_sec_rulebase));
    }

private:
    AppSecRulebase app_sec_rulebase;
};


class ParsedRule
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_K8S_POLICY) << "Loading AppSec ParsedRule";
        parseAppsecJSONKey<std::vector<std::string>>("exceptions", exceptions, archive_in);
        parseAppsecJSONKey<std::vector<std::string>>("triggers", log_triggers, archive_in);
        parseAppsecJSONKey<std::vector<std::string>>("practices", practices, archive_in);
        parseAppsecJSONKey<std::string>("mode", mode, archive_in);
        parseAppsecJSONKey<std::string>("custom-response", custom_response, archive_in);
        parseAppsecJSONKey<std::string>("source-identifiers", source_identifiers, archive_in);
        parseAppsecJSONKey<std::string>("trusted-sources", trusted_sources, archive_in);
        try {
            archive_in(cereal::make_nvp("host", host));
        } catch (const cereal::Exception &e)
        {} // The default ParsedRule does not hold a host, so no error handling
    }

    const std::vector<std::string> & getExceptions() const { return exceptions; }

    const std::vector<std::string> & getLogTriggers() const { return log_triggers; }

    const std::vector<std::string> & getPractices() const { return practices; }

    const std::string & getHost() const { return host; }

    const std::string & getMode() const { return mode; }

    void setHost(const std::string &_host) { host = _host; };

    void setMode(const std::string &_mode) { mode = _mode; };

    const std::string & getCustomResponse() const { return custom_response; }

    const std::string & getSourceIdentifiers() const { return source_identifiers; }

    const std::string & getTrustedSources() const { return trusted_sources; }

private:
    std::vector<std::string> exceptions;
    std::vector<std::string> log_triggers;
    std::vector<std::string> practices;
    std::string host;
    std::string mode;
    std::string custom_response;
    std::string source_identifiers;
    std::string trusted_sources;
};

std::ostream &
operator<<(std::ostream &os, const ParsedRule &obj)
{
    os
        << "host: "
        << obj.getHost()
        << std::endl << "log trigger: "
        << makeSeparatedStr(obj.getLogTriggers(), ",")
        << std::endl << "mode: "
        << obj.getMode()
        << std::endl << "practices: "
        << makeSeparatedStr(obj.getPractices(), ",")
        << std::endl << "web responce: "
        << obj.getCustomResponse()
        << std::endl << " Exceptions: [" << std::endl
        << makeSeparatedStr(obj.getExceptions(), ",")
        << std::endl << "]";
    return os;
}

class AppsecPolicySpec : Singleton::Consume<I_Environment>
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_K8S_POLICY) << "Loading AppSec policy spec";
        parseAppsecJSONKey<ParsedRule>("default", default_rule, archive_in);
        auto default_mode_annot =
            Singleton::Consume<I_Environment>::by<AppsecPolicySpec>()->get<std::string>("default mode annotation");
        if (default_mode_annot.ok() && !default_mode_annot.unpack().empty() && default_rule.getMode().empty()) {
            default_rule.setMode(default_mode_annot.unpack());
        }
        default_rule.setHost("*");
        parseAppsecJSONKey<std::list<ParsedRule>>("specific-rules", specific_rules, archive_in);
        specific_rules.push_front(default_rule);
    }

    const ParsedRule & getDefaultRule() const { return default_rule; }

    const std::list<ParsedRule> & getSpecificRules() const { return specific_rules; }

private:
    ParsedRule default_rule;
    std::list<ParsedRule> specific_rules;
};

class AppsecLinuxPolicy : Singleton::Consume<I_Environment>
{
public:
    void
    serialize(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_K8S_POLICY) << "Loading AppSec policy spec";
        parseAppsecJSONKey<AppsecPolicySpec>("policies", policies, archive_in);
        parseAppsecJSONKey<std::vector<AppSecPracticeSpec>>("practices", practices, archive_in);
        parseAppsecJSONKey<std::vector<AppsecTriggerSpec>>("log-triggers", log_triggers, archive_in);
        parseAppsecJSONKey<std::vector<AppSecCustomResponseSpec>>("custom-responses", custom_responses, archive_in);
        parseAppsecJSONKey<std::vector<AppsecExceptionSpec>>("exceptions", exceptions, archive_in);
        parseAppsecJSONKey<std::vector<TrustedSourcesSpec>>("trusted-sources", trusted_sources, archive_in);
        parseAppsecJSONKey<std::vector<SourceIdentifierSpecWrapper>>(
            "source-identifier",
            sources_identifier,
            archive_in
        );
    }

    const AppsecPolicySpec & getAppsecPolicySpec() const { return policies; }

    const std::vector<AppSecPracticeSpec> & getAppSecPracticeSpecs() const { return practices; }

    const std::vector<AppsecTriggerSpec> & getAppsecTriggerSpecs() const { return log_triggers; }

    const std::vector<AppSecCustomResponseSpec> & getAppSecCustomResponseSpecs() const { return custom_responses; }

    const std::vector<AppsecExceptionSpec> & getAppsecExceptionSpecs() const { return exceptions; }

    const std::vector<TrustedSourcesSpec> & getAppsecTrustedSourceSpecs() const { return trusted_sources; }

    const std::vector<SourceIdentifierSpecWrapper> &
    getAppsecSourceIdentifierSpecs() const
    {
        return sources_identifier;
    }

private:
    AppsecPolicySpec policies;
    std::vector<AppSecPracticeSpec> practices;
    std::vector<AppsecTriggerSpec> log_triggers;
    std::vector<AppSecCustomResponseSpec> custom_responses;
    std::vector<AppsecExceptionSpec> exceptions;
    std::vector<TrustedSourcesSpec> trusted_sources;
    std::vector<SourceIdentifierSpecWrapper> sources_identifier;
};

std::ostream &
operator<<(std::ostream &os, const AppsecPolicySpec &obj)
{
    os
        << "Default Rule: "
        << obj.getDefaultRule()
        << std::endl <<"Specific Rules: [" << std::endl
        << makeSeparatedStr(obj.getSpecificRules(), ",")
        << std::endl << "]";
    return os;
}

#endif // __APPSEC_PRACTICE_SECTION_H__
