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

#include "appsec_practice_section.h"

using namespace std;

USE_DEBUG_FLAG(D_K8S_POLICY);
// LCOV_EXCL_START Reason: no test exist
void
AppSecWebBotsURI::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_K8S_POLICY) << "Loading AppSec Web Bots URI";
    parseAppsecJSONKey<string>("uri", uri, archive_in);
}

const string &
AppSecWebBotsURI::getURI() const
{
    return uri;
}

void
AppSecPracticeAntiBot::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_K8S_POLICY) << "Loading AppSec Web Bots";
    parseAppsecJSONKey<vector<AppSecWebBotsURI>>("injected-URIs", injected_uris, archive_in);
    parseAppsecJSONKey<vector<AppSecWebBotsURI>>("validated-URIs", validated_uris, archive_in);
    parseAppsecJSONKey<string>("override-mode", override_mode, archive_in, "Inactive");
}

void
AppSecPracticeAntiBot::save(cereal::JSONOutputArchive &out_ar) const
{
    vector<string> injected;
    vector<string> validated;
    for (const AppSecWebBotsURI &uri : injected_uris) injected.push_back(uri.getURI());
    for (const AppSecWebBotsURI &uri : validated_uris) injected.push_back(uri.getURI());
    out_ar(
        cereal::make_nvp("injected", injected),
        cereal::make_nvp("validated", validated)
    );
}

void
AppSecWebAttackProtections::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_K8S_POLICY) << "Loading AppSec Web Attack Protections";
    parseAppsecJSONKey<string>("csrf-enabled", csrf_protection, archive_in, "inactive");
    parseAppsecJSONKey<string>("error-disclosure-enabled", error_disclosure, archive_in, "inactive");
    parseAppsecJSONKey<string>("open-redirect-enabled", open_redirect, archive_in, "inactive");
    parseAppsecJSONKey<bool>("non-valid-http-methods", non_valid_http_methods, archive_in, false);
}

const string
AppSecWebAttackProtections::getCsrfProtectionMode() const
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

const string &
AppSecWebAttackProtections::getErrorDisclosureMode() const
{
    return error_disclosure;
}

bool
AppSecWebAttackProtections::getNonValidHttpMethods() const
{
    return non_valid_http_methods;
}

const string
AppSecWebAttackProtections::getOpenRedirectMode() const
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

void
AppSecPracticeWebAttacks::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_K8S_POLICY) << "Loading AppSec practice spec";
    parseAppsecJSONKey<AppSecWebAttackProtections>("protections", protections, archive_in);
    if (getMode() == "Prevent") {
        parseAppsecJSONKey<string>("minimum-confidence", minimum_confidence, archive_in, "critical");
    } else {
        minimum_confidence = "Transparent";
    }
    parseAppsecJSONKey<string>("override-mode", mode, archive_in, "Unset");
    parseAppsecJSONKey<int>("max-body-size-kb", max_body_size_kb, archive_in, 1000000);
    parseAppsecJSONKey<int>("max-header-size-bytes", max_header_size_bytes, archive_in, 102400);
    parseAppsecJSONKey<int>("max-object-depth", max_object_depth, archive_in, 40);
    parseAppsecJSONKey<int>("max-url-size-bytes", max_url_size_bytes, archive_in, 32768);
}

int
AppSecPracticeWebAttacks::getMaxBodySizeKb() const
{
    return max_body_size_kb;
}

int
AppSecPracticeWebAttacks::getMaxHeaderSizeBytes() const
{
    return max_header_size_bytes;
}

int
AppSecPracticeWebAttacks::getMaxObjectDepth() const
{
    return max_object_depth;
}

int
AppSecPracticeWebAttacks::getMaxUrlSizeBytes() const
{
    return max_url_size_bytes;
}

const string &
AppSecPracticeWebAttacks::getMinimumConfidence() const
{
    return minimum_confidence;
}

const string &
AppSecPracticeWebAttacks::getMode(const string &default_mode) const
{
    if (mode == "Unset" || (key_to_practices_val.find(mode) == key_to_practices_val.end())) {
        dbgError(D_K8S_POLICY) << "Couldn't find a value for key: " << mode << ". Returning " << default_mode;
        return default_mode;
    }
    return key_to_practices_val.at(mode);
}

void
AppSecPracticeSnortSignatures::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_K8S_POLICY) << "Loading AppSec Snort Signatures practice";
    parseAppsecJSONKey<string>("override-mode", override_mode, archive_in, "Inactive");
    parseAppsecJSONKey<vector<string>>("configmap", config_map, archive_in);
}

const string &
AppSecPracticeSnortSignatures::getOverrideMode() const
{
    return override_mode;
}

const vector<string> &
AppSecPracticeSnortSignatures::getConfigMap() const
{
    return config_map;
}

void
AppSecPracticeOpenSchemaAPI::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_K8S_POLICY) << "Loading AppSecPracticeOpenSchemaAPI practice";
    parseAppsecJSONKey<string>("override-mode", override_mode, archive_in, "Inactive");
    parseAppsecJSONKey<vector<string>>("configmap", config_map, archive_in);
}

const string &
AppSecPracticeOpenSchemaAPI::getOverrideMode() const
{
    return override_mode;
}

const vector<string> &
AppSecPracticeOpenSchemaAPI::getConfigMap() const
{
    return config_map;
}

void
AppSecPracticeSpec::load(cereal::JSONInputArchive &archive_in)
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
    parseAppsecJSONKey<string>("name", practice_name, archive_in);
}

const AppSecPracticeOpenSchemaAPI &
AppSecPracticeSpec::getOpenSchemaValidation() const
{
    return openapi_schema_validation;
}

const AppSecPracticeSnortSignatures &
AppSecPracticeSpec::getSnortSignatures() const
{
    return snort_signatures;
}

const AppSecPracticeWebAttacks &
AppSecPracticeSpec::getWebAttacks() const
{
    return web_attacks;
}

const AppSecPracticeAntiBot &
AppSecPracticeSpec::getAntiBot() const
{
    return anti_bot;
}

const string &
AppSecPracticeSpec::getName() const
{
    return practice_name;
}

void
PracticeAdvancedConfig::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("httpHeaderMaxSize",         http_header_max_size),
        cereal::make_nvp("httpIllegalMethodsAllowed", http_illegal_methods_allowed),
        cereal::make_nvp("httpRequestBodyMaxSize",    http_request_body_max_size),
        cereal::make_nvp("jsonMaxObjectDepth",        json_max_object_depth),
        cereal::make_nvp("urlMaxSize",                url_max_size)
    );
}

void
TriggersInWaapSection::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("$triggerType", trigger_type),
        cereal::make_nvp("id", id),
        cereal::make_nvp("name", name),
        cereal::make_nvp("log", log)
    );
}

AppSecOverride::AppSecOverride(const SourcesIdentifiers &parsed_trusted_sources)
{
    string source_ident = parsed_trusted_sources.getSourceIdent();
    map<string, string> behavior = {{"httpSourceId", source_ident}};
    parsed_behavior.push_back(behavior);
    parsed_match = {{"operator", "BASIC"}, {"tag", "sourceip"}, {"value", "0.0.0.0/0"}};
}

void
AppSecOverride::save(cereal::JSONOutputArchive &out_ar) const
{
    string parameter_type = "TrustedSource";
    out_ar(
        cereal::make_nvp("parsedBehavior", parsed_behavior),
        cereal::make_nvp("parsedMatch",    parsed_match)
    );
}

WebAppSection::WebAppSection(
    const string &_application_urls,
    const string &_asset_id,
    const string &_asset_name,
    const string &_rule_id,
    const string &_rule_name,
    const string &_practice_id,
    const string &_practice_name,
    const AppSecPracticeSpec &parsed_appsec_spec,
    const LogTriggerSection &parsed_log_trigger,
    const string &default_mode,
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
WebAppSection::save(cereal::JSONOutputArchive &out_ar) const
{
    string disabled_str = "Disabled";
    string detect_str = "Detect";
    vector<string> empty_list;
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

const string &
WebAppSection::getPracticeId() const
{
    return practice_id;
}

bool
WebAppSection::operator<(const WebAppSection &other) const
{
    return getPracticeId() < other.getPracticeId();
}

void
WebAPISection::save(cereal::JSONOutputArchive &out_ar) const
{
    string disabled_str = "Disabled";
    vector<string> empty_list;
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

const string &
WebAPISection::getPracticeId() const
{
    return practice_id;
}

void
AppSecRulebase::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("WebAPISecurity",         webAPIPractices),
        cereal::make_nvp("WebApplicationSecurity", webApplicationPractices)
    );
}

void
AppSecWrapper::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(cereal::make_nvp("WAAP", app_sec_rulebase));
}

void
ParsedRule::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_K8S_POLICY) << "Loading AppSec ParsedRule";
    parseAppsecJSONKey<vector<string>>("exceptions", exceptions, archive_in);
    parseAppsecJSONKey<vector<string>>("triggers", log_triggers, archive_in);
    parseAppsecJSONKey<vector<string>>("practices", practices, archive_in);
    parseAppsecJSONKey<string>("mode", mode, archive_in);
    parseAppsecJSONKey<string>("custom-response", custom_response, archive_in);
    parseAppsecJSONKey<string>("source-identifiers", source_identifiers, archive_in);
    parseAppsecJSONKey<string>("trusted-sources", trusted_sources, archive_in);
    try {
        archive_in(cereal::make_nvp("host", host));
    } catch (const cereal::Exception &e)
    {} // The default ParsedRule does not hold a host, so no error handling
}

const vector<string> &
ParsedRule::getExceptions() const
{
    return exceptions;
}

const vector<string> &
ParsedRule::getLogTriggers() const
{
    return log_triggers;
}

const vector<string> &
ParsedRule::getPractices() const
{
    return practices;
}

const string &
ParsedRule::getHost() const
{
    return host;
}

const string &
ParsedRule::getMode() const
{
    return mode;
}

void
ParsedRule::setHost(const string &_host)
{
    host = _host;
}

void
ParsedRule::setMode(const string &_mode)
{
    mode = _mode;
}

const string &
ParsedRule::getCustomResponse() const
{
    return custom_response;
}

const string &
ParsedRule::getSourceIdentifiers() const
{
    return source_identifiers;
}

const string &
ParsedRule::getTrustedSources() const
{
    return trusted_sources;
}

void
AppsecPolicySpec::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_K8S_POLICY) << "Loading AppSec policy spec";
    parseAppsecJSONKey<ParsedRule>("default", default_rule, archive_in);
    auto default_mode_annot =
        Singleton::Consume<I_Environment>::by<AppsecPolicySpec>()->get<string>("default mode annotation");
    if (default_mode_annot.ok() && !default_mode_annot.unpack().empty() && default_rule.getMode().empty()) {
        default_rule.setMode(default_mode_annot.unpack());
    }
    default_rule.setHost("*");
    parseAppsecJSONKey<list<ParsedRule>>("specific-rules", specific_rules, archive_in);
    specific_rules.push_front(default_rule);
}

const ParsedRule &
AppsecPolicySpec::getDefaultRule() const
{
    return default_rule;
}

const list<ParsedRule> &
AppsecPolicySpec::getSpecificRules() const
{
    return specific_rules;
}

void
AppsecLinuxPolicy::serialize(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_K8S_POLICY) << "Loading Appsec Linux Policy";
    parseAppsecJSONKey<AppsecPolicySpec>("policies", policies, archive_in);
    parseAppsecJSONKey<vector<AppSecPracticeSpec>>("practices", practices, archive_in);
    parseAppsecJSONKey<vector<AppsecTriggerSpec>>("log-triggers", log_triggers, archive_in);
    parseAppsecJSONKey<vector<AppSecCustomResponseSpec>>("custom-responses", custom_responses, archive_in);
    parseAppsecJSONKey<vector<AppsecExceptionSpec>>("exceptions", exceptions, archive_in);
    parseAppsecJSONKey<vector<TrustedSourcesSpec>>("trusted-sources", trusted_sources, archive_in);
    parseAppsecJSONKey<vector<SourceIdentifierSpecWrapper>>(
        "source-identifier",
        sources_identifier,
        archive_in
    );
}

const AppsecPolicySpec &
AppsecLinuxPolicy::getAppsecPolicySpec() const
{
    return policies;
}

const vector<AppSecPracticeSpec> &
AppsecLinuxPolicy::getAppSecPracticeSpecs() const
{
    return practices;
}

const vector<AppsecTriggerSpec> &
AppsecLinuxPolicy::getAppsecTriggerSpecs() const
{
    return log_triggers;
}

const vector<AppSecCustomResponseSpec> &
AppsecLinuxPolicy::getAppSecCustomResponseSpecs() const
{
    return custom_responses;
}

const vector<AppsecExceptionSpec> &
AppsecLinuxPolicy::getAppsecExceptionSpecs() const
{
    return exceptions;
}

const vector<TrustedSourcesSpec> &
AppsecLinuxPolicy::getAppsecTrustedSourceSpecs() const
{
    return trusted_sources;
}

const vector<SourceIdentifierSpecWrapper> &
AppsecLinuxPolicy::getAppsecSourceIdentifierSpecs() const
{
    return sources_identifier;
}

// LCOV_EXCL_STOP
