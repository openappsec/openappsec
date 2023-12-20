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
#include <algorithm>

using namespace std;

USE_DEBUG_FLAG(D_LOCAL_POLICY);
// LCOV_EXCL_START Reason: no test exist

static const set<string> valid_modes = {"prevent-learn", "detect-learn", "prevent", "detect", "inactive"};
static const set<string> valid_confidences = {"medium", "high", "critical"};

void
AppSecWebBotsURI::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec Web Bots URI";
    parseAppsecJSONKey<string>("uri", uri, archive_in);
}

const string &
AppSecWebBotsURI::getURI() const
{
    return uri;
}

vector<string>
AppSecPracticeAntiBot::getIjectedUris() const
{
    vector<string> injected;
    for (const AppSecWebBotsURI &uri : injected_uris) {
        injected.push_back(uri.getURI());
    }
    return injected;
}

vector<string>
AppSecPracticeAntiBot::getValidatedUris() const
{
    vector<string> validated;
    for (const AppSecWebBotsURI &uri : validated_uris) {
        validated.push_back(uri.getURI());
    }
    return validated;
}

void
AppSecPracticeAntiBot::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec Web Bots";
    parseAppsecJSONKey<vector<AppSecWebBotsURI>>("injected-URIs", injected_uris, archive_in);
    parseAppsecJSONKey<vector<AppSecWebBotsURI>>("validated-URIs", validated_uris, archive_in);
    parseAppsecJSONKey<string>("override-mode", override_mode, archive_in, "Inactive");
    if (valid_modes.count(override_mode) == 0) {
        dbgWarning(D_LOCAL_POLICY) << "AppSec Web Bots override mode invalid: " << override_mode;
    }
}

void
AppSecPracticeAntiBot::save(cereal::JSONOutputArchive &out_ar) const
{
    vector<string> injected;
    vector<string> validated;
    for (const AppSecWebBotsURI &uri : injected_uris) injected.push_back(uri.getURI());
    for (const AppSecWebBotsURI &uri : validated_uris) validated.push_back(uri.getURI());
    out_ar(
        cereal::make_nvp("injected", injected),
        cereal::make_nvp("validated", validated)
    );
}

void
AppSecWebAttackProtections::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec Web Attack Protections";
    parseAppsecJSONKey<string>("csrf-enabled", csrf_protection, archive_in, "inactive");
    parseAppsecJSONKey<string>("error-disclosure-enabled", error_disclosure, archive_in, "inactive");
    parseAppsecJSONKey<string>("open-redirect-enabled", open_redirect, archive_in, "inactive");
    parseAppsecJSONKey<bool>("non-valid-http-methods", non_valid_http_methods, archive_in, false);
}

const string
AppSecWebAttackProtections::getCsrfProtectionMode() const
{
    if (key_to_practices_val.find(csrf_protection) == key_to_practices_val.end()) {
        dbgError(D_LOCAL_POLICY)
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
        dbgError(D_LOCAL_POLICY)
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
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec practice spec";
    parseAppsecJSONKey<AppSecWebAttackProtections>("protections", protections, archive_in);
    parseAppsecJSONKey<string>("override-mode", mode, archive_in, "Unset");
    if (valid_modes.count(mode) == 0) {
        dbgWarning(D_LOCAL_POLICY) << "AppSec practice override mode invalid: " << mode;
    }

    if (getMode() == "Prevent") {
        parseAppsecJSONKey<string>("minimum-confidence", minimum_confidence, archive_in, "critical");
        if (valid_confidences.count(minimum_confidence) == 0) {
            dbgWarning(D_LOCAL_POLICY)
                << "AppSec practice override minimum confidence invalid: "
                << minimum_confidence;
        }
    } else {
        minimum_confidence = "Transparent";
    }
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
    if (mode == "Unset" || (key_to_practices_val2.find(mode) == key_to_practices_val2.end())) {
        dbgError(D_LOCAL_POLICY) << "Couldn't find a value for key: " << mode << ". Returning " << default_mode;
        return default_mode;
    }
    return key_to_practices_val2.at(mode);
}

void
AppSecPracticeSnortSignatures::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec Snort Signatures practice";
    parseAppsecJSONKey<string>("override-mode", override_mode, archive_in, "Inactive");
    parseAppsecJSONKey<vector<string>>("configmap", config_map, archive_in);
    if (valid_modes.count(override_mode) == 0) {
        dbgWarning(D_LOCAL_POLICY) << "AppSec Snort Signatures override mode invalid: " << override_mode;
    }
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
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec Practice OpenSchemaAPI practice";
    parseAppsecJSONKey<vector<string>>("configmap", config_map, archive_in);
    parseAppsecJSONKey<string>("override-mode", override_mode, archive_in, "Inactive");
    if (valid_modes.count(override_mode) == 0) {
        dbgWarning(D_LOCAL_POLICY) << "AppSec Open Schema API override mode invalid: " << override_mode;
    }
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

// LCOV_EXCL_STOP
void
AppSecPracticeSpec::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec practice spec";
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

void
AppSecPracticeSpec::setName(const string &_name)
{
    practice_name = _name;
}

// LCOV_EXCL_START Reason: no test exist
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

// LCOV_EXCL_STOP

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

ParsedMatch::ParsedMatch(const string &_operator, const string &_tag, const string &_value)
    :
    operator_type(_operator),
    tag(_tag),
    value(_value)
{
}

// LCOV_EXCL_START Reason: no test exist
ParsedMatch::ParsedMatch(const ExceptionMatch &exceptions)
{
    if (exceptions.getOperator() == "equals") {
        operator_type = "basic";
        tag = exceptions.getKey();
        value = exceptions.getValue();
    } else {
        operator_type = exceptions.getOperator();
    }
    for (const ExceptionMatch &exception_match : exceptions.getMatch()) {
        parsed_match.push_back(ParsedMatch(exception_match));
    }
}

// LCOV_EXCL_STOP

void
ParsedMatch::save(cereal::JSONOutputArchive &out_ar) const
{
    if (parsed_match.size() > 0) {
        out_ar(cereal::make_nvp("operator", operator_type));
        int i = 0;
        for (const ParsedMatch &operand : parsed_match) {
            i++;
            out_ar(cereal::make_nvp("operand" + to_string(i), operand));
        }
    } else {
        out_ar(
            cereal::make_nvp("operator",    operator_type),
            cereal::make_nvp("tag",         tag),
            cereal::make_nvp("value",       value)
        );
    }
}

AppSecOverride::AppSecOverride(const SourcesIdentifiers &parsed_trusted_sources)
{
    string source_ident = parsed_trusted_sources.getSourceIdent();
    map<string, string> behavior = {{"httpSourceId", source_ident}};
    parsed_behavior.push_back(behavior);
    parsed_match = ParsedMatch("BASIC", "sourceip", "0.0.0.0/0");
}

// LCOV_EXCL_START Reason: no test exist
AppSecOverride::AppSecOverride(const InnerException &parsed_exceptions)
    :
    id(parsed_exceptions.getBehaviorId()),
    parsed_match(parsed_exceptions.getMatch())
{
    map<string, string> behavior = {{parsed_exceptions.getBehaviorKey(), parsed_exceptions.getBehaviorValue()}};
    parsed_behavior.push_back(behavior);
}

// LCOV_EXCL_STOP

void
AppSecOverride::save(cereal::JSONOutputArchive &out_ar) const
{
    if (!id.empty()) {
        out_ar(cereal::make_nvp("id", id));
    }
    out_ar(
        cereal::make_nvp("parsedBehavior", parsed_behavior),
        cereal::make_nvp("parsedMatch",    parsed_match)
    );
}

void
AppsecPracticeAntiBotSection::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("injected", injected_uris),
        cereal::make_nvp("validated", validated_uris)
    );
}

// LCOV_EXCL_START Reason: no test exist
WebAppSection::WebAppSection(
    const string &_application_urls,
    const string &_asset_id,
    const string &_asset_name,
    const string &_rule_id,
    const string &_rule_name,
    const string &_practice_id,
    const string &_practice_name,
    const string &_context,
    const AppSecPracticeSpec &parsed_appsec_spec,
    const LogTriggerSection &parsed_log_trigger,
    const string &default_mode,
    const AppSecTrustedSources &parsed_trusted_sources,
    const vector<InnerException> &parsed_exceptions)
    :
    application_urls(_application_urls),
    asset_id(_asset_id),
    asset_name(_asset_name),
    rule_id(_rule_id),
    rule_name(_rule_name),
    practice_id(_practice_id),
    practice_name(_practice_name),
    context(_context),
    web_attack_mitigation_severity(parsed_appsec_spec.getWebAttacks().getMinimumConfidence()),
    web_attack_mitigation_mode(parsed_appsec_spec.getWebAttacks().getMode(default_mode)),
    practice_advanced_config(parsed_appsec_spec),
    anti_bots(parsed_appsec_spec.getAntiBot()),
    trusted_sources({ parsed_trusted_sources })
{
    web_attack_mitigation = web_attack_mitigation_mode != "Disabled";
    web_attack_mitigation_action =
        web_attack_mitigation_mode != "Prevent" ? "Transparent" :
        web_attack_mitigation_severity == "critical" ? "low" :
        web_attack_mitigation_severity == "high" ? "balanced" :
        web_attack_mitigation_severity == "medium" ? "high" :
        "Error";

    triggers.push_back(TriggersInWaapSection(parsed_log_trigger));
    for (const SourcesIdentifiers &source_ident : parsed_trusted_sources.getSourcesIdentifiers()) {
        overrides.push_back(AppSecOverride(source_ident));
    }

    for (const InnerException &exception : parsed_exceptions) {
        overrides.push_back(AppSecOverride(exception));
    }
}

WebAppSection::WebAppSection(
    const string &_application_urls,
    const string &_asset_id,
    const string &_asset_name,
    const string &_rule_id,
    const string &_rule_name,
    const string &_practice_id,
    const string &_practice_name,
    const string &_context,
    const string &_web_attack_mitigation_severity,
    const string &_web_attack_mitigation_mode,
    const PracticeAdvancedConfig &_practice_advanced_config,
    const AppsecPracticeAntiBotSection &_anti_bots,
    const LogTriggerSection &parsed_log_trigger,
    const AppSecTrustedSources &parsed_trusted_sources)
    :
    application_urls(_application_urls),
    asset_id(_asset_id),
    asset_name(_asset_name),
    rule_id(_rule_id),
    rule_name(_rule_name),
    practice_id(_practice_id),
    practice_name(_practice_name),
    context(_context),
    web_attack_mitigation_severity(_web_attack_mitigation_severity),
    web_attack_mitigation_mode(_web_attack_mitigation_mode),
    practice_advanced_config(_practice_advanced_config),
    anti_bots(_anti_bots),
    trusted_sources({ parsed_trusted_sources })
{
    web_attack_mitigation = web_attack_mitigation_mode != "Disabled";
    web_attack_mitigation_action =
        web_attack_mitigation_mode != "Prevent" ? "Transparent" :
        web_attack_mitigation_severity == "critical" ? "low" :
        web_attack_mitigation_severity == "high" ? "balanced" :
        web_attack_mitigation_severity == "medium" ? "high" :
        "Error";

    triggers.push_back(TriggersInWaapSection(parsed_log_trigger));
    for (const SourcesIdentifiers &source_ident : parsed_trusted_sources.getSourcesIdentifiers()) {
        overrides.push_back(AppSecOverride(source_ident));
    }
}

// LCOV_EXCL_STOP

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
        cereal::make_nvp("schemaValidation",               false),
        cereal::make_nvp("schemaValidation_v2",            disabled_str),
        cereal::make_nvp("oas",                            empty_list),
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

// LCOV_EXCL_START Reason: no test exist

bool
WebAppSection::operator<(const WebAppSection &other) const
{
    // for sorting from the most specific to the least specific rule
    if (application_urls == default_appsec_url) return false;
    if (other.application_urls == default_appsec_url) return true;
    return application_urls.size() > other.application_urls.size();
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

bool
WebAPISection::operator<(const WebAPISection &other) const
{
    // for sorting from the most specific to the least specific rule
    if (application_urls == default_appsec_url) return false;
    if (other.application_urls == default_appsec_url) return true;
    return application_urls.size() > other.application_urls.size();
}

// LCOV_EXCL_STOP

AppSecRulebase::AppSecRulebase(
    std::vector<WebAppSection> _webApplicationPractices,
    std::vector<WebAPISection> _webAPIPractices
) :
    webApplicationPractices(_webApplicationPractices),
    webAPIPractices(_webAPIPractices)
{
    sort(webAPIPractices.begin(), webAPIPractices.end());
    sort(webApplicationPractices.begin(), webApplicationPractices.end());
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
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec ParsedRule";
    parseAppsecJSONKey<vector<string>>("exceptions", exceptions, archive_in);
    parseAppsecJSONKey<vector<string>>("triggers", log_triggers, archive_in);
    parseAppsecJSONKey<vector<string>>("practices", practices, archive_in);
    parseAppsecJSONKey<string>("mode", mode, archive_in);
    if (valid_modes.count(mode) == 0) {
        dbgWarning(D_LOCAL_POLICY) << "AppSec Parsed Rule mode invalid: " << mode;
    }
    parseAppsecJSONKey<string>("custom-response", custom_response, archive_in);
    parseAppsecJSONKey<string>("source-identifiers", source_identifiers, archive_in);
    parseAppsecJSONKey<string>("trusted-sources", trusted_sources, archive_in);
    parseAppsecJSONKey<string>("upstream", rpm_upstream, archive_in);
    parseAppsecJSONKey<string>("rp-settings", rpm_settings, archive_in);
    parseAppsecJSONKey<bool>("ssl", rpm_is_ssl, archive_in);
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

const string &
ParsedRule::rpmGetUpstream() const
{
    return rpm_upstream;
}

const std::string &
ParsedRule::rpmGetRPSettings() const
{
    return rpm_settings;
}

bool
ParsedRule::rpmIsHttps() const
{
    return rpm_is_ssl;
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
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec policy spec";
    parseAppsecJSONKey<ParsedRule>("default", default_rule, archive_in);
    default_rule.setHost("*");
    parseAppsecJSONKey<vector<ParsedRule>>("specific-rules", specific_rules, archive_in);
}

const ParsedRule &
AppsecPolicySpec::getDefaultRule() const
{
    return default_rule;
}

const vector<ParsedRule> &
AppsecPolicySpec::getSpecificRules() const
{
    return specific_rules;
}

bool
AppsecPolicySpec::isAssetHostExist(const string &full_url) const
{
    for (const ParsedRule &rule : specific_rules) {
        if (rule.getHost() == full_url) return true;
    }
    return false;
}

void
AppsecPolicySpec::addSpecificRule(const ParsedRule &_rule)
{
    specific_rules.push_back(_rule);
}

void
AppsecLinuxPolicy::serialize(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading Appsec Linux Policy";
    parseAppsecJSONKey<AppsecPolicySpec>("policies", policies, archive_in);
    parseAppsecJSONKey<vector<RPMSettings>>("rp-settings", rpm_settings, archive_in);
    parseAppsecJSONKey<vector<AppSecPracticeSpec>>("practices", practices, archive_in);
    parseAppsecJSONKey<vector<AppsecTriggerSpec>>("log-triggers", log_triggers, archive_in);
    parseAppsecJSONKey<vector<AppSecCustomResponseSpec>>("custom-responses", custom_responses, archive_in);
    parseAppsecJSONKey<vector<AppsecException>>("exceptions", exceptions, archive_in);
    parseAppsecJSONKey<vector<TrustedSourcesSpec>>("trusted-sources", trusted_sources, archive_in);
    parseAppsecJSONKey<vector<SourceIdentifierSpecWrapper>>("source-identifiers", sources_identifiers, archive_in);
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

const vector<AppsecException> &
AppsecLinuxPolicy::getAppsecExceptions() const
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
    return sources_identifiers;
}

const vector<RPMSettings> &
AppsecLinuxPolicy::rpmGetRPSettings() const
{
    return rpm_settings;
}

void
AppsecLinuxPolicy::addSpecificRule(const ParsedRule &_rule)
{
    policies.addSpecificRule(_rule);
}
