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

#include "policy_maker_utils.h"

using namespace std;

USE_DEBUG_FLAG(D_NGINX_POLICY);

// LCOV_EXCL_START Reason: no test exist

void
SecurityAppsWrapper::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("waap",       waap),
        cereal::make_nvp("triggers",   trrigers),
        cereal::make_nvp("rules",      rules),
        cereal::make_nvp("exceptions", exceptions),
        cereal::make_nvp("version",    policy_version)
    );
}

void
PolicyWrapper::save(cereal::JSONOutputArchive &out_ar) const
{
    security_apps.save(out_ar);
}

string
PolicyMakerUtils::getPolicyName(const string &policy_path)
{
    if (policy_path.find_last_of("/") != string::npos) {
        string policy_name = policy_path.substr(policy_path.find_last_of("/") + 1);
        if (policy_name.find(".") != string::npos) return policy_name.substr(0, policy_name.find("."));
        return policy_name;
    }
    return policy_path;
}

Maybe<AppsecLinuxPolicy>
PolicyMakerUtils::openPolicyAsJson(const string &policy_path)
{
    auto maybe_policy_as_json = Singleton::Consume<I_ShellCmd>::by<PolicyMakerUtils>()->getExecOutput(
        getFilesystemPathConfig() + "/bin/yq " + policy_path + " -o json"
    );

    if (!maybe_policy_as_json.ok()) {
        dbgDebug(D_NGINX_POLICY) << "Could not convert policy from yaml to json";
        return genError("Could not convert policy from yaml to json. Error: " + maybe_policy_as_json.getErr());
    }

    auto i_orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<PolicyMakerUtils>();
    auto maybe_policy = i_orchestration_tools->jsonStringToObject<AppsecLinuxPolicy>(
        maybe_policy_as_json.unpack()
    );

    if (!maybe_policy.ok()) {
        string error = "Policy in path: " + policy_path + " was not loaded. Error: " + maybe_policy.getErr();
        dbgDebug(D_NGINX_POLICY) << error;
        return  genError(error);
    }
    return maybe_policy.unpack();
}

void
PolicyMakerUtils::clearElementsMaps()
{
    log_triggers.clear();
    web_user_res_triggers.clear();
    inner_exceptions.clear();
    web_apps.clear();
    rules_config.clear();
}

bool
PolicyMakerUtils::startsWith(const string &str, const string &prefix)
{
    return str.rfind(prefix, 0) == 0;
}

bool
PolicyMakerUtils::endsWith(const string &str, const string &suffix)
{
    return str.size() >= suffix.size() &&
        str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

tuple<string, string, string>
PolicyMakerUtils::splitHostName(const string &host_name)
{
    string url = host_name;
    string uri;
    string port;
    if (startsWith(url, "http://")) {
        url = url.substr(7, url.length() - 1);
        port = "80";
    } else if (startsWith(url, "https://")) {
        url = url.substr(8, url.length() - 1);
        port = "443";
    }

    if (url.find("/") != string::npos) {
        uri = url.substr(url.find("/"));
        url = url.substr(0, url.find("/"));
    } else {
        uri = "";
    }

    if (url.find(":") != string::npos) {
        port = url.substr(url.find(":") + 1, url.length() - 1);
        url = url.substr(0, url.find(":"));
    }

    if (host_name == "*") {
        url = "Any";
        uri = "Any";
    }
    return make_tuple(url, port, uri);
}

string
PolicyMakerUtils::dumpPolicyToFile(const PolicyWrapper &policy, const string &policy_path) const
{
    stringstream ss;
    {
        cereal::JSONOutputArchive ar(ss);
        policy.save(ar);
    }
    string policy_str = ss.str();
    dbgTrace(D_NGINX_POLICY) << "policy: " << policy_str;
    try {
        ofstream policy_file(policy_path);
        policy_file << policy_str;
        policy_file.close();
    } catch (const ofstream::failure &e) {
        dbgDebug(D_NGINX_POLICY) << "Error while writing new policy to " << policy_path << ", Error: " << e.what();
        return "";
    }
    return policy_str;
}

map<AnnotationTypes, string>
extractAnnotationsNames(
    const ParsedRule &parsed_rule,
    const ParsedRule &default_rule,
    const string &policy_name)
{
    map<AnnotationTypes, string> rule_annotation;
    string practice_annotation_name;
    // TBD: support multiple practices
    if (!parsed_rule.getPractices().empty() && !parsed_rule.getPractices()[0].empty()) {
        practice_annotation_name = parsed_rule.getPractices()[0];
    } else if (!default_rule.getPractices().empty() && !default_rule.getPractices()[0].empty()) {
        practice_annotation_name = default_rule.getPractices()[0];
    }

    if (!practice_annotation_name.empty()) {
        rule_annotation[AnnotationTypes::PRACTICE] = policy_name + "/" + practice_annotation_name;
    }

    string trigger_annotation_name;
    // TBD: support multiple triggers
    if (!parsed_rule.getLogTriggers().empty() && !parsed_rule.getLogTriggers()[0].empty()) {
        trigger_annotation_name = parsed_rule.getLogTriggers()[0];
    } else if (!default_rule.getLogTriggers().empty() && !default_rule.getLogTriggers()[0].empty()) {
        trigger_annotation_name = default_rule.getLogTriggers()[0];
    }

    if (!trigger_annotation_name.empty()) {
        rule_annotation[AnnotationTypes::TRIGGER] = policy_name + "/" + trigger_annotation_name;
    }

    string exception_annotation_name;
    // TBD: support multiple exceptions
    if (!parsed_rule.getExceptions().empty() && !parsed_rule.getExceptions()[0].empty()) {
        exception_annotation_name = parsed_rule.getExceptions()[0];
    } else if (!default_rule.getExceptions().empty() && !default_rule.getExceptions()[0].empty()) {
        exception_annotation_name = default_rule.getExceptions()[0];
    }

    if (!exception_annotation_name.empty()) {
        rule_annotation[AnnotationTypes::EXCEPTION] = policy_name + "/" + exception_annotation_name;
    }

    string web_user_res_annotation_name =
        parsed_rule.getCustomResponse().empty() ?
        default_rule.getCustomResponse() :
        parsed_rule.getCustomResponse();

    if (!web_user_res_annotation_name.empty()) {
        rule_annotation[AnnotationTypes::WEB_USER_RES] = policy_name + "/" + web_user_res_annotation_name;
    }

    string source_identifiers_annotation_name =
        parsed_rule.getSourceIdentifiers().empty() ?
        default_rule.getSourceIdentifiers() :
        parsed_rule.getSourceIdentifiers();

    if (!source_identifiers_annotation_name.empty()) {
        rule_annotation[AnnotationTypes::SOURCE_IDENTIFIERS] = policy_name + "/" + source_identifiers_annotation_name;
    }

    string trusted_sources_annotation_name =
        parsed_rule.getTrustedSources ().empty() ?
        default_rule.getTrustedSources() :
        parsed_rule.getTrustedSources();

    if (!trusted_sources_annotation_name.empty()) {
        rule_annotation[AnnotationTypes::TRUSTED_SOURCES] = policy_name + "/" + trusted_sources_annotation_name;
    }
    return rule_annotation;
}

template<class container_it>
container_it
extractElement(container_it begin, container_it end, const string &element_name)
{
    dbgTrace(D_NGINX_POLICY) << "Tryting to find element: " << element_name;
    string clean_element_name = element_name.substr(element_name.find("/") + 1);
    for (container_it it = begin; it < end; it++) {
        if (clean_element_name == it->getName()) {
            dbgTrace(D_NGINX_POLICY) << "Element with name " << clean_element_name << " was found";
            return it;
        }
    }
    dbgTrace(D_NGINX_POLICY) << "Element with name " << clean_element_name << " was not found";
    return end;
}

template<typename K, typename V>
vector<V>
convertMapToVector(map<K, V> map)
{
    vector<V> vec;
    vec.reserve(map.size());
    if (map.empty()) {
        return vec;
    }
    for (const auto &m : map) {
        if (!m.first.empty()) vec.push_back(m.second);
    }
    return vec;
}

AppSecPracticeSpec
getAppsecPracticeSpec(const string &practice_annotation_name, const AppsecLinuxPolicy &policy)
{
    auto practices_vec = policy.getAppSecPracticeSpecs();
    auto practice_it = extractElement(practices_vec.begin(), practices_vec.end(), practice_annotation_name);

    if (practice_it == practices_vec.end()) {
        dbgTrace(D_NGINX_POLICY) << "Failed to retrieve AppSec practice";
        return AppSecPracticeSpec();
    }
    return *practice_it;
}

AppsecTriggerSpec
getAppsecTriggerSpec(const string &trigger_annotation_name, const AppsecLinuxPolicy &policy)
{
    auto triggers_vec = policy.getAppsecTriggerSpecs();
    auto trigger_it = extractElement(triggers_vec.begin(), triggers_vec.end(), trigger_annotation_name);

    if (trigger_it == triggers_vec.end()) {
        dbgTrace(D_NGINX_POLICY) << "Failed to retrieve AppSec trigger";
        return AppsecTriggerSpec();
    }
    return *trigger_it;
}

AppsecExceptionSpec
getAppsecExceptionSpec(const string &exception_annotation_name, const AppsecLinuxPolicy &policy)
{
    auto exceptions_vec = policy.getAppsecExceptionSpecs();
    auto exception_it = extractElement(exceptions_vec.begin(), exceptions_vec.end(), exception_annotation_name);

    if (exception_it == exceptions_vec.end()) {
        dbgTrace(D_NGINX_POLICY) << "Failed to retrieve AppSec exception";
        return AppsecExceptionSpec();
    }
    return *exception_it;
}

AppSecCustomResponseSpec
getAppsecCustomResponseSpec(const string &custom_response_annotation_name, const AppsecLinuxPolicy &policy)
{
    auto custom_response_vec = policy.getAppSecCustomResponseSpecs();
    auto custom_response_it = extractElement(
        custom_response_vec.begin(),
        custom_response_vec.end(),
        custom_response_annotation_name);

    if (custom_response_it == custom_response_vec.end()) {
        dbgTrace(D_NGINX_POLICY) << "Failed to retrieve AppSec custom response";
        return AppSecCustomResponseSpec();
    }
    return *custom_response_it;
}

SourceIdentifierSpecWrapper
getAppsecSourceIdentifierSpecs(const string &source_identifiers_annotation_name, const AppsecLinuxPolicy &policy)
{
    auto source_identifiers_vec = policy.getAppsecSourceIdentifierSpecs();
    auto source_identifier_it = extractElement(
        source_identifiers_vec.begin(),
        source_identifiers_vec.end(),
        source_identifiers_annotation_name);

    if (source_identifier_it == source_identifiers_vec.end()) {
        dbgTrace(D_NGINX_POLICY) << "Failed to retrieve AppSec source identifier";
        return SourceIdentifierSpecWrapper();
    }
    return *source_identifier_it;
}

TrustedSourcesSpec
getAppsecTrustedSourceSpecs(const string &trusted_sources_annotation_name, const AppsecLinuxPolicy &policy)
{
    auto trusted_sources_vec = policy.getAppsecTrustedSourceSpecs();
    auto trusted_sources_it = extractElement(
        trusted_sources_vec.begin(),
        trusted_sources_vec.end(),
        trusted_sources_annotation_name);

    if (trusted_sources_it == trusted_sources_vec.end()) {
        dbgTrace(D_NGINX_POLICY) << "Failed to retrieve AppSec trusted source";
        return TrustedSourcesSpec();
    }
    return *trusted_sources_it;
}

LogTriggerSection
createLogTriggerSection(
    const string &trigger_annotation_name,
    const AppsecLinuxPolicy &policy)
{
    AppsecTriggerSpec trigger_spec = getAppsecTriggerSpec(trigger_annotation_name, policy);

    string verbosity = "Standard";
    string extendLoggingMinSeverity =
        trigger_spec.getAppsecTriggerAdditionalSuspiciousEventsLogging().getMinimumSeverity();
    bool tpDetect = trigger_spec.getAppsecTriggerLogging().isDetectEvents();
    bool tpPrevent = trigger_spec.getAppsecTriggerLogging().isPreventEvents();
    bool webRequests = trigger_spec.getAppsecTriggerLogging().isAllWebRequests();
    bool webUrlPath = trigger_spec.getAppsecTriggerExtendedLogging().isUrlPath();
    bool webUrlQuery = trigger_spec.getAppsecTriggerExtendedLogging().isUrlQuery();
    bool webHeaders = trigger_spec.getAppsecTriggerExtendedLogging().isHttpHeaders();
    bool webBody = trigger_spec.getAppsecTriggerExtendedLogging().isRequestBody();
    bool logToCloud = trigger_spec.getAppsecTriggerLogDestination().getCloud();
    bool logToAgent = trigger_spec.getAppsecTriggerLogDestination().isAgentLocal();
    bool beautify_logs = trigger_spec.getAppsecTriggerLogDestination().shouldBeautifyLogs();
    bool logToCef = trigger_spec.getAppsecTriggerLogDestination().isCefNeeded();
    bool logToSyslog = trigger_spec.getAppsecTriggerLogDestination().isSyslogNeeded();
    bool responseBody = trigger_spec.getAppsecTriggerAdditionalSuspiciousEventsLogging().isResponseBody();
    bool extendLogging = trigger_spec.getAppsecTriggerAdditionalSuspiciousEventsLogging().isEnabled();
    int cefPortNum = logToCef ? trigger_spec.getAppsecTriggerLogDestination().getCefServerUdpPort() : 0;
    string cefIpAddress =
        logToCef ? trigger_spec.getAppsecTriggerLogDestination().getCefServerIpv4Address() : "";
    int syslogPortNum =
        logToSyslog ?
        trigger_spec.getAppsecTriggerLogDestination().getSyslogServerUdpPort() :
        514;
    string syslogIpAddress =
        logToSyslog ?
        trigger_spec.getAppsecTriggerLogDestination().getSyslogServerIpv4Address() :
        "";

    LogTriggerSection log(
        trigger_annotation_name,
        verbosity,
        extendLoggingMinSeverity,
        extendLogging,
        logToAgent,
        logToCef,
        logToCloud,
        logToSyslog,
        responseBody,
        tpDetect,
        tpPrevent,
        webBody,
        webHeaders,
        webRequests,
        webUrlPath,
        webUrlQuery,
        cefPortNum,
        cefIpAddress,
        syslogPortNum,
        syslogIpAddress,
        beautify_logs
    );
    return log;
}

WebUserResponseTriggerSection
createWebUserResponseTriggerSection(
    const string &web_user_res_annotation_name,
    const AppsecLinuxPolicy &policy)
{
    AppSecCustomResponseSpec web_user_res_spec = getAppsecCustomResponseSpec(web_user_res_annotation_name, policy);
    string mode = web_user_res_spec.getMode();
    string response_body = web_user_res_spec.getMessageBody();
    string response_title = web_user_res_spec.getMessageTitle();
    int response_code = web_user_res_spec.getHttpResponseCode();

    WebUserResponseTriggerSection web_user_res(
        web_user_res_annotation_name,
        mode,
        response_body,
        response_code,
        response_title
    );

    return web_user_res;
}

vector<SourcesIdentifiers>
addSourceIdentifiersToTrustedSource(
    const string &source_identifeir_from_trust,
    const SourceIdentifierSpec &src_ident
)
{
    vector<SourcesIdentifiers> generated_trusted_json;
    if (src_ident.getValues().empty()) {
        generated_trusted_json.push_back(
            SourcesIdentifiers(src_ident.getSourceIdentifier(), source_identifeir_from_trust)
        );
    } else {
        for (const string &val : src_ident.getValues()) {
            string src_key = src_ident.getSourceIdentifier() + ":" + val;
            generated_trusted_json.push_back(SourcesIdentifiers(src_key, source_identifeir_from_trust));
        }
    }

    return generated_trusted_json;
}

AppSecTrustedSources
createTrustedSourcesSection(
    const string &treusted_sources_annotation_name,
    const string &source_identifier_annotation_name,
    const AppsecLinuxPolicy &policy)
{
    TrustedSourcesSpec treusted_sources_spec = getAppsecTrustedSourceSpecs(treusted_sources_annotation_name, policy);
    SourceIdentifierSpecWrapper source_identifiers_spec = getAppsecSourceIdentifierSpecs(
        source_identifier_annotation_name,
        policy
    );

    vector<SourcesIdentifiers> generated_trusted_json;
    for (const SourceIdentifierSpec &src_ident : source_identifiers_spec.getIdentifiers()) {
        for (const string &source_identifeir_from_trust : treusted_sources_spec.getSourcesIdentifiers()) {
            vector<SourcesIdentifiers> tmp_trusted = addSourceIdentifiersToTrustedSource(
                source_identifeir_from_trust,
                src_ident
            );
            generated_trusted_json.insert(generated_trusted_json.end(), tmp_trusted.begin(), tmp_trusted.end());
        }
    }

    AppSecTrustedSources treusted_sources(
        treusted_sources_spec.getName(),
        treusted_sources_spec.getMinNumOfSources(),
        generated_trusted_json
    );

    return treusted_sources;
}

InnerException
createExceptionSection(
    const string &exception_annotation_name,
    const AppsecLinuxPolicy &policy)
{
    AppsecExceptionSpec exception_spec = getAppsecExceptionSpec(exception_annotation_name, policy);
    ExceptionMatch exception_match(exception_spec);
    string behavior =
        exception_spec.getAction() == "skip" ?
        "ignore" :
        exception_spec.getAction();
    ExceptionBehavior exception_behavior("action", behavior);
    InnerException inner_exception(exception_behavior, exception_match);
    return inner_exception;
}

UsersIdentifiersRulebase
createUserIdentifiers (
    const string &source_identifier_annotation_name,
    const AppsecLinuxPolicy &policy,
    const string &context
)
{
    string jwt_identifier = "";
    vector<string> jwt_identifier_values;
    vector<UsersIdentifier> user_ident_vec;
    SourceIdentifierSpecWrapper source_identifiers_spec = getAppsecSourceIdentifierSpecs(
        source_identifier_annotation_name,
        policy
    );

    for (const SourceIdentifierSpec &src_ident : source_identifiers_spec.getIdentifiers()) {
        if (src_ident.getSourceIdentifier() == "JWTKey") {
            jwt_identifier = "JWTKey";
            jwt_identifier_values.insert(
                jwt_identifier_values.end(),
                src_ident.getValues().begin(),
                src_ident.getValues().end()
            );
            user_ident_vec.push_back(UsersIdentifier("authorization", src_ident.getValues()));
        } else {
            user_ident_vec.push_back(UsersIdentifier(src_ident.getSourceIdentifier(), src_ident.getValues()));
        }
    }
    UsersIdentifiersRulebase users_ident = UsersIdentifiersRulebase(
        context,
        jwt_identifier,
        jwt_identifier_values,
        user_ident_vec
    );

    return users_ident;
}

RulesConfigRulebase
createMultiRulesSections(
    const string &url,
    const string &uri,
    const string &practice_id,
    const string &practice_name,
    const string &practice_type,
    const string &log_trigger_name,
    const string &log_trigger_id,
    const string &log_trigger_type,
    const string &web_user_res_vec_name,
    const string &web_user_res_vec_id,
    const string &web_user_res_vec_type,
    const string &asset_name,
    const string &exception_name,
    const string &exception_id)
{
    PracticeSection practice = PracticeSection(practice_id, practice_type, practice_name);
    ParametersSection exception_param = ParametersSection(exception_id, exception_name);

    vector<RulesTriggerSection> triggers;
    if (!log_trigger_id.empty()) {
        triggers.push_back(RulesTriggerSection(log_trigger_name, log_trigger_id, log_trigger_type));
    }
    if (!web_user_res_vec_id.empty()) {
        triggers.push_back(RulesTriggerSection(
            web_user_res_vec_name,
            web_user_res_vec_id,
            web_user_res_vec_type)
        );
    }

    RulesConfigRulebase rules_config = RulesConfigRulebase(
        asset_name,
        url,
        uri,
        {practice},
        {exception_param},
        triggers
    );

    return rules_config;
}

SettingsWrapper
createProfilesSection()
{
    string agent_settings_key = "agent.test.policy";
    string agent_settings_value = "local policy";
    AgentSettingsSection agent_setting_1 = AgentSettingsSection(agent_settings_key, agent_settings_value);

    SettingsRulebase settings_rulebase_1 = SettingsRulebase({agent_setting_1});
    return SettingsWrapper(settings_rulebase_1);
}

PolicyWrapper
PolicyMakerUtils::combineElementsToPolicy(const string &policy_version)
{
    TriggersWrapper triggers_section(
        TriggersRulebase(
            convertMapToVector(log_triggers), convertMapToVector(web_user_res_triggers)
        )
    );
    ExceptionsWrapper exceptions_section({
        ExceptionsRulebase(convertMapToVector(inner_exceptions))
    });

    AppSecWrapper appses_section(AppSecRulebase(convertMapToVector(web_apps), {}));
    RulesConfigWrapper rules_config_section(convertMapToVector(rules_config), convertMapToVector(users_identifiers));
    SecurityAppsWrapper security_app_section = SecurityAppsWrapper(
        appses_section,
        triggers_section,
        rules_config_section,
        exceptions_section,
        policy_version
    );

    SettingsWrapper profiles_section = createProfilesSection();
    PolicyWrapper policy_wrapper = PolicyWrapper(profiles_section, security_app_section);

    return policy_wrapper;
}

void
PolicyMakerUtils::createPolicyElementsByRule(
    const ParsedRule &rule,
    const ParsedRule &default_rule,
    const AppsecLinuxPolicy &policy,
    const string &policy_name)
{
    map<AnnotationTypes, string> rule_annotations = extractAnnotationsNames(rule, default_rule, policy_name);
    if (
        !rule_annotations[AnnotationTypes::TRIGGER].empty() &&
        !log_triggers.count(rule_annotations[AnnotationTypes::TRIGGER])
    ) {
        log_triggers[rule_annotations[AnnotationTypes::TRIGGER]] =
            createLogTriggerSection(
                rule_annotations[AnnotationTypes::TRIGGER],
                policy
            );
    }

    if (
        !rule_annotations[AnnotationTypes::WEB_USER_RES].empty() &&
        !web_user_res_triggers.count(rule_annotations[AnnotationTypes::WEB_USER_RES])
    ) {
        web_user_res_triggers[rule_annotations[AnnotationTypes::WEB_USER_RES]] =
            createWebUserResponseTriggerSection(
                rule_annotations[AnnotationTypes::WEB_USER_RES],
                policy
            );
    }

    if (
        !rule_annotations[AnnotationTypes::EXCEPTION].empty() &&
        !inner_exceptions.count(rule_annotations[AnnotationTypes::EXCEPTION])
    ) {
        inner_exceptions[rule_annotations[AnnotationTypes::EXCEPTION]] =
            createExceptionSection(
                rule_annotations[AnnotationTypes::EXCEPTION],
                policy
            );
    }

    if (
        !rule_annotations[AnnotationTypes::TRUSTED_SOURCES].empty() &&
        !rule_annotations[AnnotationTypes::SOURCE_IDENTIFIERS].empty() &&
        !trusted_sources.count(rule_annotations[AnnotationTypes::TRUSTED_SOURCES])
    ) {
        trusted_sources[rule_annotations[AnnotationTypes::TRUSTED_SOURCES]] =
            createTrustedSourcesSection(
                rule_annotations[AnnotationTypes::TRUSTED_SOURCES],
                rule_annotations[AnnotationTypes::SOURCE_IDENTIFIERS],
                policy
            );
    }

    if (
        !rule_annotations[AnnotationTypes::PRACTICE].empty() &&
        !web_apps.count(rule_annotations[AnnotationTypes::PRACTICE])
    ) {
            string practice_id = "";
            try {
                practice_id = to_string(boost::uuids::random_generator()());
            } catch (const boost::uuids::entropy_error &e) {
                //TBD: return Maybe as part of future error handling
            }
            tuple<string, string, string> splited_host_name = splitHostName(rule.getHost());
            string full_url = rule.getHost() == "*"
                ? "Any"
                : rule.getHost();


            RulesConfigRulebase rule_config = createMultiRulesSections(
                std::get<0>(splited_host_name),
                std::get<2>(splited_host_name),
                practice_id,
                rule_annotations[AnnotationTypes::PRACTICE],
                "WebApplication",
                rule_annotations[AnnotationTypes::TRIGGER],
                log_triggers[rule_annotations[AnnotationTypes::TRIGGER]].getTriggerId(),
                "log",
                rule_annotations[AnnotationTypes::WEB_USER_RES],
                web_user_res_triggers[rule_annotations[AnnotationTypes::WEB_USER_RES]].getTriggerId(),
                "WebUserResponse",
                full_url,
                rule_annotations[AnnotationTypes::EXCEPTION],
                inner_exceptions[rule_annotations[AnnotationTypes::EXCEPTION]].getBehaviorId()
            );
            rules_config[rule_config.getAssetName()] = rule_config;

            if (!rule_annotations[AnnotationTypes::SOURCE_IDENTIFIERS].empty()) {
                UsersIdentifiersRulebase user_identifiers = createUserIdentifiers(
                    rule_annotations[AnnotationTypes::SOURCE_IDENTIFIERS],
                    policy,
                    rule_config.getContext()
                );
                users_identifiers[rule_annotations[AnnotationTypes::SOURCE_IDENTIFIERS]] = user_identifiers;
            }

            WebAppSection web_app = WebAppSection(
                full_url == "Any" ? "" : full_url,
                rule_config.getAssetId(),
                rule_config.getAssetName(),
                rule_config.getAssetId(),
                rule_config.getAssetName(),
                practice_id,
                rule_annotations[AnnotationTypes::PRACTICE],
                getAppsecPracticeSpec(rule_annotations[AnnotationTypes::PRACTICE], policy),
                log_triggers[rule_annotations[AnnotationTypes::TRIGGER]],
                rule.getMode(),
                trusted_sources[rule_annotations[AnnotationTypes::TRUSTED_SOURCES]]
            );
            web_apps[rule_annotations[AnnotationTypes::PRACTICE]] = web_app;
        }
}

void
PolicyMakerUtils::createPolicyElements(
    const vector<ParsedRule> &rules,
    const ParsedRule &default_rule,
    const AppsecLinuxPolicy &policy,
    const string &policy_name)
{
    for (const ParsedRule &rule : rules) {
        createPolicyElementsByRule(rule, default_rule, policy, policy_name);
    }
}

// LCOV_EXCL_STOP
