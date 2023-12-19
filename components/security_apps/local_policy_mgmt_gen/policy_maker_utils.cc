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

#include <regex>

#include "local_policy_mgmt_gen.h"
#include "log_generator.h"

using namespace std;

USE_DEBUG_FLAG(D_NGINX_POLICY);

void
SecurityAppsWrapper::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("accessControlV2",     rate_limit),
        cereal::make_nvp("waap",                waap),
        cereal::make_nvp("triggers",            trrigers),
        cereal::make_nvp("rules",               rules),
        cereal::make_nvp("ips",                 ips),
        cereal::make_nvp("exceptions",          exceptions),
        cereal::make_nvp("snort",               snort),
        cereal::make_nvp("fileSecurity",        file_security),
        cereal::make_nvp("version",             policy_version)
    );
}

string
PolicyMakerUtils::getPolicyName(const string &policy_path)
{
    string policy_name;
    if (policy_path.find_last_of("/") != string::npos) {
        policy_name = policy_path.substr(policy_path.find_last_of("/") + 1);
    } else {
        policy_name = policy_path;
    }
    if (policy_name.find(".") != string::npos) {
        return policy_name.substr(0, policy_name.find("."));
    }
    return policy_name;
}

template<class T>
Maybe<T>
PolicyMakerUtils::openFileAsJson(const string &path)
{
    auto maybe_file_as_json = Singleton::Consume<I_ShellCmd>::by<LocalPolicyMgmtGenerator>()->getExecOutput(
        getFilesystemPathConfig() + "/bin/yq " + path + " -o json"
    );

    if (!maybe_file_as_json.ok()) {
        dbgDebug(D_NGINX_POLICY) << "Could not convert policy from yaml to json";
        return genError("Could not convert policy from yaml to json. Error: " + maybe_file_as_json.getErr());
    }

    auto i_orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<LocalPolicyMgmtGenerator>();
    auto maybe_file = i_orchestration_tools->jsonStringToObject<T>(
        maybe_file_as_json.unpack()
    );

    if (!maybe_file.ok()) {
        string error = "Policy in path: " + path + " was not loaded. Error: " + maybe_file.getErr();
        dbgDebug(D_NGINX_POLICY) << error;
        return  genError(error);
    }
    return maybe_file.unpack();
}

void
PolicyMakerUtils::clearElementsMaps()
{
    log_triggers.clear();
    web_user_res_triggers.clear();
    inner_exceptions.clear();
    web_apps.clear();
    rules_config.clear();
    ips.clear();
    snort.clear();
    snort_protections.clear();
    file_security.clear();
    rate_limit.clear();
}

// LCOV_EXCL_START Reason: no test exist - needed for NGINX config
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
// LCOV_EXCL_STOP

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

    if (host_name == "*" || host_name == "*:*") {
        url = "Any";
        uri = "Any";
    }

    return make_tuple(url, port, uri);
}

string
PolicyMakerUtils::dumpPolicyToFile(
    const PolicyWrapper &policy,
    const string &policy_path,
    const string &settings_path)
{
    clearElementsMaps();

    stringstream policy_ss, settings_ss;
    {
        cereal::JSONOutputArchive ar(policy_ss);
        policy.getSecurityApps().save(ar);
    }
    string policy_str = policy_ss.str();
    try {
        ofstream policy_file(policy_path);
        policy_file << policy_str;
        policy_file.close();
    } catch (const ofstream::failure &e) {
        dbgDebug(D_NGINX_POLICY) << "Error while writing new policy to " << policy_path << ", Error: " << e.what();
        return "";
    }

    {
        cereal::JSONOutputArchive ar(settings_ss);
        policy.getSettings().save(ar);
    }
    string settings_str = settings_ss.str();
    try {
        ofstream settings_file(settings_path);
        settings_file << settings_str;
        settings_file.close();
    } catch (const ofstream::failure &e) {
        dbgDebug(D_NGINX_POLICY) << "Error while writing settings to " << settings_path << ", Error: " << e.what();
    }
    dbgDebug(D_LOCAL_POLICY) << settings_path << " content: " << settings_str;

    return policy_str;
}

template<class R>
map<AnnotationTypes, string>
extractAnnotationsNames(
    const R &parsed_rule,
    const R &default_rule,
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

// LCOV_EXCL_START Reason: no test exist
template<>
map<AnnotationTypes, string>
extractAnnotationsNames<NewParsedRule>(
    const NewParsedRule &parsed_rule,
    const NewParsedRule &default_rule,
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

    string access_control_practice_name;
    // TBD: support multiple practices
    if (!parsed_rule.getAccessControlPractices().empty() && !parsed_rule.getAccessControlPractices()[0].empty()) {
        access_control_practice_name = parsed_rule.getAccessControlPractices()[0];
    } else if ( !default_rule.getAccessControlPractices().empty() &&
                !default_rule.getAccessControlPractices()[0].empty()) {
        access_control_practice_name = default_rule.getAccessControlPractices()[0];
    }

    if (!access_control_practice_name.empty()) {
        rule_annotation[AnnotationTypes::ACCESS_CONTROL_PRACTICE] = policy_name + "/" + access_control_practice_name;
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
// LCOV_EXCL_STOP

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

vector<InnerException>
convertExceptionsMapToVector(map<string, vector<InnerException>> map)
{
    vector<InnerException> vec;
    if (map.empty()) {
        return vec;
    }
    for (const auto &m : map) {
        if (!m.first.empty()) vec.insert(vec.end(), m.second.begin(), m.second.end());
    }
    return vec;
}

template<class T, class R>
R
getAppsecPracticeSpec(const string &practice_annotation_name, const T &policy)
{
    auto practices_vec = policy.getAppSecPracticeSpecs();
    auto practice_it = extractElement(practices_vec.begin(), practices_vec.end(), practice_annotation_name);

    if (practice_it == practices_vec.end()) {
        dbgTrace(D_NGINX_POLICY) << "Failed to retrieve AppSec practice";
        return R();
    }
    return *practice_it;
}

// LCOV_EXCL_START Reason: no test exist
AccessControlPracticeSpec
getAccessControlPracticeSpec()
{
    return AccessControlPracticeSpec();
}

AccessControlPracticeSpec
getAccessControlPracticeSpec(const string &practice_annotation_name, const V1beta2AppsecLinuxPolicy &policy)
{
    auto practices_vec = policy.getAccessControlPracticeSpecs();
    auto practice_it = extractElement(practices_vec.begin(), practices_vec.end(), practice_annotation_name);

    if (practice_it == practices_vec.end()) {
        dbgTrace(D_NGINX_POLICY) << "Failed to retrieve Access control practice";
        return AccessControlPracticeSpec();
    }
    return *practice_it;
}
// LCOV_EXCL_STOP

template<class T, class R>
R
getAppsecTriggerSpec(const string &trigger_annotation_name, const T &policy)
{
    auto triggers_vec = policy.getAppsecTriggerSpecs();
    auto trigger_it = extractElement(triggers_vec.begin(), triggers_vec.end(), trigger_annotation_name);

    if (trigger_it == triggers_vec.end()) {
        dbgTrace(D_NGINX_POLICY) << "Failed to retrieve AppSec trigger";
        return R();
    }
    return *trigger_it;
}

template<class T, class R>
R
getAppsecExceptionSpec(const string &exception_annotation_name, const T &policy)
{
    auto exceptions_vec = policy.getAppsecExceptions();
    auto exception_it = extractElement(exceptions_vec.begin(), exceptions_vec.end(), exception_annotation_name);

    if (exception_it == exceptions_vec.end()) {
        dbgTrace(D_NGINX_POLICY) << "Failed to retrieve AppSec exception";
        return R();
    }
    return *exception_it;
}

template<class T, class R>
R
getAppsecCustomResponseSpec(const string &custom_response_annotation_name, const T &policy)
{
    auto custom_response_vec = policy.getAppSecCustomResponseSpecs();
    auto custom_response_it = extractElement(
        custom_response_vec.begin(),
        custom_response_vec.end(),
        custom_response_annotation_name);

    if (custom_response_it == custom_response_vec.end()) {
        dbgTrace(D_NGINX_POLICY) << "Failed to retrieve AppSec custom response";
        return R();
    }
    return *custom_response_it;
}

template<class T, class R>
R
rpmGetAppsecRPSettingSpec(const string &rp_settings_name, const T &policy)
{
    auto rp_settings_vec = policy.rpmGetRPSettings();
    auto rp_settings_it = extractElement(
        rp_settings_vec.begin(),
        rp_settings_vec.end(),
        rp_settings_name);

    if (rp_settings_it == rp_settings_vec.end()) {
        dbgTrace(D_NGINX_POLICY) << "Failed to retrieve AppSec RP Settings";
        return R();
    }
    return *rp_settings_it;
}

template<class T, class R>
R
getAppsecSourceIdentifierSpecs(const string &source_identifiers_annotation_name, const T &policy)
{
    auto source_identifiers_vec = policy.getAppsecSourceIdentifierSpecs();
    auto source_identifier_it = extractElement(
        source_identifiers_vec.begin(),
        source_identifiers_vec.end(),
        source_identifiers_annotation_name);

    if (source_identifier_it == source_identifiers_vec.end()) {
        dbgTrace(D_NGINX_POLICY) << "Failed to retrieve AppSec source identifier";
        return R();
    }
    return *source_identifier_it;
}

template<class T, class R>
R
getAppsecTrustedSourceSpecs(const string &trusted_sources_annotation_name, const T &policy)
{
    auto trusted_sources_vec = policy.getAppsecTrustedSourceSpecs();
    auto trusted_sources_it = extractElement(
        trusted_sources_vec.begin(),
        trusted_sources_vec.end(),
        trusted_sources_annotation_name);

    if (trusted_sources_it == trusted_sources_vec.end()) {
        dbgTrace(D_NGINX_POLICY) << "Failed to retrieve AppSec trusted source";
        return R();
    }
    return *trusted_sources_it;
}

template<class T>
LogTriggerSection
extractLogTriggerData(const string &trigger_annotation_name, const T &trigger_spec){
    string verbosity = "Standard";
    string extendLoggingMinSeverity =
        trigger_spec.getAppsecTriggerAdditionalSuspiciousEventsLogging().getMinimumSeverity();
    bool tpDetect = trigger_spec.getAppsecTriggerLogging().isDetectEvents();
    bool tpPrevent = trigger_spec.getAppsecTriggerLogging().isPreventEvents();
    bool acAllow = trigger_spec.getAppsecTriggerAccessControlLogging().isAcAllowEvents();
    bool acDrop = trigger_spec.getAppsecTriggerAccessControlLogging().isAcDropEvents();
    bool webRequests = trigger_spec.getAppsecTriggerLogging().isAllWebRequests();
    bool webUrlPath = trigger_spec.getAppsecTriggerExtendedLogging().isUrlPath();
    bool webUrlQuery = trigger_spec.getAppsecTriggerExtendedLogging().isUrlQuery();
    bool webHeaders = trigger_spec.getAppsecTriggerExtendedLogging().isHttpHeaders();
    bool webBody = trigger_spec.getAppsecTriggerExtendedLogging().isRequestBody();
    bool logToCloud = trigger_spec.getAppsecTriggerLogDestination().getCloud();
    bool logToK8sService = trigger_spec.getAppsecTriggerLogDestination().isK8SNeeded();
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
        logToK8sService,
        logToSyslog,
        responseBody,
        tpDetect,
        tpPrevent,
        acAllow,
        acDrop,
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

// LCOV_EXCL_START Reason: no test exist
template<class T>
LogTriggerSection
createLogTriggerSection(
    const string &trigger_annotation_name,
    const T &policy)
{
    auto trigger_spec = getAppsecTriggerSpec<T, AppsecTriggerSpec>(trigger_annotation_name, policy);
    return extractLogTriggerData<AppsecTriggerSpec>(trigger_annotation_name, trigger_spec);
}

template<>
LogTriggerSection
createLogTriggerSection<V1beta2AppsecLinuxPolicy>(
    const string &trigger_annotation_name,
    const V1beta2AppsecLinuxPolicy &policy)
{
    auto trigger_spec =
        getAppsecTriggerSpec<V1beta2AppsecLinuxPolicy, NewAppsecLogTrigger>(trigger_annotation_name, policy);
    return extractLogTriggerData<NewAppsecLogTrigger>(trigger_annotation_name, trigger_spec);
}

template<class T>
WebUserResponseTriggerSection
extractWebUserResponseTriggerSectionrData
(
    const string &web_user_res_annotation_name,
    const T &web_user_res_spec)
{
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

template<class T>
WebUserResponseTriggerSection
createWebUserResponseTriggerSection(
    const string &web_user_res_annotation_name,
    const T &policy)
{
    auto web_user_res_spec =
        getAppsecCustomResponseSpec<T, AppSecCustomResponseSpec>(web_user_res_annotation_name, policy);
    return extractLogTriggerData<AppSecCustomResponseSpec>(web_user_res_annotation_name, web_user_res_spec);
}

template<>
WebUserResponseTriggerSection
createWebUserResponseTriggerSection<AppsecLinuxPolicy>(
    const string &web_user_res_annotation_name,
    const AppsecLinuxPolicy &policy)
{
    auto web_user_res_spec =
        getAppsecCustomResponseSpec<AppsecLinuxPolicy, AppSecCustomResponseSpec>(web_user_res_annotation_name, policy);
    return extractWebUserResponseTriggerSectionrData<AppSecCustomResponseSpec>(
                web_user_res_annotation_name,
                web_user_res_spec
            );
}

template<>
WebUserResponseTriggerSection
createWebUserResponseTriggerSection<V1beta2AppsecLinuxPolicy>(
    const string &web_user_res_annotation_name,
    const V1beta2AppsecLinuxPolicy &policy)
{
    auto web_user_res_spec =
        getAppsecCustomResponseSpec<V1beta2AppsecLinuxPolicy, NewAppSecCustomResponse>(
            web_user_res_annotation_name,
            policy
        );
    return extractWebUserResponseTriggerSectionrData<NewAppSecCustomResponse>(
                web_user_res_annotation_name,
                web_user_res_spec
            );
}

vector<SourcesIdentifiers>
addSourceIdentifiersToTrustedSource(
    const string &source_identifeir_from_trust,
    const vector<string> &values,
    const string &source_identifer
)
{
    vector<SourcesIdentifiers> generated_trusted_json;
    if (values.empty()) {
        generated_trusted_json.push_back(
            SourcesIdentifiers(source_identifer, source_identifeir_from_trust)
        );
    } else {
        for (const string &val : values) {
            string src_key = source_identifer + ":" + val;
            generated_trusted_json.push_back(SourcesIdentifiers(src_key, source_identifeir_from_trust));
        }
    }

    return generated_trusted_json;
}

template<class T>
AppSecTrustedSources
createTrustedSourcesSection(
    const string &treusted_sources_annotation_name,
    const string &source_identifier_annotation_name,
    const T &policy)
{
    TrustedSourcesSpec treusted_sources_spec =
        getAppsecTrustedSourceSpecs<T, TrustedSourcesSpec>(treusted_sources_annotation_name, policy);
    SourceIdentifierSpecWrapper source_identifiers_spec =
        getAppsecSourceIdentifierSpecs<T, SourceIdentifierSpecWrapper>(
            source_identifier_annotation_name,
            policy
        );

    vector<SourcesIdentifiers> generated_trusted_json;
    for (const SourceIdentifierSpec &src_ident : source_identifiers_spec.getIdentifiers()) {
        for (const string &source_identifeir_from_trust : treusted_sources_spec.getSourcesIdentifiers()) {
            vector<SourcesIdentifiers> tmp_trusted = addSourceIdentifiersToTrustedSource(
                source_identifeir_from_trust,
                src_ident.getValues(),
                src_ident.getSourceIdentifier()
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

template<>
AppSecTrustedSources
createTrustedSourcesSection<V1beta2AppsecLinuxPolicy>(
    const string &treusted_sources_annotation_name,
    const string &source_identifier_annotation_name,
    const V1beta2AppsecLinuxPolicy &policy)
{
    NewTrustedSourcesSpec treusted_sources_spec =
        getAppsecTrustedSourceSpecs<V1beta2AppsecLinuxPolicy, NewTrustedSourcesSpec>(
            treusted_sources_annotation_name,
            policy
        );
    NewSourcesIdentifiers source_identifiers_spec =
        getAppsecSourceIdentifierSpecs<V1beta2AppsecLinuxPolicy, NewSourcesIdentifiers>(
            source_identifier_annotation_name,
            policy
        );

    vector<SourcesIdentifiers> generated_trusted_json;
    for (const Identifier &src_ident : source_identifiers_spec.getSourcesIdentifiers()) {
        for (const string &source_identifeir_from_trust : treusted_sources_spec.getSourcesIdentifiers()) {
            vector<SourcesIdentifiers> tmp_trusted = addSourceIdentifiersToTrustedSource(
                source_identifeir_from_trust,
                src_ident.getValues(),
                src_ident.getIdentifier()
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

template<class T>
vector<InnerException>
createExceptionSection(
    const string &exception_annotation_name,
    const T &policy)
{
    AppsecException exception_spec =
        getAppsecExceptionSpec<T, AppsecException>(exception_annotation_name, policy);
    vector<InnerException> res;
    for (auto exception : exception_spec.getExceptions()) {
        ExceptionMatch exception_match(exception);
        ExceptionBehavior exception_behavior(exception.getAction());
        res.push_back(InnerException(exception_behavior, exception_match));
    }
    return res;
}

template<>
vector<InnerException>
createExceptionSection<V1beta2AppsecLinuxPolicy>(
    const string &exception_annotation_name,
    const V1beta2AppsecLinuxPolicy &policy)
{
    NewAppsecException exception_spec =
        getAppsecExceptionSpec<V1beta2AppsecLinuxPolicy, NewAppsecException>(exception_annotation_name, policy);
    ExceptionMatch exception_match(exception_spec);
    ExceptionBehavior exception_behavior(exception_spec.getAction());
    InnerException inner_exception(exception_behavior, exception_match);
    return {inner_exception};
}

template<class T>
UsersIdentifiersRulebase
createUserIdentifiers(
    const string &source_identifier_annotation_name,
    const T &policy,
    const string &context
)
{
    string jwt_identifier = "";
    vector<string> jwt_identifier_values;
    vector<UsersIdentifier> user_ident_vec;
    SourceIdentifierSpecWrapper source_identifiers_spec =
        getAppsecSourceIdentifierSpecs<T, SourceIdentifierSpecWrapper>(
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

template<>
UsersIdentifiersRulebase
createUserIdentifiers<V1beta2AppsecLinuxPolicy>(
    const string &source_identifier_annotation_name,
    const V1beta2AppsecLinuxPolicy &policy,
    const string &context
)
{
    string jwt_identifier = "";
    vector<string> jwt_identifier_values;
    vector<UsersIdentifier> user_ident_vec;
    NewSourcesIdentifiers source_identifiers_spec =
        getAppsecSourceIdentifierSpecs<V1beta2AppsecLinuxPolicy, NewSourcesIdentifiers>(
            source_identifier_annotation_name,
            policy
        );

    for (const Identifier &src_ident : source_identifiers_spec.getSourcesIdentifiers()) {
        if (src_ident.getIdentifier() == "JWTKey") {
            jwt_identifier = "JWTKey";
            jwt_identifier_values.insert(
                jwt_identifier_values.end(),
                src_ident.getValues().begin(),
                src_ident.getValues().end()
            );
            user_ident_vec.push_back(UsersIdentifier("authorization", src_ident.getValues()));
        } else {
            user_ident_vec.push_back(UsersIdentifier(src_ident.getIdentifier(), src_ident.getValues()));
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
    const string &port,
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
    const vector<InnerException> &exceptions)
{
    PracticeSection practice = PracticeSection(practice_id, practice_type, practice_name);
    vector<ParametersSection> exceptions_result;
    for (auto exception : exceptions) {
        exceptions_result.push_back(ParametersSection(exception.getBehaviorId(), exception_name));
    }

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
        port,
        uri,
        {practice},
        exceptions_result,
        triggers
    );

    return rules_config;
}

RulesConfigRulebase
createMultiRulesSections(
    const string &url,
    const string &port,
    const string &uri,
    const string &practice_id,
    const string &practice_name,
    const string &practice_type,
    const string &rate_limit_practice_id,
    const string &rate_limit_practice_name,
    const string &rate_limit_practice_type,
    const string &log_trigger_name,
    const string &log_trigger_id,
    const string &log_trigger_type,
    const string &web_user_res_vec_name,
    const string &web_user_res_vec_id,
    const string &web_user_res_vec_type,
    const string &asset_name,
    const string &exception_name,
    const vector<InnerException> &exceptions)
{
    string behaviorId = exceptions.empty() ? "" : exceptions[0].getBehaviorId();
    ParametersSection exception_param = ParametersSection(behaviorId, exception_name);

    vector<PracticeSection> practices;
    if (!practice_id.empty()) {
        practices.push_back(PracticeSection(practice_id, practice_type, practice_name));
    }
    if (!rate_limit_practice_id.empty()) {
        practices.push_back(
            PracticeSection(rate_limit_practice_id, rate_limit_practice_type, rate_limit_practice_name)
        );
    }

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
        port,
        uri,
        practices,
        {exception_param},
        triggers
    );

    return rules_config;
}

void
PolicyMakerUtils::createIpsSections(
    const string &asset_id,
    const string &asset_name,
    const string &practice_id,
    const string &practice_name,
    const string &source_identifier,
    const string & context,
    const V1beta2AppsecLinuxPolicy &policy,
    map<AnnotationTypes, string> &rule_annotations)
{
    auto apssec_practice = getAppsecPracticeSpec<V1beta2AppsecLinuxPolicy, NewAppSecPracticeSpec>(
        rule_annotations[AnnotationTypes::PRACTICE],
        policy);

    if (apssec_practice.getIntrusionPrevention().getMode().empty()) return;

    IpsProtectionsSection ips_section = IpsProtectionsSection(
        context,
        asset_name,
        asset_id,
        practice_name,
        practice_id,
        source_identifier,
        apssec_practice.getIntrusionPrevention().getMode(),
        apssec_practice.getIntrusionPrevention().createIpsRules()
    );

    ips[asset_name] = ips_section;
}

void
PolicyMakerUtils::createSnortProtecionsSection(const string &file_name, bool is_temporary)
{
    auto path = getFilesystemPathConfig() + "/conf/snort/" + file_name;
    string in_file = is_temporary ? path + ".rule" : path;

    if (snort_protections.find(path) != snort_protections.end()) {
        dbgTrace(D_LOCAL_POLICY) << "Snort protections section for file " << file_name << " already exists";
        return;
    }
    dbgTrace(D_LOCAL_POLICY)
        << "Reading snort signatures from"
        << (is_temporary ? " temporary" : "") << " file " << path;

    auto snort_script_path = getFilesystemPathConfig() + "/scripts/snort_to_ips_local.py";
    auto cmd = "python3 " + snort_script_path + " " + in_file + " " + path + ".out " + path + ".err";

    auto res = Singleton::Consume<I_ShellCmd>::by<LocalPolicyMgmtGenerator>()->getExecOutput(cmd);

    if (!res.ok()) {
        dbgWarning(D_LOCAL_POLICY) << res.getErr();
        return;
    }

    Maybe<ProtectionsSectionWrapper> maybe_protections = openFileAsJson<ProtectionsSectionWrapper>(path + ".out");
    if (!maybe_protections.ok()){
        dbgWarning(D_LOCAL_POLICY) << maybe_protections.getErr();
        return;
    }

    auto i_orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<LocalPolicyMgmtGenerator>();
    if (is_temporary) i_orchestration_tools->removeFile(in_file);
    i_orchestration_tools->removeFile(path + ".out");
    i_orchestration_tools->removeFile(path + ".err");

    snort_protections[path] = ProtectionsSection(
        maybe_protections.unpack().getProtections(),
        file_name
    );
}

void
PolicyMakerUtils::createSnortSections(
    const string & context,
    const string &asset_name,
    const string &asset_id,
    const string &practice_name,
    const string &practice_id,
    const string &source_identifier,
    const V1beta2AppsecLinuxPolicy &policy,
    map<AnnotationTypes, string> &rule_annotations)
{
    auto apssec_practice = getAppsecPracticeSpec<V1beta2AppsecLinuxPolicy, NewAppSecPracticeSpec>(
        rule_annotations[AnnotationTypes::PRACTICE],
        policy);

    if (apssec_practice.getSnortSignatures().getOverrideMode() == "inactive" ||
        apssec_practice.getSnortSignatures().getFiles().size() == 0) {
        return;
    }

    if (apssec_practice.getSnortSignatures().isTemporary()) {
        createSnortProtecionsSection("snort_k8s_" + apssec_practice.getName(), true);
    } else if (apssec_practice.getSnortSignatures().getFiles().size() > 0) {
        // when support for multiple files is ready, will iterate over the files array
        auto file = apssec_practice.getSnortSignatures().getFiles()[0];
        createSnortProtecionsSection(file, false);
    }

    SnortProtectionsSection snort_section = SnortProtectionsSection(
        context,
        asset_name,
        asset_id,
        practice_name,
        practice_id,
        source_identifier,
        apssec_practice.getSnortSignatures().getOverrideMode(),
        apssec_practice.getSnortSignatures().getFiles()
    );

    snort[asset_name] = snort_section;
}

void
PolicyMakerUtils::createFileSecuritySections(
    const string &asset_id,
    const string &asset_name,
    const string &practice_id,
    const string &practice_name,
    const string &context,
    const V1beta2AppsecLinuxPolicy &policy,
    map<AnnotationTypes, string> &rule_annotations)
{
    auto apssec_practice = getAppsecPracticeSpec<V1beta2AppsecLinuxPolicy, NewAppSecPracticeSpec>(
        rule_annotations[AnnotationTypes::PRACTICE],
        policy);

    if (apssec_practice.getFileSecurity().getOverrideMode().empty()) return;

    auto file_security_section = apssec_practice.getFileSecurity().createFileSecurityProtectionsSection(
        context,
        asset_name,
        asset_id,
        practice_name,
        practice_id
    );

    file_security[asset_name] = file_security_section;
}

void
PolicyMakerUtils::createRateLimitSection(
    const string &asset_name,
    const string &url,
    const string &uri,
    const string &trigger_id,
    const V1beta2AppsecLinuxPolicy &policy,
    map<AnnotationTypes, string> &rule_annotations)
{
    if (rule_annotations[AnnotationTypes::ACCESS_CONTROL_PRACTICE].empty()) {
        return;
    }

    string practice_id = "";
    try {
        practice_id = to_string(boost::uuids::random_generator()());
    } catch (const boost::uuids::entropy_error &e) {
        dbgFlow(D_LOCAL_POLICY) << "Couldn't generate random id for rate limit practice";
    }
    auto access_control_practice = getAccessControlPracticeSpec(
        rule_annotations[AnnotationTypes::ACCESS_CONTROL_PRACTICE],
        policy);

    RateLimitRulesTriggerSection trigger;
    if (!trigger_id.empty()) {
        string trigger_name = rule_annotations[AnnotationTypes::TRIGGER];
        trigger = RateLimitRulesTriggerSection(trigger_id, trigger_name, "Trigger");
    }

    auto rules = access_control_practice.geRateLimit().createRateLimitRulesSection(trigger);

    rate_limit[rule_annotations[AnnotationTypes::ACCESS_CONTROL_PRACTICE]] = RateLimitSection(
        asset_name,
        url,
        uri,
        access_control_practice.geRateLimit().getMode(),
        practice_id,
        rule_annotations[AnnotationTypes::ACCESS_CONTROL_PRACTICE],
        rules
    );
}

void
PolicyMakerUtils::createWebAppSection(
    const V1beta2AppsecLinuxPolicy &policy,
    const RulesConfigRulebase& rule_config,
    const string &practice_id, const string &full_url,
    const string &default_mode,
    map<AnnotationTypes, string> &rule_annotations)
{
    auto apssec_practice =
        getAppsecPracticeSpec<V1beta2AppsecLinuxPolicy, NewAppSecPracticeSpec>(
            rule_annotations[AnnotationTypes::PRACTICE],
            policy
        );
    PracticeAdvancedConfig practice_advance_config(
        apssec_practice.getWebAttacks().getMaxHeaderSizeBytes(),
        apssec_practice.getWebAttacks().getMaxBodySizeKb(),
        apssec_practice.getWebAttacks().getMaxObjectDepth(),
        apssec_practice.getWebAttacks().getMaxUrlSizeBytes()
    );
    WebAppSection web_app = WebAppSection(
        full_url == "Any" ? default_appsec_url : full_url,
        rule_config.getAssetId(),
        rule_config.getAssetName(),
        rule_config.getAssetId(),
        rule_config.getAssetName(),
        practice_id,
        rule_annotations[AnnotationTypes::PRACTICE],
        rule_config.getContext(),
        apssec_practice.getWebAttacks().getMinimumConfidence(),
        apssec_practice.getWebAttacks().getMode(default_mode),
        practice_advance_config,
        apssec_practice.getAntiBot(),
        log_triggers[rule_annotations[AnnotationTypes::TRIGGER]],
        trusted_sources[rule_annotations[AnnotationTypes::TRUSTED_SOURCES]]
    );
    web_apps[rule_config.getAssetName()] = web_app;
}

void
PolicyMakerUtils::createThreatPreventionPracticeSections(
    const string &asset_name,
    const string &url,
    const string &port,
    const string &uri,
    const string &default_mode,
    const V1beta2AppsecLinuxPolicy &policy,
    map<AnnotationTypes, string> &rule_annotations)
{
    if (rule_annotations[AnnotationTypes::PRACTICE].empty() ||
        web_apps.count(asset_name)
    ) {
        return;
    }
    string practice_id = "";
    try {
        practice_id = to_string(boost::uuids::random_generator()());
    } catch (const boost::uuids::entropy_error &e) {
        dbgFlow(D_LOCAL_POLICY) << "Couldn't generate random id for threat prevention practice";
    }

    RulesConfigRulebase rule_config = createMultiRulesSections(
        url,
        port,
        uri,
        practice_id,
        rule_annotations[AnnotationTypes::PRACTICE],
        "WebApplication",
        rate_limit[rule_annotations[AnnotationTypes::ACCESS_CONTROL_PRACTICE]].getId(),
        rate_limit[rule_annotations[AnnotationTypes::ACCESS_CONTROL_PRACTICE]].getName(),
        "RateLimit",
        rule_annotations[AnnotationTypes::TRIGGER],
        log_triggers[rule_annotations[AnnotationTypes::TRIGGER]].getTriggerId(),
        "log",
        rule_annotations[AnnotationTypes::WEB_USER_RES],
        web_user_res_triggers[rule_annotations[AnnotationTypes::WEB_USER_RES]].getTriggerId(),
        "WebUserResponse",
        asset_name,
        rule_annotations[AnnotationTypes::EXCEPTION],
        inner_exceptions[rule_annotations[AnnotationTypes::EXCEPTION]]
    );
    rules_config[rule_config.getAssetName()] = rule_config;

    string current_identifier;
    if (!rule_annotations[AnnotationTypes::SOURCE_IDENTIFIERS].empty()) {
        UsersIdentifiersRulebase user_identifiers = createUserIdentifiers<V1beta2AppsecLinuxPolicy>(
            rule_annotations[AnnotationTypes::SOURCE_IDENTIFIERS],
            policy,
            rule_config.getContext()
        );
        users_identifiers[rule_annotations[AnnotationTypes::SOURCE_IDENTIFIERS]] = user_identifiers;
        current_identifier = user_identifiers.getIdentifier();
    }

    createIpsSections(
        rule_config.getAssetId(),
        rule_config.getAssetName(),
        practice_id,
        rule_annotations[AnnotationTypes::PRACTICE],
        current_identifier,
        rule_config.getContext(),
        policy,
        rule_annotations
    );

    createSnortSections(
        "practiceId(" + practice_id + ")",
        rule_config.getAssetName(),
        rule_config.getAssetId(),
        rule_annotations[AnnotationTypes::PRACTICE],
        practice_id,
        current_identifier,
        policy,
        rule_annotations
    );

    createFileSecuritySections(
        rule_config.getAssetId(),
        rule_config.getAssetName(),
        practice_id,
        rule_annotations[AnnotationTypes::PRACTICE],
        "assetId(" + rule_config.getAssetId() + ")",
        policy,
        rule_annotations
    );

    if (!web_apps.count(rule_config.getAssetName())) {
        createWebAppSection(policy, rule_config, practice_id, asset_name, default_mode, rule_annotations);
    }

}

SettingsRulebase
createSettingsSection(const AppSecAutoUpgradeSpec &upgrade_settings)
{
    string agent_settings_key = "agent.test.policy";
    string agent_settings_value = "local policy";
    AgentSettingsSection agent_setting_1 = AgentSettingsSection(agent_settings_key, agent_settings_value);

    return SettingsRulebase({agent_setting_1}, upgrade_settings);

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
        ExceptionsRulebase(convertExceptionsMapToVector(inner_exceptions))
    });

    AppSecWrapper appses_section(AppSecRulebase(convertMapToVector(web_apps), {}));
    RulesConfigWrapper rules_config_section(convertMapToVector(rules_config), convertMapToVector(users_identifiers));
    IntrusionPreventionWrapper ips_section(convertMapToVector(ips));
    SnortSectionWrapper snort_section(convertMapToVector(snort), convertMapToVector(snort_protections));
    FileSecurityWrapper file_security_section(convertMapToVector(file_security));
    AccessControlRulebaseWrapper rate_limit_section(convertMapToVector(rate_limit));
    SecurityAppsWrapper security_app_section = SecurityAppsWrapper(
        appses_section,
        triggers_section,
        rules_config_section,
        ips_section,
        snort_section,
        rate_limit_section,
        file_security_section,
        exceptions_section,
        policy_version
    );

    SettingsRulebase settings_section = createSettingsSection(upgrade_settings);
    PolicyWrapper policy_wrapper = PolicyWrapper(settings_section, security_app_section);

    return policy_wrapper;
}

template<class T, class R>
void
PolicyMakerUtils::createPolicyElementsByRule(
    const R &rule,
    const R &default_rule,
    const T &policy,
    const string &policy_name)
{
    map<AnnotationTypes, string> rule_annotations = extractAnnotationsNames(rule, default_rule, policy_name);
    if (
        !rule_annotations[AnnotationTypes::TRIGGER].empty() &&
        !log_triggers.count(rule_annotations[AnnotationTypes::TRIGGER])
    ) {
        log_triggers[rule_annotations[AnnotationTypes::TRIGGER]] =
            createLogTriggerSection<T>(
                rule_annotations[AnnotationTypes::TRIGGER],
                policy
            );
    }

    if (
        !rule_annotations[AnnotationTypes::WEB_USER_RES].empty() &&
        !web_user_res_triggers.count(rule_annotations[AnnotationTypes::WEB_USER_RES])
    ) {
        web_user_res_triggers[rule_annotations[AnnotationTypes::WEB_USER_RES]] =
            createWebUserResponseTriggerSection<T>(
                rule_annotations[AnnotationTypes::WEB_USER_RES],
                policy
            );
    }

    if (
        !rule_annotations[AnnotationTypes::EXCEPTION].empty() &&
        !inner_exceptions.count(rule_annotations[AnnotationTypes::EXCEPTION])
    ) {
        inner_exceptions[rule_annotations[AnnotationTypes::EXCEPTION]] =
            createExceptionSection<T>(
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
            createTrustedSourcesSection<T>(
                rule_annotations[AnnotationTypes::TRUSTED_SOURCES],
                rule_annotations[AnnotationTypes::SOURCE_IDENTIFIERS],
                policy
            );
    }

    if (
        !rule_annotations[AnnotationTypes::PRACTICE].empty() &&
        !web_apps.count(rule_annotations[AnnotationTypes::PRACTICE])
    ) {
        trusted_sources[rule_annotations[AnnotationTypes::TRUSTED_SOURCES]] =
            createTrustedSourcesSection<T>(
                rule_annotations[AnnotationTypes::TRUSTED_SOURCES],
                rule_annotations[AnnotationTypes::SOURCE_IDENTIFIERS],
                policy
            );
    }

    string full_url = rule.getHost() == "*" || rule.getHost() == "*:*"
            ? "Any"
            : rule.getHost();


    if (!rule_annotations[AnnotationTypes::PRACTICE].empty() &&
        !web_apps.count(full_url)
    ) {
        string practice_id = "";
        try {
            practice_id = to_string(boost::uuids::random_generator()());
        } catch (const boost::uuids::entropy_error &e) {
            //TBD: return Maybe as part of future error handling
        }

        tuple<string, string, string> splited_host_name = splitHostName(rule.getHost());

        RulesConfigRulebase rule_config = createMultiRulesSections(
            std::get<0>(splited_host_name),
            std::get<1>(splited_host_name),
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
            inner_exceptions[rule_annotations[AnnotationTypes::EXCEPTION]]
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

        if (!web_apps.count(rule_config.getAssetName())) {
            WebAppSection web_app = WebAppSection(
                full_url == "Any" ? default_appsec_url : full_url,
                rule_config.getAssetId(),
                rule_config.getAssetName(),
                rule_config.getAssetId(),
                rule_config.getAssetName(),
                practice_id,
                rule_annotations[AnnotationTypes::PRACTICE],
                rule_config.getContext(),
                getAppsecPracticeSpec<T, AppSecPracticeSpec>(rule_annotations[AnnotationTypes::PRACTICE], policy),
                log_triggers[rule_annotations[AnnotationTypes::TRIGGER]],
                rule.getMode(),
                trusted_sources[rule_annotations[AnnotationTypes::TRUSTED_SOURCES]],
                inner_exceptions[rule_annotations[AnnotationTypes::EXCEPTION]]
            );
            web_apps[rule_config.getAssetName()] = web_app;
        }
    }
}

// LCOV_EXCL_START Reason: no test exist
template<>
void
PolicyMakerUtils::createPolicyElementsByRule<V1beta2AppsecLinuxPolicy, NewParsedRule>(
    const NewParsedRule &rule,
    const NewParsedRule &default_rule,
    const V1beta2AppsecLinuxPolicy &policy,
    const string &policy_name)
{
    dbgTrace(D_LOCAL_POLICY) << "Creating policy elements from version V1beta2";
    map<AnnotationTypes, string> rule_annotations =
        extractAnnotationsNames<NewParsedRule>(rule, default_rule, policy_name);

    if (
        rule_annotations.count(AnnotationTypes::TRIGGER) > 0 &&
        !rule_annotations[AnnotationTypes::TRIGGER].empty() &&
        !log_triggers.count(rule_annotations[AnnotationTypes::TRIGGER])
    ) {
        log_triggers[rule_annotations[AnnotationTypes::TRIGGER]] =
            createLogTriggerSection<V1beta2AppsecLinuxPolicy>(
                rule_annotations[AnnotationTypes::TRIGGER],
                policy
            );
    }

    if (
        rule_annotations.count(AnnotationTypes::WEB_USER_RES) > 0 &&
        !rule_annotations[AnnotationTypes::WEB_USER_RES].empty() &&
        !web_user_res_triggers.count(rule_annotations[AnnotationTypes::WEB_USER_RES])
    ) {
        web_user_res_triggers[rule_annotations[AnnotationTypes::WEB_USER_RES]] =
            createWebUserResponseTriggerSection<V1beta2AppsecLinuxPolicy>(
                rule_annotations[AnnotationTypes::WEB_USER_RES],
                policy
            );
    }

    if (
        rule_annotations.count(AnnotationTypes::EXCEPTION) > 0 &&
        !rule_annotations[AnnotationTypes::EXCEPTION].empty() &&
        !inner_exceptions.count(rule_annotations[AnnotationTypes::EXCEPTION])
    ) {
        inner_exceptions[rule_annotations[AnnotationTypes::EXCEPTION]] =
            createExceptionSection<V1beta2AppsecLinuxPolicy>(
                rule_annotations[AnnotationTypes::EXCEPTION],
                policy
            );
    }

    if (
        rule_annotations.count(AnnotationTypes::TRUSTED_SOURCES) > 0 &&
        rule_annotations.count(AnnotationTypes::SOURCE_IDENTIFIERS) > 0 &&
        !rule_annotations[AnnotationTypes::TRUSTED_SOURCES].empty() &&
        !rule_annotations[AnnotationTypes::SOURCE_IDENTIFIERS].empty() &&
        !trusted_sources.count(rule_annotations[AnnotationTypes::TRUSTED_SOURCES])
    ) {
        trusted_sources[rule_annotations[AnnotationTypes::TRUSTED_SOURCES]] =
            createTrustedSourcesSection<V1beta2AppsecLinuxPolicy>(
                rule_annotations[AnnotationTypes::TRUSTED_SOURCES],
                rule_annotations[AnnotationTypes::SOURCE_IDENTIFIERS],
                policy
            );
    }

    if (
        rule_annotations.count(AnnotationTypes::PRACTICE) > 0 &&
        !rule_annotations[AnnotationTypes::PRACTICE].empty() &&
        !web_apps.count(rule_annotations[AnnotationTypes::PRACTICE])
    ) {
        trusted_sources[rule_annotations[AnnotationTypes::TRUSTED_SOURCES]] =
            createTrustedSourcesSection<V1beta2AppsecLinuxPolicy>(
                rule_annotations[AnnotationTypes::TRUSTED_SOURCES],
                rule_annotations[AnnotationTypes::SOURCE_IDENTIFIERS],
                policy
            );
    }

    string full_url = rule.getHost() == "*" || rule.getHost() == "*:*"
        ? "Any"
        : rule.getHost();
    tuple<string, string, string> splited_host_name = splitHostName(rule.getHost());

    createRateLimitSection(
        full_url,
        std::get<0>(splited_host_name),
        std::get<2>(splited_host_name),
        log_triggers[rule_annotations[AnnotationTypes::TRIGGER]].getTriggerId(),
        policy,
        rule_annotations
    );

    createThreatPreventionPracticeSections(
        full_url,
        std::get<0>(splited_host_name),
        std::get<1>(splited_host_name),
        std::get<2>(splited_host_name),
        rule.getMode(),
        policy,
        rule_annotations
    );

    upgrade_settings = policy.getAppSecAutoUpgradeSpec();
}
// LCOV_EXCL_STOP

template<class T, class R>
void
PolicyMakerUtils::createPolicyElements(
    const vector<R> &rules,
    const R &default_rule,
    const T &policy,
    const string &policy_name)
{
    for (const R &rule : rules) {
        createPolicyElementsByRule<T, R>(rule, default_rule, policy, policy_name);
    }
}

template<class T, class R>
void
PolicyMakerUtils::createAgentPolicyFromAppsecPolicy(const string &policy_name, const T &appsec_policy)
{
    dbgTrace(D_LOCAL_POLICY) << "Proccesing policy, name: " << policy_name;

    R default_rule = appsec_policy.getAppsecPolicySpec().getDefaultRule();

    vector<R> specific_rules = appsec_policy.getAppsecPolicySpec().getSpecificRules();
    createPolicyElements<T, R>(specific_rules, default_rule, appsec_policy, policy_name);

    // add default rule to policy
    createPolicyElementsByRule<T, R>(default_rule, default_rule, appsec_policy, policy_name);
}

// LCOV_EXCL_START Reason: no test exist
template<>
void
PolicyMakerUtils::createAgentPolicyFromAppsecPolicy<V1beta2AppsecLinuxPolicy, NewParsedRule>(
    const string &policy_name,
    const V1beta2AppsecLinuxPolicy &appsec_policy)
{
    dbgTrace(D_LOCAL_POLICY) << "Proccesing v1beta2 policy, name: " << policy_name;

    NewParsedRule default_rule = appsec_policy.getAppsecPolicySpec().getDefaultRule();

    vector<NewParsedRule> specific_rules = appsec_policy.getAppsecPolicySpec().getSpecificRules();
    createPolicyElements<V1beta2AppsecLinuxPolicy, NewParsedRule>(
        specific_rules,
        default_rule,
        appsec_policy,
        policy_name
    );

    // add default rule to policy
    createPolicyElementsByRule<V1beta2AppsecLinuxPolicy, NewParsedRule>(
        default_rule,
        default_rule,
        appsec_policy,
        policy_name);
}
// LCOV_EXCL_STOP

string
PolicyMakerUtils::proccesSingleAppsecPolicy(
    const string &policy_path,
    const string &policy_version,
    const string &local_appsec_policy_path)
{

    Maybe<V1beta2AppsecLinuxPolicy> maybe_policy_v1beta2 = openFileAsJson<V1beta2AppsecLinuxPolicy>(policy_path);
    if (maybe_policy_v1beta2.ok()) {
        policy_version_name = "v1beta2";
        createAgentPolicyFromAppsecPolicy<V1beta2AppsecLinuxPolicy, NewParsedRule>(
            getPolicyName(policy_path),
            maybe_policy_v1beta2.unpack()
        );
    } else {
        policy_version_name = "v1beta1";
        dbgInfo(D_LOCAL_POLICY)
            << "Failed to retrieve AppSec local policy with version: v1beta2, Trying version: v1beta1";

        Maybe<AppsecLinuxPolicy> maybe_policy_v1beta1 = openFileAsJson<AppsecLinuxPolicy>(policy_path);
        if (!maybe_policy_v1beta1.ok()){
            dbgWarning(D_LOCAL_POLICY) << maybe_policy_v1beta1.getErr();
            return "";
        }
        createAgentPolicyFromAppsecPolicy<AppsecLinuxPolicy, ParsedRule>(
            getPolicyName(policy_path),
            maybe_policy_v1beta1.unpack()
        );

        if (getenv("OPENAPPSEC_STANDALONE")) rpmBuildNginxServers(maybe_policy_v1beta1.unpack());
    }

    PolicyWrapper policy_wrapper = combineElementsToPolicy(policy_version);
    return dumpPolicyToFile(
        policy_wrapper,
        local_appsec_policy_path
    );
}

void
PolicyMakerUtils::rpmReportInfo(const std::string &msg)
{
    dbgTrace(D_LOCAL_POLICY) << msg;

    LogGen(
        msg,
        ReportIS::Audience::SECURITY,
        ReportIS::Severity::INFO,
        ReportIS::Priority::LOW,
        ReportIS::Tags::ORCHESTRATOR
    );
}

void
PolicyMakerUtils::rpmReportError(const std::string &msg)
{
    dbgWarning(D_LOCAL_POLICY) << msg;

    LogGen(
        msg,
        ReportIS::Audience::SECURITY,
        ReportIS::Severity::CRITICAL,
        ReportIS::Priority::URGENT,
        ReportIS::Tags::ORCHESTRATOR
    );
}

void
PolicyMakerUtils::rpmBuildNginxServers(const AppsecLinuxPolicy &policy)
{
    rpmReportInfo("Started building NGINX servers");

    ReverseProxyBuilder::init();
    bool full_success = true;
    bool partial_success = false;
    set<pair<string, bool>> processed_rules;
    for (ParsedRule const &rule : policy.getAppsecPolicySpec().getSpecificRules()) {
        tuple<string, string, string> splited_host_name = splitHostName(rule.getHost());
        string host = std::get<0>(splited_host_name);
        if (host.empty() || rule.rpmGetUpstream().empty()) continue;

        string location = std::get<2>(splited_host_name);
        if (location.empty()) location = "/";

        dbgTrace(D_LOCAL_POLICY)
            << "Building NGINX server: "
            << host
            << ", location: "
            << location
            << " RP-Settings: "
            << rule.rpmGetRPSettings();

        RPMSettings rp_settings =
            rpmGetAppsecRPSettingSpec<AppsecLinuxPolicy, RPMSettings>(rule.rpmGetRPSettings(), policy);
        pair<string, bool> server = {host, rule.rpmIsHttps()};
        auto it = processed_rules.find(server);
        if (it != processed_rules.end()) {
            auto maybe_res = ReverseProxyBuilder::addNginxServerLocation(location, host, rule, rp_settings);
            if (!maybe_res.ok()) {
                rpmReportError(
                    "Could not add an NGINX server location: " + location + " to server: " + host +
                    ", error: " + maybe_res.getErr()
                );
                full_success = false;
                continue;
            }
            rpmReportInfo("NGINX server location: " + location + " was successfully added to server: " + host);
            partial_success = true;
        } else {
            auto maybe_res = ReverseProxyBuilder::createNewNginxServer(host, rule, rp_settings);
            if (!maybe_res.ok()) {
                rpmReportError("Could not create a new NGINX server: " + host + ", error: " + maybe_res.getErr());
                full_success = false;
                continue;
            }
            rpmReportInfo(
                (rule.rpmIsHttps() ? string("SSL") : string("HTTP")) + " NGINX server: " + host +
                " was successfully built"
            );
            processed_rules.insert(server);

            maybe_res = ReverseProxyBuilder::addNginxServerLocation(location, host, rule, rp_settings);
            if (!maybe_res.ok()) {
                rpmReportError(
                    "Could not add an NGINX server location: " + location + " to server: " + host +
                    ", error: " + maybe_res.getErr()
                );
                full_success = false;
                continue;
            }
            rpmReportInfo("NGINX server location: " + location + " was successfully added to server: " + host);
            partial_success = true;
        }
    }

    auto maybe_reload_nginx = ReverseProxyBuilder::reloadNginx();
    if (!maybe_reload_nginx.ok()) {
        rpmReportError("Could not reload NGINX, error: " + maybe_reload_nginx.getErr());
        return;
    }

    if (full_success) {
        rpmReportInfo("NGINX configuration was loaded successfully!");
    } else if (partial_success) {
        rpmReportInfo("NGINX configuration was partially loaded");
    } else {
        rpmReportError("Could not load any NGINX configuration");
    }
}
