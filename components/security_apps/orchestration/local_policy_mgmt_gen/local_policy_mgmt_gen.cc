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

#include "k8s_policy_gen.h"

#include <map>
#include <set>
#include <string>
#include <fstream>
#include <streambuf>
#include <cereal/types/vector.hpp>
#include <cereal/archives/json.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid_generators.hpp>

#include "rest.h"
#include "debug.h"
#include "config.h"
#include "connkey.h"
#include "url_parser.h"
#include "i_messaging.h"
#include "i_agent_details.h"
#include "customized_cereal_map.h"
#include "include/appsec_practice_section.h"
#include "include/ingress_data.h"
#include "include/settings_section.h"
#include "include/triggers_section.h"
#include "include/k8s_policy_common.h"
#include "include/exceptions_section.h"
#include "include/rules_config_section.h"
#include "include/trusted_sources_section.h"

using namespace std;

USE_DEBUG_FLAG(D_K8S_POLICY);

const static string policy_path = "/tmp/k8s.policy";
const static string open_appsec_io = "openappsec.io/";
const static string policy_key = "policy";
const static string syslog_key = "syslog";
const static string mode_key = "mode";

class SecurityAppsWrapper
{
public:
    SecurityAppsWrapper(
        const AppSecWrapper &_waap,
        const TriggersWrapper &_trrigers,
        const RulesConfigWrapper &_rules,
        const ExceptionsWrapper &_exceptions,
        const string &_policy_version)
            :
        waap(_waap),
        trrigers(_trrigers),
        rules(_rules),
        exceptions(_exceptions),
        policy_version(_policy_version) {}

    void
    serialize(cereal::JSONOutputArchive &out_ar) const
    {
        out_ar(
            cereal::make_nvp("waap",       waap),
            cereal::make_nvp("triggers",   trrigers),
            cereal::make_nvp("rules",      rules),
            cereal::make_nvp("exceptions", exceptions),
            cereal::make_nvp("version", policy_version)
        );
    }

private:
    AppSecWrapper waap;
    TriggersWrapper trrigers;
    RulesConfigWrapper rules;
    ExceptionsWrapper exceptions;
    string policy_version;
};

class K8sPolicyWrapper
{
public:
    K8sPolicyWrapper(
        const SettingsWrapper &_settings,
        const SecurityAppsWrapper &_security_apps)
            :
        settings(_settings),
        security_apps(_security_apps) {}

    void
    serialize(cereal::JSONOutputArchive &out_ar) const
    {
        security_apps.serialize(out_ar);
    }

private:
    SettingsWrapper settings;
    SecurityAppsWrapper security_apps;
};

class NamespaceMetadata
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgInfo(D_K8S_POLICY) << "NamespaceMetadata load";
        parseAppsecJSONKey<std::string>("name", name, archive_in);
        parseAppsecJSONKey<std::string>("uid", uid, archive_in);
    }

    const std::string & getName() const { return name; }
    const std::string & getUID() const { return uid; }

private:
    std::string name;
    std::string uid;
};

class SingleNamespaceData
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        parseAppsecJSONKey<NamespaceMetadata>("metadata", metadata, archive_in);
    }

    const NamespaceMetadata & getMetadata() const { return metadata; }

private:
    NamespaceMetadata metadata;
};

class NamespaceData : public ClientRest
{
public:
    bool
    loadJson(const std::string &json)
    {
        dbgTrace(D_K8S_POLICY) << "Loading namespace data";
        std::string modified_json = json;
        modified_json.pop_back();
        std::stringstream in;
        in.str(modified_json);
        try {
            cereal::JSONInputArchive in_ar(in);
            in_ar(
                cereal::make_nvp("items", items)
            );
        } catch (cereal::Exception &e) {
            dbgError(D_K8S_POLICY) << "Failed to load namespace data JSON. Error: " << e.what();
            return false;
        }
        return true;
    }

    const std::vector<SingleNamespaceData> & getItems() const { return items; }

private:
    std::vector<SingleNamespaceData> items;
};

class K8sPolicyGenerator::Impl
        :
    public Singleton::Provide<I_K8S_Policy_Gen>::From<K8sPolicyGenerator>,
    public Singleton::Consume<I_Messaging>,
    public Singleton::Consume<I_AgentDetails>,
    public Singleton::Consume<I_Environment>,
    public Singleton::Consume<I_MainLoop>
{
public:
    void
    init()
    {
        token = retrieveToken();
        if (token.empty()) return;
        dbgTrace(D_K8S_POLICY) << "Initializing K8S policy generator";
        conn_flags.setFlag(MessageConnConfig::SECURE_CONN);
        conn_flags.setFlag(MessageConnConfig::IGNORE_SSL_VALIDATION);

        messaging = Singleton::Consume<I_Messaging>::by<K8sPolicyGenerator::Impl>();

        Singleton::Consume<I_MainLoop>::by<K8sPolicyGenerator::Impl>()->addOneTimeRoutine(
            I_MainLoop::RoutineType::Offline,
            [this] ()
            {
                ScopedContext ctx;
                ctx.registerValue<bool>("k8s_env", true);
                while(!getClusterId()) {
                    Singleton::Consume<I_MainLoop>::by<K8sPolicyGenerator::Impl>()->yield(chrono::seconds(1));
                }
                return;
            },
            "Get k8s cluster ID"
        );
    }

    const string & getPolicyPath(void) const override { return policy_path; }

    string
    parsePolicy(const string &policy_version)
    {
        ScopedContext ctx;
        ctx.registerValue<bool>("k8s_env", true);

        IngressData ingress;
        bool res = messaging->sendObject(
                    ingress,
                    I_Messaging::Method::GET,
                    "kubernetes.default.svc",
                    443,
                    conn_flags,
                    "/apis/networking.k8s.io/v1/ingresses",
                    "Authorization: Bearer " + token + "\nConnection: close"
        );

        if(!res) {
            // TBD: Error handling : INXT-31444
            dbgError(D_K8S_POLICY) << "Failed to retrieve K8S Ingress configurations";
            return "";
        }

        set<string> generated_apps;
        set<WebAppSection> parsed_web_apps_set;
        vector<WebAppSection> parsed_web_apps;
        vector<RulesConfigRulebase> parsed_rules;
        vector<LogTriggerSection> parsed_log_triggers;
        set<InnerException> parsed_exeptions;
        vector<WebUserResponseTriggerSection> parsed_web_user_res;
        map<string, AppSecPracticeSpec> practice_map;
        map<string, LogTriggerSection> log_triggers_map;
        map<string, InnerException> exception_map;
        map<string, WebUserResponseTriggerSection> web_user_res_map;
        map<string, TrustedSourcesSpec> trusted_sources_map;
        map<string, vector<SourceIdentifierSpec>> source_identifiers_map;
        RulesConfigRulebase cleanup_rule;
        string cleanup_rule_mode = "Inactive";

        dbgTrace(D_K8S_POLICY) << "Received Ingress apiVersion: " << ingress.getapiVersion();
        dbgTrace(D_K8S_POLICY) << "Ingress items ammount: " << ingress.getItems().size();
        // TBD: break to methods : INXT-31445
        for (const SingleIngressData &item : ingress.getItems()) {
            dbgTrace(D_K8S_POLICY)
                << "Metadata name is: "
                << item.getMetadata().getName()
                << ", Namespace is: "
                << item.getMetadata().getNamespace()
                << ", Spec: "
                << item.getSpec();

            set<pair<string, string>> specific_assets_from_ingress;
            for (const IngressDefinedRule &rule : item.getSpec().getRules()) {
                string url = rule.getHost();
                for (const IngressRulePath &uri : rule.getPathsWrapper().getRulePaths()) {
                    specific_assets_from_ingress.insert({url, uri.getPath()});
                    dbgTrace(D_K8S_POLICY)
                        << "Inserting Host data to the specific asset set:"
                        << "URL: '"
                        << url
                        << "' uri: '"
                        << uri.getPath()
                        << "'";
                }
            }

            string asset;
            string annotation_type;
            string annotation_name;
            string policy_annotation;
            string syslog_address;
            string syslog_port;
            string mode_annotation;
            for (const pair<string, string> &annotation : item.getMetadata().getAnnotations()) {
                string annotation_key = annotation.first;
                string annotation_val = annotation.second;
                if (annotation_key.find(open_appsec_io) != string::npos) {
                    if (annotation_key.find(policy_key) != string::npos) policy_annotation = annotation_val;
                    if (annotation_key.find(syslog_key) != string::npos) {
                        bool has_port = annotation_val.find(":");
                        syslog_address = annotation_val.substr(0, annotation_val.find(":"));
                        syslog_port = has_port ? annotation_val.substr(annotation_val.find(":") + 1) : "";
                    }
                    if (annotation_key.find(mode_key) != string::npos) {
                        mode_annotation = annotation_val;
                        ctx.registerValue<string>("default mode annotation", mode_annotation);
                    }
                }
            }
            if (policy_annotation.empty()) {
                dbgInfo(D_K8S_POLICY) << "No policy was found in this ingress";
                continue;
            }

            dbgTrace(D_K8S_POLICY) << "Trying to parse policy for " << policy_annotation;
            AppsecSpecParser<AppsecPolicySpec> appsec_policy;
            res = messaging->sendObject(appsec_policy,
                                I_Messaging::Method::GET,
                                "kubernetes.default.svc",
                                443,
                                conn_flags,
                                "/apis/openappsec.io/v1beta1/policies/" + policy_annotation,
                                "Authorization: Bearer " + token + "\nConnection: close");
            if(!res) {
                dbgError(D_K8S_POLICY) << "Failed to retrieve AppSec policy";
                return "";
            }
            dbgTrace(D_K8S_POLICY) << "Succeessfully retrieved AppSec policy: " << appsec_policy.getSpec();

            vector<ParsedRule> specific_rules = appsec_policy.getSpec().getSpecificRules();
            ParsedRule default_rule = appsec_policy.getSpec().getDefaultRule();

            for (const ParsedRule &parsed_rule : specific_rules) {
                string asset_name = parsed_rule.getHost();
                dbgTrace(D_K8S_POLICY) << "Handling specific rule for asset: " << asset_name;

                string practice_annotation_name;
                // TBD: support multiple practices
                if (parsed_rule.getPractices().size() > 0 && !parsed_rule.getPractices()[0].empty()) {
                    practice_annotation_name = parsed_rule.getPractices()[0];
                } else if (default_rule.getPractices().size() > 0 && !default_rule.getPractices()[0].empty()) {
                    practice_annotation_name = default_rule.getPractices()[0];
                }

                string trigger_annotation_name;
                // TBD: support multiple triggers
                if (parsed_rule.getLogTriggers().size() > 0 && !parsed_rule.getLogTriggers()[0].empty()) {
                    trigger_annotation_name = parsed_rule.getLogTriggers()[0];
                } else if (default_rule.getLogTriggers().size() > 0 && !default_rule.getLogTriggers()[0].empty()) {
                    trigger_annotation_name = default_rule.getLogTriggers()[0];
                }

                string exception_annotation_name;
                // TBD: support multiple exceptions
                if (parsed_rule.getExceptions().size() > 0 && !parsed_rule.getExceptions()[0].empty()) {
                    exception_annotation_name = parsed_rule.getExceptions()[0];
                } else if (default_rule.getExceptions().size() > 0 && !default_rule.getExceptions()[0].empty()) {
                    exception_annotation_name = default_rule.getExceptions()[0];
                }

                string web_user_res_annotation_name =
                    parsed_rule.getCustomResponse().empty() ?
                    default_rule.getCustomResponse() :
                    parsed_rule.getCustomResponse();

                string source_identifiers_annotation_name =
                    parsed_rule.getSourceIdentifiers().empty() ?
                    default_rule.getSourceIdentifiers() :
                    parsed_rule.getSourceIdentifiers();

                string trusted_sources_annotation_name =
                    parsed_rule.getTrustedSources ().empty() ?
                    default_rule.getTrustedSources() :
                    parsed_rule.getTrustedSources();

                auto pos = asset_name.find("/");
                string url;
                string uri;
                if (pos != string::npos) {
                    url = asset_name.substr(0, asset_name.find("/"));
                    uri = asset_name.substr(asset_name.find("/"));
                } else {
                    url = asset_name;
                    uri = "";
                }

                if (specific_assets_from_ingress.find({url, uri}) != specific_assets_from_ingress.end()) {
                    // Erasing the current asset from the specific assets, because it won't have default policy
                    specific_assets_from_ingress.erase({url, uri});
                }

                vector<pair<string, string>> web_user_res_vec;
                if (!extractExceptions(exception_annotation_name, exception_map, parsed_exeptions)) {
                    dbgWarning(D_K8S_POLICY)
                        << "Failed extracting exceptions. Exception name: "
                        << exception_annotation_name;
                    return "";
                }

                if (!extractTriggers(
                        trigger_annotation_name,
                        log_triggers_map,
                        parsed_log_triggers,
                        syslog_address,
                        syslog_port)
                ) {
                        dbgWarning(D_K8S_POLICY)
                        << "Failed extracting triggers. Trigger name: "
                        << trigger_annotation_name;
                    return "";
                }

                if (!extractWebUserResponse(
                    web_user_res_annotation_name,
                    web_user_res_map,
                    web_user_res_vec,
                    parsed_web_user_res)
                ) {
                    dbgWarning(D_K8S_POLICY)
                        << "Failed extracting custom response. Custom response name: "
                        << web_user_res_annotation_name;
                    return "";
                }

                AppSecTrustedSources parsed_trusted_sources;
                if (!extractTrustedSources(
                    asset_name,
                    trusted_sources_annotation_name,
                    source_identifiers_annotation_name,
                    trusted_sources_map,
                    source_identifiers_map,
                    parsed_trusted_sources)
                ) {
                    dbgWarning(D_K8S_POLICY)
                        << "Failed extracting trused sources. Trusted source name: "
                        << trusted_sources_annotation_name
                        << ", Source identifiers annotation name: "
                        << source_identifiers_annotation_name;
                    return "";
                }

                if (!practice_annotation_name.empty() && practice_map.count(practice_annotation_name) == 0) {
                    AppsecSpecParser<AppSecPracticeSpec> appsec_practice;
                    res = messaging->sendObject(appsec_practice,
                                        I_Messaging::Method::GET,
                                        "kubernetes.default.svc",
                                        443,
                                        conn_flags,
                                        "/apis/openappsec.io/v1beta1/practices/" + practice_annotation_name,
                                        "Authorization: Bearer " + token + "\nConnection: close");
                    if(!res) {
                        dbgError(D_K8S_POLICY) << "Failed to retrieve AppSec practice for asset " << asset_name;
                        return "";
                    }
                    practice_map.emplace(practice_annotation_name, appsec_practice.getSpec());
                    dbgTrace(D_K8S_POLICY)
                        << "Successfully retrieved AppSec practice "
                        << practice_annotation_name
                        << appsec_practice.getSpec();
                }

                string log_trigger_id;
                LogTriggerSection log_trigger_annotation;
                if (log_triggers_map.count(trigger_annotation_name) > 0) {
                    log_trigger_id = log_triggers_map.at(trigger_annotation_name).getTriggerId();
                    log_trigger_annotation = log_triggers_map.at(trigger_annotation_name);
                }
                string exception_id;
                if (exception_map.count(exception_annotation_name) > 0) {
                    exception_id = exception_map.at(exception_annotation_name).getBehaviorId();
                }
                if (asset_name == "*") {
                    asset_name = "Any";
                    url = "Any";
                    uri = "Any";
                }

                RulesConfigRulebase rules_config = createMultiRulesSections(
                    url,
                    uri,
                    practice_annotation_name,
                    "WebApplication",
                    trigger_annotation_name,
                    log_trigger_id,
                    "log",
                    web_user_res_vec,
                    asset_name,
                    exception_annotation_name,
                    exception_id
                );
                string port = "80";
                string full_url = asset_name == "Any" ? "" : url + "/" + uri + ":" + port;
                string asset_id = rules_config.getAsstId();
                string practice_id = rules_config.getPracticeId();

                if (!generated_apps.count(full_url)) {
                    WebAppSection web_app = WebAppSection(
                        full_url,
                        asset_id,
                        asset_name,
                        asset_id,
                        asset_name,
                        practice_id,
                        practice_annotation_name,
                        practice_map.at(practice_annotation_name),
                        log_trigger_annotation,
                        default_rule.getMode(),
                        parsed_trusted_sources
                    );

                    parsed_web_apps_set.insert(web_app);
                    parsed_rules.push_back(rules_config);
                    generated_apps.insert(full_url);
                }
            }

            string exception_name;
            if (!default_rule.getExceptions().empty()) {
                exception_name = default_rule.getExceptions()[0];
                if (!extractExceptions(exception_name, exception_map, parsed_exeptions)) return "";
            }

            string trigger_name;
            if (!default_rule.getLogTriggers().empty()) {
                trigger_name = default_rule.getLogTriggers()[0];
                if (!extractTriggers(
                    trigger_name,
                    log_triggers_map,
                    parsed_log_triggers,
                    syslog_address,
                    syslog_port)) return "";
            }

            vector<pair<string, string>> default_web_user_res_vec;
            string web_user_res_annotation_name = default_rule.getCustomResponse();
            if (!extractWebUserResponse(
                web_user_res_annotation_name,
                web_user_res_map,
                default_web_user_res_vec,
                parsed_web_user_res)
            ) return "";

            AppSecTrustedSources default_parsed_trusted_sources;
            string trusted_sources_annotation_name = default_rule.getTrustedSources();
            string source_identifiers_annotation_name = default_rule.getSourceIdentifiers();
            if (!extractTrustedSources(
                "Any",
                trusted_sources_annotation_name,
                source_identifiers_annotation_name,
                trusted_sources_map,
                source_identifiers_map,
                default_parsed_trusted_sources)
            ) {
                dbgWarning(D_K8S_POLICY)
                    << "Failed extracting trused sources. Trusted source name: "
                    << trusted_sources_annotation_name
                    << ", Source identifiers annotation name: "
                    << source_identifiers_annotation_name;
                return "";
            }

            string practice_name;
            if (!default_rule.getPractices().empty()) {
                practice_name = default_rule.getPractices()[0];
            }
            if (!practice_name.empty() && practice_map.count(practice_name) == 0) {
                AppsecSpecParser<AppSecPracticeSpec> appsec_practice;
                res = messaging->sendObject(appsec_practice,
                                    I_Messaging::Method::GET,
                                    "kubernetes.default.svc",
                                    443,
                                    conn_flags,
                                    "/apis/openappsec.io/v1beta1/practices/" + practice_name,
                                    "Authorization: Bearer " + token + "\nConnection: close");
                if(!res) {
                    dbgError(D_K8S_POLICY) << "Failed to retrieve AppSec practice for the dafult practice";
                    return "";
                }
                practice_map.emplace(practice_name, appsec_practice.getSpec());
                dbgTrace(D_K8S_POLICY)
                    << "Successfully retrieved AppSec practice"
                    << practice_name
                    << appsec_practice.getSpec();
            }

            if (item.getSpec().isDefaultBackendExists()) {
                dbgTrace(D_K8S_POLICY) << "Default Backend exists in the ingress";
                bool should_create_rule = false;
                if (cleanup_rule_mode != "Prevent") {
                    if (default_rule.getMode().find("prevent") != string::npos) {
                        cleanup_rule_mode = "Prevent";
                        should_create_rule = true;
                    }
                } else if (cleanup_rule_mode == "Inactive") {
                    if (default_rule.getMode().find("detect") != string::npos) {
                        cleanup_rule_mode = "Detect";
                        should_create_rule = true;
                    }
                }

                if (should_create_rule) {
                    dbgTrace(D_K8S_POLICY) << "Cleanup rule mode: " << cleanup_rule_mode;
                    specific_assets_from_ingress.insert({"Any", "Any"});
                }
            }

            // TBD: fix this to support multiple exceptions!
            for (const pair<string, string> &asset : specific_assets_from_ingress) {
                string log_trigger_id;
                LogTriggerSection log_trigger_section;
                if (log_triggers_map.count(trigger_name) > 0) {
                    log_trigger_id = log_triggers_map.at(trigger_name).getTriggerId();
                    log_trigger_section = log_triggers_map.at(trigger_name);
                }
                string exception_id;
                if (
                    !default_rule.getExceptions().empty() && exception_map.count(default_rule.getExceptions()[0]) > 0
                ) {
                    exception_id = exception_map.at(default_rule.getExceptions()[0]).getBehaviorId();
                }
                string asset_name = asset.first == "Any" && asset.second == "Any" ? "Any" : asset.first + asset.second;
                RulesConfigRulebase default_rule_config = createMultiRulesSections(
                    asset.first,
                    asset.second,
                    practice_name,
                    "WebApplication",
                    trigger_name,
                    log_trigger_id,
                    "log",
                    default_web_user_res_vec,
                    asset_name,
                    exception_name,
                    exception_id
                );
                if (asset_name == "Any") {
                    cleanup_rule = default_rule_config;
                } else {
                    parsed_rules.push_back(default_rule_config);
                }

                string asset_id = default_rule_config.getAsstId();
                string practice_id = default_rule_config.getPracticeId();

                if (!generated_apps.count(asset.first + asset.second)) {
                    WebAppSection web_app = WebAppSection(
                        asset.first + asset.second,
                        asset_id,
                        "Any",
                        asset_id,
                        "Any",
                        practice_id,
                        practice_name,
                        practice_map.at(practice_name),
                        log_trigger_section,
                        default_rule.getMode(),
                        default_parsed_trusted_sources
                    );
                    parsed_web_apps_set.insert(web_app);
                    generated_apps.insert(asset.first + asset.second);
                }
            }
        }

        if (cleanup_rule_mode != "Inactive") {
            dbgTrace(D_K8S_POLICY) << "Pushing a cleanup rule";
            parsed_rules.push_back(cleanup_rule);
        }

        for (const auto & parsed_web_app : parsed_web_apps_set) {
            parsed_web_apps.push_back(parsed_web_app);
        }

        dbgTrace(D_K8S_POLICY)
            << "Policy creation summery:" << endl
            << "Web applications ammount: "
            << parsed_web_apps.size()
            << endl << "Rules ammount: "
            << parsed_rules.size()
            << endl << "Triggers ammount: "
            << parsed_log_triggers.size()
            << endl << "Web user response ammount: "
            << parsed_web_user_res.size();

        TriggersWrapper triggers_section(TriggersRulebase(parsed_log_triggers, parsed_web_user_res));
        AppSecWrapper waap_section = createMultipleAppSecSections(parsed_web_apps);
        RulesConfigWrapper rules_config_section(parsed_rules);

        ExceptionsWrapper exceptions_section = createExceptionSection(parsed_exeptions);
        SecurityAppsWrapper security_app_section = SecurityAppsWrapper(
            waap_section,
            triggers_section,
            rules_config_section,
            exceptions_section,
            policy_version
        );

        SettingsWrapper profiles_section = createProfilesSection();
        K8sPolicyWrapper k8s_policy = K8sPolicyWrapper(profiles_section, security_app_section);

        return dumpPolicyToFile(k8s_policy);
    }

    SettingsWrapper
    createProfilesSection()
    {
        string agent_settings_key = "agent.test.k8s.policy";
        string agent_settings_value = "k8s policy";
        AgentSettingsSection agent_setting_1 = AgentSettingsSection(agent_settings_key, agent_settings_value);

        SettingsRulebase settings_rulebase_1 = SettingsRulebase({agent_setting_1});
        return SettingsWrapper(settings_rulebase_1);
    }

    LogTriggerSection
    createLogTriggersSection(
        const string &trigger_name,
        bool is_syslog = false,
        const string &syslog_port = string(),
        const AppsecTriggerSpec &trigger_spec = AppsecTriggerSpec())
    {
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
        bool logToSyslog = is_syslog ? is_syslog : trigger_spec.getAppsecTriggerLogDestination().isSyslogNeeded();
        bool responseBody = trigger_spec.getAppsecTriggerAdditionalSuspiciousEventsLogging().isResponseBody();
        bool extendLogging = trigger_spec.getAppsecTriggerAdditionalSuspiciousEventsLogging().isEnabled();
        int cefPortNum = logToCef ? trigger_spec.getAppsecTriggerLogDestination().getCefServerUdpPort() : 0;
        string cefIpAddress =
            logToCef ? trigger_spec.getAppsecTriggerLogDestination().getCefServerIpv4Address() : "";
        int syslogPortNum;
        try {
            syslogPortNum =
                is_syslog ?
                stoi(syslog_port) :
                logToSyslog ?
                trigger_spec.getAppsecTriggerLogDestination().getSyslogServerUdpPort() :
                514;
        } catch (const exception &err) {
            dbgWarning(D_K8S_POLICY)
                << "Failed to convert port number from string. Port: "
                << syslog_port
                << ". Setting default value 514";
            syslogPortNum = 514;
        }
        string syslogIpAddress =
            is_syslog ?
            trigger_name :
            logToSyslog ?
            trigger_spec.getAppsecTriggerLogDestination().getSyslogServerIpv4Address() :
            "";

        LogTriggerSection log(
            trigger_name,
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
        const string &trigger_name,
        const AppSecWebUserResponseSpec &trigger_spec)
    {
        string mode = trigger_spec.getMode();
        string response_body = trigger_spec.getMessageBody();
        string response_title = trigger_spec.getMessageTitle();
        int response_code = trigger_spec.getHttpResponseCode();

        WebUserResponseTriggerSection web_user_res(
            trigger_name,
            mode,
            response_body,
            response_code,
            response_title
        );

        return web_user_res;
    }

    ExceptionsWrapper
    createExceptionSection(const set<InnerException> &_exeptions)
    {
        vector<InnerException> exeptions(_exeptions.begin(), _exeptions.end());
        ExceptionsRulebase exception_1(exeptions);
        return ExceptionsWrapper({exception_1});
    }

    RulesConfigRulebase
    createMultiRulesSections(
        const string &url,
        const string &uri,
        const string &practice_name,
        const string &practice_type,
        const string &trigger_name,
        const string &trigger_id,
        const string &trigger_type,
        const vector<pair<string, string>> &web_user_res_vec,
        const string &asset_name,
        const string &exception_name,
        const string &exception_id)
    {
        string practice_id;
        if (practice_name_to_id_map.count(practice_name)) {
            practice_id = practice_name_to_id_map[practice_name];
        } else {
            try {
                practice_id = to_string(boost::uuids::random_generator()());
            } catch (const boost::uuids::entropy_error &e) {
                dbgWarning(D_K8S_POLICY) << "Failed to generate Practice ID. Error: " << e.what();
                //TBD: return Maybe as part of future error handling
            }
        }

        PracticeSection practice = PracticeSection(practice_id, practice_type, practice_name);
        ParametersSection exception_param = ParametersSection(exception_id, exception_name);

        vector<RulesTriggerSection> triggers;
        if (!trigger_id.empty()) {
            triggers.push_back(RulesTriggerSection(trigger_name, trigger_id, trigger_type));
        }
        for (const pair<string, string> &web_user_res : web_user_res_vec) {
            triggers.push_back(RulesTriggerSection(web_user_res.first, web_user_res.second, "WebUserResponse"));
        }

        RulesConfigRulebase rules_config_1 = RulesConfigRulebase(
            asset_name,
            url,
            uri,
            {practice},
            {exception_param},
            triggers
        );
        return rules_config_1;
    }

    AppSecWrapper
    createMultipleAppSecSections(vector<WebAppSection> &web_apps)
    {
        AppSecRulebase app_sec_rulebase = AppSecRulebase(web_apps, {});
        return AppSecWrapper(app_sec_rulebase);
    }

private:
    I_Messaging* messaging = nullptr;
    Flags<MessageConnConfig> conn_flags;
    const string cluster_url = "https://kubernetes.default.svc";
    const string service_account = "/var/run/secrets/kubernetes.io/serviceaccount";
    const string cacert_path = service_account + "/ca.crt";
    string token;
    map<string, string> practice_name_to_id_map;

    bool
    getClusterId()
    {
        dbgTrace(D_K8S_POLICY) << "Getting cluster UID";
        NamespaceData namespaces_data;
        bool res = messaging->sendObject(
                    namespaces_data,
                    I_Messaging::Method::GET,
                    "kubernetes.default.svc",
                    443,
                    conn_flags,
                    "/api/v1/namespaces/",
                    "Authorization: Bearer " + token + "\nConnection: close"
        );

        if(!res) {
            dbgError(D_K8S_POLICY) << "Failed to retrieve K8S namespace data";
            return false;
        }

        string uid;
        for (const SingleNamespaceData &ns : namespaces_data.getItems()) {
            if (ns.getMetadata().getName() == "kube-system") {
                uid = ns.getMetadata().getUID();
                dbgTrace(D_K8S_POLICY) << "Found k8s cluster UID: " << uid;
                I_Environment *env = Singleton::Consume<I_Environment>::by<K8sPolicyGenerator::Impl>();
                env->getConfigurationContext().registerValue<string>(
                    "k8sClusterId",
                    uid,
                    EnvKeyAttr::LogSection::SOURCE
                );
                Singleton::Consume<I_AgentDetails>::by<K8sPolicyGenerator::Impl>()->setClusterId(uid);
                return true;
            }
        }
        return false;
    }

    const string
    dumpPolicyToFile(const K8sPolicyWrapper &k8s_policy) const
    {
        stringstream ss;
        {
            cereal::JSONOutputArchive ar(ss);
            k8s_policy.serialize(ar);
        }
        string policy_str = ss.str();
        ofstream policy_file("/tmp/k8s.policy");
        policy_file << policy_str;
        policy_file.close();
        return policy_str;
    }

    string
    readFileContent(const string&file_path)
    {
        ifstream file(file_path);
        stringstream buffer;

        buffer << file.rdbuf();

        return buffer.str();
    }

    string
    retrieveToken()
    {
        return readFileContent(service_account + "/token");
    }

    bool
    extractExceptions(
        const string &exception_annotation_name,
        map<string, InnerException> &exception_map,
        set<InnerException> &parsed_exeptions)
    {
        if (!exception_annotation_name.empty() && exception_map.count(exception_annotation_name) == 0) {
            dbgTrace(D_K8S_POLICY) << "Trying to retrieve exceptions for " << exception_annotation_name;
            AppsecSpecParser<vector<AppsecExceptionSpec>> appsec_exception;
            bool res = messaging->sendObject(appsec_exception,
                                I_Messaging::Method::GET,
                                "kubernetes.default.svc",
                                443,
                                conn_flags,
                                "/apis/openappsec.io/v1beta1/exceptions/" + exception_annotation_name,
                                "Authorization: Bearer " + token + "\nConnection: close");
            if(!res) {
                dbgError(D_K8S_POLICY) << "Failed to retrieve AppSec exception";
                return false;
            }
            dbgTrace(D_K8S_POLICY)
                << "Successfuly retrieved AppSec exceptions for "
                << exception_annotation_name;

            for (const AppsecExceptionSpec &parsed_exeption : appsec_exception.getSpec()) {
                ExceptionMatch exception_match(parsed_exeption);
                string behavior =
                    parsed_exeption.getAction() == "skip" ?
                    "ignore" :
                    parsed_exeption.getAction();
                ExceptionBehavior exception_behavior("action", behavior);
                InnerException inner_exception(exception_behavior, exception_match);
                exception_map.emplace(exception_annotation_name, inner_exception);
                parsed_exeptions.insert(inner_exception);
            }
        }
        return true;
    }

    bool
    extractTriggers(
        const string &trigger_annotation_name,
        map<string, LogTriggerSection> &log_triggers_map,
        vector<LogTriggerSection> &parsed_log_triggers,
        const string &syslog_address = string(),
        const string &syslog_port = string())
    {
        if (trigger_annotation_name.empty() && !syslog_address.empty()) {
            if (!IPAddr::isValidIPAddr(syslog_address)) {
                dbgWarning(D_K8S_POLICY) << "Syslog address is invalid. Address: " << syslog_address;
                return false;
            }
            dbgTrace(D_K8S_POLICY)
                << "Creating default syslog log section with syslog service address: "
                << syslog_address
                << ", Port: "
                << syslog_port;

            LogTriggerSection log_triggers_section =
                createLogTriggersSection(syslog_address, true, syslog_port);
            log_triggers_map.emplace(trigger_annotation_name, log_triggers_section);
            parsed_log_triggers.push_back(log_triggers_section);
        } else if (!trigger_annotation_name.empty() && log_triggers_map.count(trigger_annotation_name) == 0) {
            dbgTrace(D_K8S_POLICY) << "Trying to retrieve triggers for " << trigger_annotation_name;
            AppsecSpecParser<AppsecTriggerSpec> appsec_trigger;
            bool res = messaging->sendObject(appsec_trigger,
                                I_Messaging::Method::GET,
                                "kubernetes.default.svc",
                                443,
                                conn_flags,
                                "/apis/openappsec.io/v1beta1/logtriggers/" + trigger_annotation_name,
                                "Authorization: Bearer " + token + "\nConnection: close");
            if(!res) {
                dbgError(D_K8S_POLICY) << "Failed to retrieve AppSec triggers";
                return false;
            }
            dbgTrace(D_K8S_POLICY)
                << "Successfuly retrieved AppSec exceptions for "
                << trigger_annotation_name
                << ":\n"
                << appsec_trigger.getSpec();

            LogTriggerSection log_triggers_section =
                createLogTriggersSection(trigger_annotation_name, false, "", appsec_trigger.getSpec());
            log_triggers_map.emplace(trigger_annotation_name, log_triggers_section);
            parsed_log_triggers.push_back(log_triggers_section);
        }
        return true;
    }

    bool
    extractTrustedSources(
        const string &asset_name,
        const string &trusted_sources_name,
        const string &source_identifiers_name,
        map<string, TrustedSourcesSpec> &trusted_sources_map,
        map<string, vector<SourceIdentifierSpec>> &source_identifiers_map,
        AppSecTrustedSources &parsedTrustedSources)
    {
        if (trusted_sources_name.empty() && source_identifiers_name.empty()) return true;
        if (trusted_sources_name.empty() ^ source_identifiers_name.empty()) {
            dbgInfo(D_K8S_POLICY)
                << "Trusted Sources or Source Identifier were not provided. Truster Sources: "
                << trusted_sources_name
                << ", Source Identidier: "
                << source_identifiers_name;
            return false;
        }

        AppsecSpecParser<TrustedSourcesSpec> trusted_sources_from_ingress;
        AppsecSpecParser<vector<SourceIdentifierSpec>> source_identifier_from_ingress;

        // Parsing trusted sources from the k8s API
        if (!trusted_sources_map.count(trusted_sources_name)) {
            dbgTrace(D_K8S_POLICY) << "Trying to retrieve trusted sources for: " << trusted_sources_name;
            bool res = messaging->sendObject(trusted_sources_from_ingress,
                                I_Messaging::Method::GET,
                                "kubernetes.default.svc",
                                443,
                                conn_flags,
                                "/apis/openappsec.io/v1beta1/trustedsources/" + trusted_sources_name,
                                "Authorization: Bearer " + token + "\nConnection: close");
            if(!res) {
                dbgError(D_K8S_POLICY) << "Failed to retrieve trusted sources";
                return false;
            }
            trusted_sources_map[trusted_sources_name] = trusted_sources_from_ingress.getSpec();
        }

        // Parsing source identifiers from the k8s API
        if (!source_identifiers_map.count(source_identifiers_name)) {
            dbgTrace(D_K8S_POLICY) << "Trying to retrieve sources identifiers for: " << source_identifiers_name;
            bool res = messaging->sendObject(source_identifier_from_ingress,
                                I_Messaging::Method::GET,
                                "kubernetes.default.svc",
                                443,
                                conn_flags,
                                "/apis/openappsec.io/v1beta1/sourcesidentifiers/" + source_identifiers_name,
                                "Authorization: Bearer " + token + "\nConnection: close");
            if(!res) {
                dbgError(D_K8S_POLICY) << "Failed to retrieve trusted sources";
                return false;
            }
            source_identifiers_map[source_identifiers_name] = source_identifier_from_ingress.getSpec();
        }

        // Generating the (Trusted Sources X Source Identifiers) matrix
        vector<SourcesIdentifiers> generated_trusted_json;
        for (const SourceIdentifierSpec &src_ident : source_identifiers_map[source_identifiers_name]) {
            for (const string &trusted_src : trusted_sources_map[trusted_sources_name].getSourcesIdentifiers()) {
                if (src_ident.getValues().empty()) {
                    generated_trusted_json.push_back(SourcesIdentifiers(src_ident.getSourceIdentifier(), trusted_src));
                } else {
                    for (const string &val : src_ident.getValues()) {
                        string src_key = src_ident.getSourceIdentifier() + ":" + val;
                        generated_trusted_json.push_back(SourcesIdentifiers(src_key, trusted_src));
                    }
                }
            }
        }

        parsedTrustedSources = AppSecTrustedSources(
            asset_name,
            trusted_sources_map[trusted_sources_name].getMinNumOfSources(),
            generated_trusted_json
        );

        return true;
    }

    bool
    extractWebUserResponse(
        const string &web_user_res_annotation_name,
        map<string, WebUserResponseTriggerSection> &web_user_res_map,
        vector<pair<string, string>> &web_user_res_vec,
        vector<WebUserResponseTriggerSection> &parsed_web_user_res)
    {
        if(!web_user_res_annotation_name.empty()) {
            dbgTrace(D_K8S_POLICY) << "Trying to retrieve web user response for: " << web_user_res_annotation_name;
            AppsecSpecParser<AppSecWebUserResponseSpec> appsec_web_user_res;
            bool res = messaging->sendObject(appsec_web_user_res,
                                I_Messaging::Method::GET,
                                "kubernetes.default.svc",
                                443,
                                conn_flags,
                                "/apis/openappsec.io/v1beta1/customresponses/" + web_user_res_annotation_name,
                                "Authorization: Bearer " + token + "\nConnection: close");
            if(!res) {
                dbgError(D_K8S_POLICY) << "Failed to retrieve appsec web user res";
                return false;
            }

            if(web_user_res_map.count(web_user_res_annotation_name) == 0) {
                WebUserResponseTriggerSection web_user_res_section = createWebUserResponseTriggerSection(
                    web_user_res_annotation_name,
                    appsec_web_user_res.getSpec());

                web_user_res_map.emplace(web_user_res_annotation_name, web_user_res_section);
                parsed_web_user_res.push_back(web_user_res_section);
                web_user_res_vec.push_back(
                    pair<string, string>(
                        web_user_res_section.getTriggerName(),
                        web_user_res_section.getTriggerId()
                    )
                );
            } else {
                web_user_res_vec.push_back(
                    pair<string, string>(
                        web_user_res_map.at(web_user_res_annotation_name).getTriggerName(),
                        web_user_res_map.at(web_user_res_annotation_name).getTriggerId()
                    )
                );
            }

            dbgTrace(D_K8S_POLICY)
                << "Successfuly retrieved AppSec web user response for: "
                << web_user_res_annotation_name
                << ":\n"
                << appsec_web_user_res.getSpec();
        }
        return true;
    }
};


K8sPolicyGenerator::K8sPolicyGenerator()
        :
    Component("K8sPolicyGenerator"),
    pimpl(make_unique<K8sPolicyGenerator::Impl>()) {}

K8sPolicyGenerator::~K8sPolicyGenerator() {}

void
K8sPolicyGenerator::init()
{
    pimpl->init();
}

void
K8sPolicyGenerator::preload()
{}
