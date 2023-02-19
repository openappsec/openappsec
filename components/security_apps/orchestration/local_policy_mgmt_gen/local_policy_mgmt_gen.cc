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

#include "local_policy_mgmt_gen.h"

#include <algorithm>
#include <cctype>
#include <iostream>
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
#include "i_shell_cmd.h"
#include "customized_cereal_map.h"
#include "include/appsec_practice_section.h"
#include "include/ingress_data.h"
#include "include/settings_section.h"
#include "include/triggers_section.h"
#include "include/k8s_policy_common.h"
#include "include/exceptions_section.h"
#include "include/rules_config_section.h"
#include "include/trusted_sources_section.h"
#include "include/policy_maker_utils.h"

using namespace std;

USE_DEBUG_FLAG(D_K8S_POLICY);

const static string local_appsec_policy_path = "/tmp/local_appsec.policy";
const static string open_appsec_io = "openappsec.io/";
const static string policy_key = "policy";
const static string syslog_key = "syslog";
const static string mode_key = "mode";
const static string local_mgmt_policy_path = "/conf/local_policy.yaml";
// LCOV_EXCL_START Reason: no test exist

class NamespaceMetadata
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgInfo(D_K8S_POLICY) << "NamespaceMetadata load";
        parseAppsecJSONKey<string>("name", name, archive_in);
        parseAppsecJSONKey<string>("uid", uid, archive_in);
    }

    const string & getName() const { return name; }
    const string & getUID() const { return uid; }

private:
    string name;
    string uid;
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
    loadJson(const string &json)
    {
        dbgTrace(D_K8S_POLICY) << "Loading namespace data";
        string modified_json = json;
        modified_json.pop_back();
        stringstream in;
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

    const vector<SingleNamespaceData> & getItems() const { return items; }

private:
    vector<SingleNamespaceData> items;
};

class LocalPolicyMgmtGenerator::Impl
        :
    public Singleton::Provide<I_LocalPolicyMgmtGen>::From<LocalPolicyMgmtGenerator>,
    public Singleton::Consume<I_Messaging>,
    public Singleton::Consume<I_AgentDetails>,
    public Singleton::Consume<I_Environment>,
    public Singleton::Consume<I_MainLoop>,
    public Singleton::Consume<I_OrchestrationTools>,
    public Singleton::Consume<I_ShellCmd>
{
public:
    void
    init()
    {
        token = retrieveToken();
        if (token.empty()) {
            dbgInfo(D_K8S_POLICY) << "Initializing Linux Local-Policy generator";
            env_type = LocalPolicyEnv::LINUX;
            return;
        }
        env_type = LocalPolicyEnv::K8S;
        dbgInfo(D_K8S_POLICY) << "Initializing K8S policy generator";
        conn_flags.setFlag(MessageConnConfig::SECURE_CONN);
        conn_flags.setFlag(MessageConnConfig::IGNORE_SSL_VALIDATION);

        messaging = Singleton::Consume<I_Messaging>::by<LocalPolicyMgmtGenerator::Impl>();

        Singleton::Consume<I_MainLoop>::by<LocalPolicyMgmtGenerator::Impl>()->addOneTimeRoutine(
            I_MainLoop::RoutineType::Offline,
            [this] ()
            {
                ScopedContext ctx;
                ctx.registerValue<bool>("k8s_env", true);
                while(!getClusterId()) {
                    Singleton::Consume<I_MainLoop>::by<LocalPolicyMgmtGenerator::Impl>()->yield(chrono::seconds(1));
                }
                return;
            },
            "Get k8s cluster ID"
        );
    }

    const string & getPolicyPath(void) const override { return local_appsec_policy_path; }

    template<class container_it>
    container_it
    extractElement(container_it begin, container_it end, const string &element_name)
    {
        dbgTrace(D_K8S_POLICY) << "Tryting to find element: " << element_name;
        for (container_it it = begin; it < end; it++) {
            if (element_name == it->getName()) {
                dbgTrace(D_K8S_POLICY) << "Element with name " << element_name << "was found";
                return it;
            }
        }
        dbgTrace(D_K8S_POLICY) << "Element with name " << element_name << "was not found";
        return end;
    }

    template<class T>
    Maybe<T>
    getObjectFromCluster(const string &path)
    {
        T object;
        bool res = messaging->sendObject(
            object,
            I_Messaging::Method::GET,
            "kubernetes.default.svc",
            443,
            conn_flags,
            path,
            "Authorization: Bearer " + token + "\nConnection: close"
        );

        if (res) return object;

        return genError("Was not able to get object form k8s cluser in path: " + path);
    }

    string
    parseLinuxPolicy(const string &policy_version)
    {
        dbgFlow(D_K8S_POLICY);

        string policy_path = getConfigurationFlagWithDefault(
            getFilesystemPathConfig() + local_mgmt_policy_path,
            "local_mgmt_policy"
        );

        auto maybe_policy_as_json = Singleton::Consume<I_ShellCmd>::by<LocalPolicyMgmtGenerator::Impl>()->
            getExecOutput(getFilesystemPathConfig() + "/bin/yq " + policy_path + " -o json");

        if (!maybe_policy_as_json.ok()) {
            dbgWarning(D_K8S_POLICY) << "Could not convert policy from yaml to json";
            return "";
        }

        auto i_orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<LocalPolicyMgmtGenerator::Impl>();
        auto maybe_policy = i_orchestration_tools->jsonStringToObject<AppsecLinuxPolicy>(
            maybe_policy_as_json.unpack()
        );

        if (!maybe_policy.ok()) {
            dbgWarning(D_K8S_POLICY) << "Policy was not loaded. Error: " << maybe_policy.getErr();
            return "";
        }

        AppsecLinuxPolicy appsec_policy = maybe_policy.unpack();
        ScopedContext ctx;
        ctx.registerFunc<AppsecLinuxPolicy>("get_linux_local_policy", [&appsec_policy](){
            return appsec_policy;
        });

        list<ParsedRule> specific_rules = appsec_policy.getAppsecPolicySpec().getSpecificRules();
        ParsedRule default_rule = appsec_policy.getAppsecPolicySpec().getDefaultRule();

        string asset;
        string annotation_type;
        string annotation_name;
        string policy_annotation;
        string syslog_address;
        string syslog_port;

        set<string> generated_apps;
        set<WebAppSection> parsed_web_apps_set;
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

            vector<pair<string, string>> web_user_res_vec;
            extractExceptions(
                exception_annotation_name,
                exception_map,
                parsed_exeptions,
                appsec_policy.getAppsecExceptionSpecs());


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
                vector<AppSecPracticeSpec> appsec_practice = appsec_policy.getAppSecPracticeSpecs();
                auto it = extractElement(appsec_practice.begin(), appsec_practice.end(), practice_annotation_name);
                if (it == appsec_practice.end()) {
                    dbgWarning(D_K8S_POLICY) << "Unable to find practice. Practice name: " << practice_annotation_name;
                    return "";
                }
                practice_map.emplace(practice_annotation_name, *it);
                dbgTrace(D_K8S_POLICY)
                    << "Successfully retrieved AppSec practice "
                    << practice_annotation_name;
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
            string full_url = asset_name == "Any" ? "" : url + uri + ":" + port;
            string asset_id = rules_config.getAssetId();
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
        } //end specific rules

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
            vector<AppSecPracticeSpec> appsec_practice = appsec_policy.getAppSecPracticeSpecs();
            auto it = extractElement(appsec_practice.begin(), appsec_practice.end(), practice_name);
            if(it == appsec_practice.end()) {
                dbgWarning(D_K8S_POLICY) << "Failed to retrieve AppSec practice for the dafult practice";
                return "";
            }
            practice_map.emplace(practice_name, *it);
            dbgTrace(D_K8S_POLICY)
                << "Successfully retrieved AppSec practice"
                << practice_name;
        }

        vector<WebAppSection> parsed_web_apps(parsed_web_apps_set.begin(), parsed_web_apps_set.end());

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
        PolicyWrapper policy_wrapper = PolicyWrapper(profiles_section, security_app_section);

        return dumpPolicyToFile(policy_wrapper);
    }

    LocalPolicyEnv getEnvType() const { return env_type;}

    string
    parseK8sPolicy(const string &policy_version)
    {
        ScopedContext ctx;
        ctx.registerValue<bool>("k8s_env", true);

        auto maybe_ingress = getObjectFromCluster<IngressData>("/apis/networking.k8s.io/v1/ingresses");

        if (!maybe_ingress.ok()) {
            // TBD: Error handling : INXT-31444
            dbgError(D_K8S_POLICY)
                << "Failed to retrieve K8S Ingress configurations. Error: "
                << maybe_ingress.getErr();
            return "";
        }

        IngressData ingress = maybe_ingress.unpack();

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
            auto maybe_appsec_policy = getObjectFromCluster<AppsecSpecParser<AppsecPolicySpec>>(
                "/apis/openappsec.io/v1beta1/policies/" + policy_annotation
            );

            if (!maybe_appsec_policy.ok()) {
                dbgError(D_K8S_POLICY) << "Failed to retrieve AppSec policy. Error: " << maybe_appsec_policy.getErr();
                return "";
            }

            AppsecSpecParser<AppsecPolicySpec> appsec_policy = maybe_appsec_policy.unpack();

            list<ParsedRule> specific_rules = appsec_policy.getSpec().getSpecificRules();
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
                    auto maybe_appsec_practice = getObjectFromCluster<AppsecSpecParser<AppSecPracticeSpec>>(
                        "/apis/openappsec.io/v1beta1/practices/" + practice_annotation_name
                    );

                    if (!maybe_appsec_practice.ok()) {
                        dbgError(D_K8S_POLICY)
                            << "Failed to retrieve AppSec practice for asset "
                            << asset_name
                            << ". Error: "
                            << maybe_appsec_practice.getErr();
                        return "";
                    }

                    AppsecSpecParser<AppSecPracticeSpec> appsec_practice = maybe_appsec_practice.unpack();
                    practice_map.emplace(practice_annotation_name, appsec_practice.getSpec());
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
                string asset_id = rules_config.getAssetId();
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
                auto maybe_appsec_practice = getObjectFromCluster<AppsecSpecParser<AppSecPracticeSpec>>(
                    "/apis/openappsec.io/v1beta1/practices/" + practice_name
                );

                if (!maybe_appsec_practice.ok()) {
                    dbgError(D_K8S_POLICY)
                        << "Failed to retrieve AppSec practice for the dafult practice. Error: "
                        << maybe_appsec_practice.getErr();
                    return "";
                }

                AppsecSpecParser<AppSecPracticeSpec> appsec_practice = maybe_appsec_practice.unpack();
                practice_map.emplace(practice_name, appsec_practice.getSpec());
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

                string asset_id = default_rule_config.getAssetId();
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
        PolicyWrapper k8s_policy = PolicyWrapper(profiles_section, security_app_section);

        return dumpPolicyToFile(k8s_policy);
    }

    string
    parsePolicy(const string &policy_version)
    {
        return env_type == LocalPolicyEnv::K8S ? parseK8sPolicy(policy_version) : parseLinuxPolicy(policy_version);
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
        const AppSecCustomResponseSpec &trigger_spec)
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
    string token = "";
    LocalPolicyEnv env_type;
    map<string, string> practice_name_to_id_map;

    bool
    isPlaygroundEnv()
    {
        string playground_variable = "PLAYGROUND";
        const char *env_string = getenv(playground_variable.c_str());

        if (env_string) {
            string env_value = env_string;
            transform(
                env_value.begin(),
                env_value.end(),
                env_value.begin(),
                [](unsigned char c) { return tolower(c); }
            );
            return env_value == "true";
        }

        return false;
    }
    
    bool
    getClusterId()
    {
        string playground_uid = isPlaygroundEnv() ? "playground-" : "";

        dbgTrace(D_K8S_POLICY) << "Getting cluster UID";
        auto maybe_namespaces_data = getObjectFromCluster<NamespaceData>("/api/v1/namespaces/");

        if (!maybe_namespaces_data.ok()) {
            dbgError(D_K8S_POLICY)
                << "Failed to retrieve K8S namespace data. Error: "
                << maybe_namespaces_data.getErr();
            return false;
        }

        NamespaceData namespaces_data = maybe_namespaces_data.unpack();

        string uid;
        for (const SingleNamespaceData &ns : namespaces_data.getItems()) {
            if (ns.getMetadata().getName() == "kube-system") {
                uid = ns.getMetadata().getUID();
                dbgTrace(D_K8S_POLICY) << "Found k8s cluster UID: " << uid;
                I_Environment *env = Singleton::Consume<I_Environment>::by<LocalPolicyMgmtGenerator::Impl>();
                env->getConfigurationContext().registerValue<string>(
                    "k8sClusterId",
                    uid,
                    EnvKeyAttr::LogSection::SOURCE
                );
                auto i_agent_details = Singleton::Consume<I_AgentDetails>::by<LocalPolicyMgmtGenerator::Impl>();
                i_agent_details->setClusterId(playground_uid + uid);
                return true;
            }
        }
        return false;
    }

    const string
    dumpPolicyToFile(const PolicyWrapper &policy) const
    {
        stringstream ss;
        {
            cereal::JSONOutputArchive ar(ss);
            policy.save(ar);
        }
        string policy_str = ss.str();
        ofstream policy_file(local_appsec_policy_path);
        policy_file << policy_str;
        policy_file.close();
        return policy_str;
    }

    string
    readFileContent(const string&file_path)
    {
        try {
            ifstream file(file_path);
            stringstream buffer;
            buffer << file.rdbuf();
            return buffer.str();
        } catch (ifstream::failure &f) {
            dbgWarning(D_ORCHESTRATOR)
                << "Cannot read the file"
                << " File: " << file_path
                << " Error: " << f.what();
            return "";
        }
    }

    string
    retrieveToken()
    {
        return readFileContent(service_account + "/token");
    }

    void
    extractExceptions(
        const string &exception_annotation_name,
        map<string, InnerException> &exception_map,
        set<InnerException> &parsed_exeptions,
        const vector<AppsecExceptionSpec> &appsec_excepetion_specs)
    {
        if (!exception_annotation_name.empty() && exception_map.count(exception_annotation_name) == 0) {
            for (const AppsecExceptionSpec &parsed_exeption : appsec_excepetion_specs) {
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
    }

    bool
    extractExceptions(
        const string &exception_annotation_name,
        map<string, InnerException> &exception_map,
        set<InnerException> &parsed_exeptions)
    {
        if (!exception_annotation_name.empty() && exception_map.count(exception_annotation_name) == 0) {
            dbgTrace(D_K8S_POLICY) << "Trying to retrieve exceptions for " << exception_annotation_name;

            auto maybe_appsec_exception = getObjectFromCluster<AppsecSpecParser<vector<AppsecExceptionSpec>>>(
                "/apis/openappsec.io/v1beta1/exceptions/" + exception_annotation_name
            );

            if (!maybe_appsec_exception.ok()) {
                dbgError(D_K8S_POLICY)
                    << "Failed to retrieve AppSec exception. Error: "
                    << maybe_appsec_exception.getErr();
                return false;
            }

            AppsecSpecParser<vector<AppsecExceptionSpec>> appsec_exception = maybe_appsec_exception.unpack();
            dbgTrace(D_K8S_POLICY)
                << "Successfuly retrieved AppSec exceptions for "
                << exception_annotation_name;

            extractExceptions(exception_annotation_name, exception_map, parsed_exeptions, appsec_exception.getSpec());
        }
        return true;
    }

    Maybe<AppsecTriggerSpec>
    getAppsecTriggerSpec(const string &trigger_annotation_name)
    {
        string error_message;
        if (getEnvType() == LocalPolicyEnv::K8S) {
            auto maybe_appsec_trigger = getObjectFromCluster<AppsecSpecParser<AppsecTriggerSpec>>(
                "/apis/openappsec.io/v1beta1/logtriggers/" + trigger_annotation_name
            );

            if (!maybe_appsec_trigger.ok()) {
                error_message = "Failed to retrieve AppSec triggers. Error: " + maybe_appsec_trigger.getErr();
                dbgError(D_K8S_POLICY) <<  error_message;
                return genError(error_message);
            }

            return maybe_appsec_trigger.unpack().getSpec();
        }

        auto maybe_appsec_policy = Singleton::Consume<I_Environment>::by<LocalPolicyMgmtGenerator::Impl>()->
            get<AppsecLinuxPolicy>("get_linux_local_policy");
        if (!maybe_appsec_policy.ok()) {
            error_message = "Failed to retrieve AppSec triggers";
            dbgDebug(D_K8S_POLICY) << error_message;
            return genError(error_message);
        }

        auto triggers_vec = maybe_appsec_policy.unpack().getAppsecTriggerSpecs();
        auto trigger_it = extractElement(triggers_vec.begin(), triggers_vec.end(), trigger_annotation_name);
        if (trigger_it == triggers_vec.end()) {
            error_message = "Failed to retrieve AppSec triggers";
            dbgDebug(D_K8S_POLICY) << error_message;
            return genError(error_message);
        }

        return *trigger_it;
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

            Maybe<AppsecTriggerSpec> maybe_appsec_trigger_spec = getAppsecTriggerSpec(trigger_annotation_name);

            if (!maybe_appsec_trigger_spec.ok()) {
                dbgWarning(D_K8S_POLICY) << "Error: " << maybe_appsec_trigger_spec.getErr();
                return false;
            }

            LogTriggerSection log_triggers_section =
                createLogTriggersSection(trigger_annotation_name, false, "", *maybe_appsec_trigger_spec);
            log_triggers_map.emplace(trigger_annotation_name, log_triggers_section);
            parsed_log_triggers.push_back(log_triggers_section);
        }
        return true;
    }

    Maybe<TrustedSourcesSpec>
    getAppsecTrustedSourceSpecs(const string &trusted_sources_name)
    {
        string error_message;
        if (getEnvType() == LocalPolicyEnv::K8S) {
            auto maybe_trusted_sources_from_ingress = getObjectFromCluster<AppsecSpecParser<TrustedSourcesSpec>>(
                "/apis/openappsec.io/v1beta1/trustedsources/" + trusted_sources_name
            );

            if (!maybe_trusted_sources_from_ingress.ok()) {
                error_message = "Failed to retrieve trusted sources. Error: " +
                    maybe_trusted_sources_from_ingress.getErr();
                dbgError(D_K8S_POLICY) << error_message;
                return genError(error_message);
            }

            return maybe_trusted_sources_from_ingress.unpack().getSpec();
        }

        auto maybe_appsec_policy = Singleton::Consume<I_Environment>::by<LocalPolicyMgmtGenerator::Impl>()->
            get<AppsecLinuxPolicy>("get_linux_local_policy");

        if (!maybe_appsec_policy.ok()) {
            error_message = "Failed to retrieve AppSec triggers";
            dbgDebug(D_K8S_POLICY) << error_message;
            return genError(error_message);
        }

        auto trusted_sources_vec = maybe_appsec_policy.unpack().getAppsecTrustedSourceSpecs();
        auto trusted_sources_it = extractElement(
            trusted_sources_vec.begin(),
            trusted_sources_vec.end(),
            trusted_sources_name);

        if (trusted_sources_it == trusted_sources_vec.end()) {
            error_message = "Failed to retrieve AppSec triggers";
            dbgDebug(D_K8S_POLICY) << error_message;
            return genError(error_message);
        }

        return *trusted_sources_it;
    }

    Maybe<vector<SourceIdentifierSpec>>
    getAppsecSourceIdentifierSpecs(const string &source_identifiers_name)
    {
        string error_message;
        if (getEnvType() == LocalPolicyEnv::K8S) {
            auto maybe_source_identifier = getObjectFromCluster<AppsecSpecParser<vector<SourceIdentifierSpec>>>(
                "/apis/openappsec.io/v1beta1/sourcesidentifiers/" + source_identifiers_name
            );

            if (!maybe_source_identifier.ok()) {
                error_message = "Failed to retrieve trusted sources. Error: " + maybe_source_identifier.getErr();
                dbgError(D_K8S_POLICY) << error_message;
                return genError(error_message);
            }

            return maybe_source_identifier.unpack().getSpec();
        }

        auto maybe_appsec_policy = Singleton::Consume<I_Environment>::by<LocalPolicyMgmtGenerator::Impl>()->
            get<AppsecLinuxPolicy>("get_linux_local_policy");

        if (!maybe_appsec_policy.ok()) {
            error_message = "Failed to retrieve AppSec triggers";
            dbgDebug(D_K8S_POLICY) << error_message;
            return genError(error_message);
        }

        auto source_identifiers_vec = maybe_appsec_policy.unpack().getAppsecSourceIdentifierSpecs();
        auto source_identifier_it = extractElement(
            source_identifiers_vec.begin(),
            source_identifiers_vec.end(),
            source_identifiers_name
        );

        if (source_identifier_it == source_identifiers_vec.end()) {
            error_message = "Failed to retrieve AppSec triggers";
            dbgDebug(D_K8S_POLICY) << error_message;
            return genError(error_message);
        }

        return (*source_identifier_it).getIdentifiers();
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

        // Parsing trusted sources from the k8s API
        if (!trusted_sources_map.count(trusted_sources_name)) {
            dbgTrace(D_K8S_POLICY) << "Trying to retrieve trusted sources for: " << trusted_sources_name;

            auto trusted_sources_from_ingress_spec = getAppsecTrustedSourceSpecs(trusted_sources_name);
            if (!trusted_sources_from_ingress_spec.ok()) {
                dbgWarning(D_K8S_POLICY) << trusted_sources_from_ingress_spec.getErr();
                return false;
            }

            trusted_sources_map[trusted_sources_name] = trusted_sources_from_ingress_spec.unpack();
        }

        // Parsing source identifiers from the k8s API
        if (!source_identifiers_map.count(source_identifiers_name)) {
            dbgTrace(D_K8S_POLICY) << "Trying to retrieve sources identifiers for: " << source_identifiers_name;

            auto source_identifier_from_ingress_spec = getAppsecSourceIdentifierSpecs(source_identifiers_name);

            if (!source_identifier_from_ingress_spec.ok()) {
                dbgWarning(D_K8S_POLICY) << "Error: " << source_identifier_from_ingress_spec.getErr();
                return false;
            }

            source_identifiers_map[source_identifiers_name] = source_identifier_from_ingress_spec.unpack();
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

    Maybe<AppSecCustomResponseSpec>
    getAppSecCustomResponseSpecs(const string &web_user_res_annotation_name)
    {
        string error_message;
        if (getEnvType() == LocalPolicyEnv::K8S) {
            auto maybe_appsec_web_user_res = getObjectFromCluster<AppsecSpecParser<AppSecCustomResponseSpec>>(
                "/apis/openappsec.io/v1beta1/customresponses/" + web_user_res_annotation_name
            );

            if (!maybe_appsec_web_user_res.ok()) {
                error_message = "Failed to retrieve appsec web user res. Error: " +
                    maybe_appsec_web_user_res.getErr();
                dbgError(D_K8S_POLICY) << error_message;
                return genError(error_message);
            }
            return maybe_appsec_web_user_res.unpack().getSpec();
        }

        auto maybe_appsec_policy = Singleton::Consume<I_Environment>::by<LocalPolicyMgmtGenerator::Impl>()->
            get<AppsecLinuxPolicy>("get_linux_local_policy");

        if (!maybe_appsec_policy.ok()) {
            error_message = "Failed to retrieve appsec web user response.";
            dbgDebug(D_K8S_POLICY) << error_message;
            return genError(error_message);
        }

        auto web_user_res_vec = maybe_appsec_policy.unpack().getAppSecCustomResponseSpecs();
        auto web_user_res_it = extractElement(
            web_user_res_vec.begin(),
            web_user_res_vec.end(),
            web_user_res_annotation_name);

        if (web_user_res_it == web_user_res_vec.end()) {
            error_message = "Failed to retrieve appsec web user response.";
            dbgDebug(D_K8S_POLICY) << error_message;
            return genError(error_message);
        }

        return *web_user_res_it;

    }

    bool
    extractWebUserResponse(
        const string &web_user_res_annotation_name,
        map<string, WebUserResponseTriggerSection> &web_user_res_map,
        vector<pair<string, string>> &web_user_res_vec,
        vector<WebUserResponseTriggerSection> &parsed_web_user_res)
    {
        if (!web_user_res_annotation_name.empty()) {
            dbgTrace(D_K8S_POLICY) << "Trying to retrieve web user response for: " << web_user_res_annotation_name;
            auto maybe_appsec_web_user_res_spec = getAppSecCustomResponseSpecs(web_user_res_annotation_name);

            if (!maybe_appsec_web_user_res_spec.ok()) {
                dbgWarning(D_K8S_POLICY) << maybe_appsec_web_user_res_spec.getErr();
                return false;
            }

            AppSecCustomResponseSpec appsec_web_user_res_spec = maybe_appsec_web_user_res_spec.unpack();

            if (web_user_res_map.count(web_user_res_annotation_name) == 0) {
                WebUserResponseTriggerSection web_user_res_section = createWebUserResponseTriggerSection(
                    web_user_res_annotation_name,
                    appsec_web_user_res_spec);

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
        }
        return true;
    }
};


LocalPolicyMgmtGenerator::LocalPolicyMgmtGenerator()
        :
    Component("LocalPolicyMgmtGenerator"),
    pimpl(make_unique<LocalPolicyMgmtGenerator::Impl>()) {}

LocalPolicyMgmtGenerator::~LocalPolicyMgmtGenerator() {}

void
LocalPolicyMgmtGenerator::init()
{
    pimpl->init();
}

void
LocalPolicyMgmtGenerator::preload()
{}
// LCOV_EXCL_STOP
