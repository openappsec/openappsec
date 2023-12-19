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

#include "k8s_policy_utils.h"
#include "configmaps.h"

using namespace std;

USE_DEBUG_FLAG(D_NGINX_POLICY);

string
convertAnnotationKeysTostring(const AnnotationKeys &key)
{
    switch (key) {
        case AnnotationKeys::PolicyKey:
            return "policy";
        case AnnotationKeys::OpenAppsecIo:
            return "openappsec.io/";
        case AnnotationKeys::SyslogAddressKey:
            return "syslog";
        case AnnotationKeys::ModeKey:
            return "mode";
        default:
            return "Irrelevant key";
    }
}

void
K8sPolicyUtils::init()
{
    env_details = Singleton::Consume<I_EnvDetails>::by<K8sPolicyUtils>();
    env_type = env_details->getEnvType();
    if (env_type == EnvType::K8S) {
        token = env_details->getToken();
        messaging = Singleton::Consume<I_Messaging>::by<K8sPolicyUtils>();
        conn_flags.setFlag(MessageConnConfig::SECURE_CONN);
        conn_flags.setFlag(MessageConnConfig::IGNORE_SSL_VALIDATION);
    }
}

map<AnnotationKeys, string>
K8sPolicyUtils::parseIngressAnnotations(const map<string, string> &annotations) const
{
    map<AnnotationKeys, string> annotations_values;
    for (const auto &annotation : annotations) {
        string annotation_key = annotation.first;
        string annotation_val = annotation.second;
        if (annotation_key.find(convertAnnotationKeysTostring(AnnotationKeys::OpenAppsecIo)) != string::npos) {
            if (annotation_key.find(convertAnnotationKeysTostring(AnnotationKeys::PolicyKey)) != string::npos) {
                annotations_values[AnnotationKeys::PolicyKey] = annotation_val;
            } else if (
                annotation_key.find(convertAnnotationKeysTostring(AnnotationKeys::SyslogAddressKey)) != string::npos
            ) {
                bool has_port = annotation_val.find(":");
                annotations_values[AnnotationKeys::SyslogAddressKey] =
                    annotation_val.substr(0, annotation_val.find(":"));
                annotations_values[AnnotationKeys::SyslogPortKey] =
                    has_port ? annotation_val.substr(annotation_val.find(":") + 1) : "";
            } else if (annotation_key.find(convertAnnotationKeysTostring(AnnotationKeys::ModeKey)) != string::npos) {
                annotations_values[AnnotationKeys::ModeKey] = annotation_val;
            }
        }
    }
    return annotations_values;
}

template<class T>
Maybe<T, string>
K8sPolicyUtils::getObjectFromCluster(const string &path) const
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

    return genError(string("Was not able to get object form k8s cluser in path: " + path));
}

map<AnnotationTypes, unordered_set<string>>
K8sPolicyUtils::extractElementsNames(const vector<ParsedRule> &specific_rules, const ParsedRule &default_rule) const
{
    map<AnnotationTypes, unordered_set<string>> policy_elements_names;
    for (const ParsedRule &specific_rule : specific_rules) {
        policy_elements_names[AnnotationTypes::EXCEPTION].insert(
            specific_rule.getExceptions().begin(),
            specific_rule.getExceptions().end()
        );
        policy_elements_names[AnnotationTypes::PRACTICE].insert(
            specific_rule.getPractices().begin(),
            specific_rule.getPractices().end()
        );
        policy_elements_names[AnnotationTypes::TRIGGER].insert(
            specific_rule.getLogTriggers().begin(),
            specific_rule.getLogTriggers().end()
        );
        policy_elements_names[AnnotationTypes::WEB_USER_RES].insert(specific_rule.getCustomResponse());
        policy_elements_names[AnnotationTypes::SOURCE_IDENTIFIERS].insert(specific_rule.getSourceIdentifiers());
        policy_elements_names[AnnotationTypes::TRUSTED_SOURCES].insert(specific_rule.getTrustedSources());
    }
    policy_elements_names[AnnotationTypes::EXCEPTION].insert(
        default_rule.getExceptions().begin(),
        default_rule.getExceptions().end()
    );
    policy_elements_names[AnnotationTypes::PRACTICE].insert(
        default_rule.getPractices().begin(),
        default_rule.getPractices().end()
    );
    policy_elements_names[AnnotationTypes::TRIGGER].insert(
        default_rule.getLogTriggers().begin(),
        default_rule.getLogTriggers().end()
    );
    policy_elements_names[AnnotationTypes::WEB_USER_RES].insert(default_rule.getCustomResponse());
    policy_elements_names[AnnotationTypes::SOURCE_IDENTIFIERS].insert(default_rule.getSourceIdentifiers());
    policy_elements_names[AnnotationTypes::TRUSTED_SOURCES].insert(default_rule.getTrustedSources());

    return policy_elements_names;
}

// LCOV_EXCL_START Reason: no test exist
void
extractElementsFromNewRule(
    const NewParsedRule &rule,
    map<AnnotationTypes, unordered_set<string>> &policy_elements_names)
{
    policy_elements_names[AnnotationTypes::EXCEPTION].insert(
        rule.getExceptions().begin(),
        rule.getExceptions().end()
    );
    policy_elements_names[AnnotationTypes::THREAT_PREVENTION_PRACTICE].insert(
        rule.getPractices().begin(),
        rule.getPractices().end()
    );
    policy_elements_names[AnnotationTypes::ACCESS_CONTROL_PRACTICE].insert(
        rule.getAccessControlPractices().begin(),
        rule.getAccessControlPractices().end()
    );
    policy_elements_names[AnnotationTypes::TRIGGER].insert(
        rule.getLogTriggers().begin(),
        rule.getLogTriggers().end()
    );
    policy_elements_names[AnnotationTypes::WEB_USER_RES].insert(rule.getCustomResponse());
    policy_elements_names[AnnotationTypes::SOURCE_IDENTIFIERS].insert(rule.getSourceIdentifiers());
    policy_elements_names[AnnotationTypes::TRUSTED_SOURCES].insert(rule.getTrustedSources());
    policy_elements_names[AnnotationTypes::UPGRADE_SETTINGS].insert(rule.getUpgradeSettings());
}

map<AnnotationTypes, unordered_set<string>>
K8sPolicyUtils::extractElementsNamesV1beta2(
    const vector<NewParsedRule> &specific_rules,
    const NewParsedRule &default_rule) const
{
    map<AnnotationTypes, unordered_set<string>> policy_elements_names;
    for (const NewParsedRule &specific_rule : specific_rules) {
        extractElementsFromNewRule(specific_rule, policy_elements_names);
    }
    extractElementsFromNewRule(default_rule, policy_elements_names);

    return policy_elements_names;
}

string
getAppSecClassNameFromCluster()
{
    auto env_res = getenv("appsecClassName");
    if (env_res != nullptr) return env_res;
    return "";
}
// LCOV_EXCL_STOP

vector<AppsecException>
K8sPolicyUtils::extractExceptionsFromCluster(
    const string &crd_plural,
    const unordered_set<string> &elements_names) const
{
    dbgTrace(D_LOCAL_POLICY) << "Retrieve AppSec elements. type: " << crd_plural;
    vector<AppsecException> elements;
    for (const string &element_name : elements_names) {
        dbgTrace(D_LOCAL_POLICY) << "AppSec element name: " << element_name;
        auto maybe_appsec_element = getObjectFromCluster<AppsecSpecParser<vector<AppsecExceptionSpec>>>(
            "/apis/openappsec.io/v1beta1/" + crd_plural + "/" + element_name
        );

        if (!maybe_appsec_element.ok()) {
            dbgWarning(D_LOCAL_POLICY)
                << "Failed to retrieve AppSec element. type: "
                << crd_plural
                << ", name: "
                << element_name
                << ". Error: "
                << maybe_appsec_element.getErr();
            continue;
        }

        AppsecSpecParser<vector<AppsecExceptionSpec>> appsec_element = maybe_appsec_element.unpack();
        elements.push_back(AppsecException(element_name, appsec_element.getSpec()));
    }
    return elements;
}

template<class T>
vector<T>
K8sPolicyUtils::extractElementsFromCluster(
    const string &crd_plural,
    const unordered_set<string> &elements_names) const
{
    dbgTrace(D_LOCAL_POLICY) << "Retrieve AppSec elements. type: " << crd_plural;
    vector<T> elements;
    for (const string &element_name : elements_names) {
        dbgTrace(D_LOCAL_POLICY) << "AppSec element name: " << element_name;
        auto maybe_appsec_element = getObjectFromCluster<AppsecSpecParser<T>>(
            "/apis/openappsec.io/v1beta1/" + crd_plural + "/" + element_name
        );

        if (!maybe_appsec_element.ok()) {
            dbgWarning(D_LOCAL_POLICY)
                << "Failed to retrieve AppSec element. type: "
                << crd_plural
                << ", name: "
                << element_name
                << ". Error: "
                << maybe_appsec_element.getErr();
            continue;
        }

        AppsecSpecParser<T> appsec_element = maybe_appsec_element.unpack();
        if (appsec_element.getSpec().getName() == "") {
            appsec_element.setName(element_name);
        }
        elements.push_back(appsec_element.getSpec());
    }
    return elements;
}

// LCOV_EXCL_START Reason: no test exist
template<class T>
vector<T>
K8sPolicyUtils::extractV1Beta2ElementsFromCluster(
    const string &crd_plural,
    const unordered_set<string> &elements_names) const
{
    dbgTrace(D_LOCAL_POLICY) << "Retrieve AppSec elements. type: " << crd_plural;
    vector<T> elements;
    for (const string &element_name : elements_names) {
        dbgTrace(D_LOCAL_POLICY) << "AppSec element name: " << element_name;
        auto maybe_appsec_element = getObjectFromCluster<AppsecSpecParser<T>>(
            "/apis/openappsec.io/v1beta2/" + crd_plural + "/" + element_name
        );

        if (!maybe_appsec_element.ok()) {
            dbgWarning(D_LOCAL_POLICY)
                << "Failed to retrieve AppSec element. type: "
                << crd_plural
                << ", name: "
                << element_name
                << ". Error: "
                << maybe_appsec_element.getErr();
            continue;
        }

        AppsecSpecParser<T> appsec_element = maybe_appsec_element.unpack();
        if (getAppSecClassNameFromCluster() != "" &&
            appsec_element.getSpec().getAppSecClassName() != getAppSecClassNameFromCluster()) {
            continue;
        }

        if (appsec_element.getSpec().getName() == "") {
            appsec_element.setName(element_name);
        }
        elements.push_back(appsec_element.getSpec());
    }
    return elements;
}
// LCOV_EXCL_STOP

Maybe<AppsecLinuxPolicy>
K8sPolicyUtils::createAppsecPolicyK8sFromV1beta1Crds(
    const AppsecSpecParser<AppsecPolicySpec> &appsec_policy_spec,
    const string &ingress_mode) const
{
    ParsedRule default_rule = appsec_policy_spec.getSpec().getDefaultRule();
    vector<ParsedRule> specific_rules = appsec_policy_spec.getSpec().getSpecificRules();

    if (!ingress_mode.empty() && default_rule.getMode().empty()) {
        default_rule.setMode(ingress_mode);
    }

    map<AnnotationTypes, unordered_set<string>> policy_elements_names = extractElementsNames(
        specific_rules,
        default_rule
    );


    vector<AppSecPracticeSpec> practices = extractElementsFromCluster<AppSecPracticeSpec>(
        "practices",
        policy_elements_names[AnnotationTypes::PRACTICE]
    );

    vector<AppsecTriggerSpec> log_triggers = extractElementsFromCluster<AppsecTriggerSpec>(
        "logtriggers",
        policy_elements_names[AnnotationTypes::TRIGGER]
    );

    vector<AppSecCustomResponseSpec> web_user_responses = extractElementsFromCluster<AppSecCustomResponseSpec>(
        "customresponses",
        policy_elements_names[AnnotationTypes::WEB_USER_RES]
    );


    vector<AppsecException> exceptions = extractExceptionsFromCluster(
        "exceptions",
        policy_elements_names[AnnotationTypes::EXCEPTION]
    );

    vector<SourceIdentifierSpecWrapper> source_identifiers = extractElementsFromCluster<SourceIdentifierSpecWrapper>(
        "sourcesidentifiers",
        policy_elements_names[AnnotationTypes::SOURCE_IDENTIFIERS]
    );

    vector<TrustedSourcesSpec> trusted_sources = extractElementsFromCluster<TrustedSourcesSpec>(
        "trustedsources",
        policy_elements_names[AnnotationTypes::TRUSTED_SOURCES]
    );

    AppsecLinuxPolicy appsec_policy = AppsecLinuxPolicy(
        appsec_policy_spec.getSpec(),
        practices,
        log_triggers,
        web_user_responses,
        exceptions,
        trusted_sources,
        source_identifiers
    );
    return appsec_policy;
}

// LCOV_EXCL_START Reason: no test exist
void
K8sPolicyUtils::createSnortFile(vector<NewAppSecPracticeSpec> &practices) const
{
    for (NewAppSecPracticeSpec &practice : practices) {
        auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<K8sPolicyUtils>();
        auto path = getFilesystemPathConfig() + "/conf/snort/snort_k8s_" + practice.getName() + ".rule";
        bool append_mode = false;
        practice.getSnortSignatures().setTemporary(true);
        for (const string &config_map : practice.getSnortSignatures().getConfigMap())
        {
            auto maybe_configmap = getObjectFromCluster<ConfigMaps>(
                "/api/v1/namespaces/default/configmaps/" + config_map
            );
            if (!maybe_configmap.ok())  {
                dbgWarning(D_LOCAL_POLICY) << "Failed to get configMaps from the cluster.";
                continue;
            }
            string file_content = maybe_configmap.unpack().getFileContent();
            string file_name = maybe_configmap.unpack().getFileName();
            if (!orchestration_tools->writeFile(file_content, path, append_mode)) {
                dbgWarning(D_LOCAL_POLICY) << "Failed to update the snort_k8s_rules file.";
                continue;
            }
            append_mode = true;
            practice.getSnortSignatures().addFile(file_name);
        }
    }
}

Maybe<V1beta2AppsecLinuxPolicy>
K8sPolicyUtils::createAppsecPolicyK8sFromV1beta2Crds(
    const AppsecSpecParser<NewAppsecPolicySpec> &appsec_policy_spec,
    const string &ingress_mode) const
{
    NewParsedRule default_rule = appsec_policy_spec.getSpec().getDefaultRule();
    vector<NewParsedRule> specific_rules = appsec_policy_spec.getSpec().getSpecificRules();
    string appsec_class_name = appsec_policy_spec.getSpec().getAppSecClassName();

    if (getAppSecClassNameFromCluster() != "" &&
        appsec_class_name != getAppSecClassNameFromCluster()) {
        return genError("Unmached appsec class name!");
    }

    if (default_rule.getMode().empty() && !ingress_mode.empty()) {
        default_rule.setMode(ingress_mode);
    }

    map<AnnotationTypes, unordered_set<string>> policy_elements_names = extractElementsNamesV1beta2(
        specific_rules,
        default_rule
    );

    vector<NewAppSecPracticeSpec> threat_prevention_practices =
        extractV1Beta2ElementsFromCluster<NewAppSecPracticeSpec>(
            "threatpreventionpractices",
            policy_elements_names[AnnotationTypes::THREAT_PREVENTION_PRACTICE]
        );

    createSnortFile(threat_prevention_practices);

    vector<AccessControlPracticeSpec> access_control_practices =
        extractV1Beta2ElementsFromCluster<AccessControlPracticeSpec>(
            "accesscontrolpractice",
            policy_elements_names[AnnotationTypes::ACCESS_CONTROL_PRACTICE]
        );

    vector<NewAppsecLogTrigger> log_triggers = extractV1Beta2ElementsFromCluster<NewAppsecLogTrigger>(
        "logtriggers",
        policy_elements_names[AnnotationTypes::TRIGGER]
    );

    vector<NewAppSecCustomResponse> web_user_responses = extractV1Beta2ElementsFromCluster<NewAppSecCustomResponse>(
        "customresponses",
        policy_elements_names[AnnotationTypes::WEB_USER_RES]
    );

    vector<NewAppsecException> exceptions = extractV1Beta2ElementsFromCluster<NewAppsecException>(
        "exceptions",
        policy_elements_names[AnnotationTypes::EXCEPTION]
    );

    vector<NewSourcesIdentifiers> source_identifiers = extractV1Beta2ElementsFromCluster<NewSourcesIdentifiers>(
        "sourcesidentifiers",
        policy_elements_names[AnnotationTypes::SOURCE_IDENTIFIERS]
    );

    vector<NewTrustedSourcesSpec> trusted_sources = extractV1Beta2ElementsFromCluster<NewTrustedSourcesSpec>(
        "trustedsources",
        policy_elements_names[AnnotationTypes::TRUSTED_SOURCES]
    );

    vector<AppSecAutoUpgradeSpec> vec_upgrade_settings = extractV1Beta2ElementsFromCluster<AppSecAutoUpgradeSpec>(
        "autoupgrade",
        policy_elements_names[AnnotationTypes::UPGRADE_SETTINGS]
    );
    if (vec_upgrade_settings.size() > 1) {
        dbgWarning(D_LOCAL_POLICY) << "Only one definition of upgrade settings is required.";
    }
    auto upgrade_settings = vec_upgrade_settings.empty() ? AppSecAutoUpgradeSpec() : vec_upgrade_settings.front();

    V1beta2AppsecLinuxPolicy appsec_policy = V1beta2AppsecLinuxPolicy(
        appsec_policy_spec.getSpec(),
        threat_prevention_practices,
        access_control_practices,
        log_triggers,
        web_user_responses,
        exceptions,
        trusted_sources,
        source_identifiers,
        upgrade_settings
    );
    return appsec_policy;
}
// LCOV_EXCL_STOP

bool
doesVersionExist(const map<string, string> &annotations, const string &version)
{
    for (auto annotation : annotations) {
        if(annotation.second.find(version) != std::string::npos) {
            return true;
        }
    }
    return false;
}

std::tuple<Maybe<AppsecLinuxPolicy>, Maybe<V1beta2AppsecLinuxPolicy>>
K8sPolicyUtils::createAppsecPolicyK8s(const string &policy_name, const string &ingress_mode) const
{
    auto maybe_appsec_policy_spec = getObjectFromCluster<AppsecSpecParser<AppsecPolicySpec>>(
        "/apis/openappsec.io/v1beta1/policies/" + policy_name
    );

    if (!maybe_appsec_policy_spec.ok() ||
        !doesVersionExist(maybe_appsec_policy_spec.unpack().getMetaData().getAnnotations(), "v1beta1")
    ) {
        dbgWarning(D_LOCAL_POLICY)
            << "Failed to retrieve Appsec policy with crds version: v1beta1, Trying version: v1beta2";
        auto maybe_v1beta2_appsec_policy_spec = getObjectFromCluster<AppsecSpecParser<NewAppsecPolicySpec>>(
            "/apis/openappsec.io/v1beta2/policies/" + policy_name
        );
        if(!maybe_v1beta2_appsec_policy_spec.ok()) {
            dbgWarning(D_LOCAL_POLICY)
                << "Failed to retrieve AppSec policy. Error: "
                << maybe_v1beta2_appsec_policy_spec.getErr();
            return std::make_tuple(
                genError("Failed to retrieve AppSec v1beta1 policy. Error: " + maybe_appsec_policy_spec.getErr()),
                genError(
                    "Failed to retrieve AppSec v1beta2 policy. Error: " + maybe_v1beta2_appsec_policy_spec.getErr()));
        }
        return std::make_tuple(
            genError("There is no v1beta1 policy"),
            createAppsecPolicyK8sFromV1beta2Crds(maybe_v1beta2_appsec_policy_spec.unpack(), ingress_mode));
    }

    return std::make_tuple(
        createAppsecPolicyK8sFromV1beta1Crds(maybe_appsec_policy_spec.unpack(), ingress_mode),
        genError("There is no v1beta2 policy"));
}

template<class T, class K>
void
K8sPolicyUtils::createPolicy(
    T &appsec_policy,
    map<std::string, T> &policies,
    map<AnnotationKeys, string> &annotations_values,
    const SingleIngressData &item) const
{
    for (const IngressDefinedRule &rule : item.getSpec().getRules()) {
            string url = rule.getHost();
            for (const IngressRulePath &uri : rule.getPathsWrapper().getRulePaths()) {
                if (!appsec_policy.getAppsecPolicySpec().isAssetHostExist(url + uri.getPath())) {
                    dbgTrace(D_LOCAL_POLICY)
                        << "Inserting Host data to the specific asset set:"
                        << "URL: '"
                        << url
                        << "' uri: '"
                        << uri.getPath()
                        << "'";
                    K ingress_rule = K(url + uri.getPath());
                    appsec_policy.addSpecificRule(ingress_rule);
                }
            }
        }
        policies[annotations_values[AnnotationKeys::PolicyKey]] = appsec_policy;
}


std::tuple<map<string, AppsecLinuxPolicy>, map<string, V1beta2AppsecLinuxPolicy>>
K8sPolicyUtils::createAppsecPoliciesFromIngresses()
{
    dbgFlow(D_LOCAL_POLICY) << "Getting all policy object from Ingresses";
    map<string, AppsecLinuxPolicy> v1bet1_policies;
    map<string, V1beta2AppsecLinuxPolicy> v1bet2_policies;
    auto maybe_ingress = getObjectFromCluster<IngressData>("/apis/networking.k8s.io/v1/ingresses");

    if (!maybe_ingress.ok()) {
        // TBD: Error handling : INXT-31444
        dbgWarning(D_LOCAL_POLICY)
            << "Failed to retrieve K8S Ingress configurations. Error: "
            << maybe_ingress.getErr();
        return make_tuple(v1bet1_policies, v1bet2_policies);
    }


    IngressData ingress = maybe_ingress.unpack();
    for (const SingleIngressData &item : ingress.getItems()) {
        map<AnnotationKeys, string> annotations_values = parseIngressAnnotations(
            item.getMetadata().getAnnotations()
        );

        if (annotations_values[AnnotationKeys::PolicyKey].empty()) {
            dbgInfo(D_LOCAL_POLICY) << "No policy was found in this ingress";
            continue;
        }

        auto maybe_appsec_policy = createAppsecPolicyK8s(
            annotations_values[AnnotationKeys::PolicyKey],
            annotations_values[AnnotationKeys::ModeKey]
        );
        if (!std::get<0>(maybe_appsec_policy).ok() && !std::get<1>(maybe_appsec_policy).ok()) {
            dbgWarning(D_LOCAL_POLICY)
                << "Failed to create appsec policy. Error: "
                << std::get<1>(maybe_appsec_policy).getErr();
            continue;
        }

        if (!std::get<0>(maybe_appsec_policy).ok()) {
            auto appsec_policy=std::get<1>(maybe_appsec_policy).unpack();
            createPolicy<V1beta2AppsecLinuxPolicy, NewParsedRule>(
                appsec_policy,
                v1bet2_policies,
                annotations_values,
                item);
        } else {
            auto appsec_policy=std::get<0>(maybe_appsec_policy).unpack();
            createPolicy<AppsecLinuxPolicy, ParsedRule>(
                appsec_policy,
                v1bet1_policies,
                annotations_values,
                item);
        }
    }
    return make_tuple(v1bet1_policies, v1bet2_policies);
}
