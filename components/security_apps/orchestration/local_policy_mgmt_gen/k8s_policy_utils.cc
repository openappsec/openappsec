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
#include "namespace_data.h"

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
    for (const pair<string, string> &annotation : annotations) {
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

Maybe<AppsecLinuxPolicy>
K8sPolicyUtils::createAppsecPolicyK8s(const string &policy_name, const string &ingress_mode) const
{
    auto maybe_appsec_policy_spec = getObjectFromCluster<AppsecSpecParser<AppsecPolicySpec>>(
        "/apis/openappsec.io/v1beta1/policies/" + policy_name
    );
    if (!maybe_appsec_policy_spec.ok()) {
        dbgWarning(D_LOCAL_POLICY)
            << "Failed to retrieve AppSec policy. Error: "
            << maybe_appsec_policy_spec.getErr();
        return genError("Failed to retrieve AppSec policy. Error: " + maybe_appsec_policy_spec.getErr());
    }
    AppsecSpecParser<AppsecPolicySpec> appsec_policy_spec = maybe_appsec_policy_spec.unpack();
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

    vector<AppsecExceptionSpec> exceptions = extractElementsFromCluster<AppsecExceptionSpec>(
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

map<string, AppsecLinuxPolicy>
K8sPolicyUtils::createAppsecPoliciesFromIngresses()
{
    dbgFlow(D_LOCAL_POLICY) << "Getting all policy object from Ingresses";
    map<string, AppsecLinuxPolicy> policies;
    auto maybe_ingress = getObjectFromCluster<IngressData>("/apis/networking.k8s.io/v1/ingresses");

    if (!maybe_ingress.ok()) {
        // TBD: Error handling : INXT-31444
        dbgWarning(D_LOCAL_POLICY)
            << "Failed to retrieve K8S Ingress configurations. Error: "
            << maybe_ingress.getErr();
        return policies;
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

        Maybe<AppsecLinuxPolicy> maybe_appsec_policy = createAppsecPolicyK8s(
            annotations_values[AnnotationKeys::PolicyKey],
            annotations_values[AnnotationKeys::ModeKey]
        );
        if (!maybe_appsec_policy.ok()) {
            dbgWarning(D_LOCAL_POLICY)
                << "Failed to create appsec policy. Error: "
                << maybe_appsec_policy.getErr();
            continue;
        }

        AppsecLinuxPolicy appsec_policy = maybe_appsec_policy.unpack();
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
                    ParsedRule ingress_rule = ParsedRule(url + uri.getPath());
                    appsec_policy.addSpecificRule(ingress_rule);
                }
            }
        }
        policies[annotations_values[AnnotationKeys::PolicyKey]] = appsec_policy;
    }
    return policies;
}

bool
isPlaygroundEnv()
{
    const char *env_string = getenv("PLAYGROUND");

    if (env_string == nullptr) return false;
    string env_value = env_string;
    transform(env_value.begin(), env_value.end(), env_value.begin(), ::tolower);

    return env_value == "true";
}

bool
K8sPolicyUtils::getClusterId() const
{
    string playground_uid = isPlaygroundEnv() ? "playground-" : "";

    dbgTrace(D_LOCAL_POLICY) << "Getting cluster UID";
    auto maybe_namespaces_data = getObjectFromCluster<NamespaceData>("/api/v1/namespaces/");

    if (!maybe_namespaces_data.ok()) {
        dbgWarning(D_LOCAL_POLICY)
            << "Failed to retrieve K8S namespace data. Error: "
            << maybe_namespaces_data.getErr();
        return false;
    }

    NamespaceData namespaces_data = maybe_namespaces_data.unpack();

    Maybe<string> maybe_ns_uid = namespaces_data.getNamespaceUidByName("kube-system");
    if (!maybe_ns_uid.ok()) {
        dbgWarning(D_LOCAL_POLICY) << maybe_ns_uid.getErr();
        return false;
    }
    string uid = playground_uid + maybe_ns_uid.unpack();
    dbgTrace(D_LOCAL_POLICY) << "Found k8s cluster UID: " << uid;
    I_Environment *env = Singleton::Consume<I_Environment>::by<K8sPolicyUtils>();
    env->getConfigurationContext().registerValue<string>(
        "k8sClusterId",
        uid,
        EnvKeyAttr::LogSection::SOURCE
    );
    I_AgentDetails *i_agent_details = Singleton::Consume<I_AgentDetails>::by<K8sPolicyUtils>();
    i_agent_details->setClusterId(uid);
    return true;
}
