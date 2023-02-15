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

#include "ingress_data.h"

using namespace std;

USE_DEBUG_FLAG(D_K8S_POLICY);
// LCOV_EXCL_START Reason: no test exist
void
IngressMetadata::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_K8S_POLICY) << "IngressMetadata load";
    parseAppsecJSONKey<string>("name", name, archive_in);
    parseAppsecJSONKey<string>("resourceVersion", resourceVersion, archive_in);
    parseAppsecJSONKey<string>("namespace", namespace_name, archive_in);
    parseAppsecJSONKey<map<string, string>>("annotations", annotations, archive_in);
}

const string &
IngressMetadata::getName() const
{
    return name;
}

const string &
IngressMetadata::getResourceVersion() const
{
    return resourceVersion;
}

const string &
IngressMetadata::getNamespace() const
{
    return namespace_name;
}

const map<string, string> &
IngressMetadata::getAnnotations() const
{
    return annotations;
}

void
IngressRulePath::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_K8S_POLICY) << "Loading ingress defined rule path";
    parseAppsecJSONKey<string>("path", path, archive_in);
}

const string &
IngressRulePath::getPath() const
{
    return path;
}

void
IngressRulePathsWrapper::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_K8S_POLICY) << "Loading ingress defined rule path wrapper";
    parseAppsecJSONKey<vector<IngressRulePath>>("paths", paths, archive_in);
}

const vector<IngressRulePath> &
IngressRulePathsWrapper::getRulePaths() const
{
    return paths;
}

void
IngressDefinedRule::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_K8S_POLICY) << "Loading ingress defined rule";
    parseAppsecJSONKey<string>("host", host, archive_in);
    parseAppsecJSONKey<IngressRulePathsWrapper>("http", paths_wrapper, archive_in);
}

const string &
IngressDefinedRule::getHost() const
{
    return host;
}

const IngressRulePathsWrapper &
IngressDefinedRule::getPathsWrapper() const
{
    return paths_wrapper;
}

void
DefaultBackend::load(cereal::JSONInputArchive &)
{
    dbgTrace(D_K8S_POLICY) << "Loading Default Backend";
    is_exists = true;
}

bool
DefaultBackend::isExists() const
{
    return is_exists;
}

void
IngressSpec::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_K8S_POLICY) << "Loading single ingress spec";
    parseAppsecJSONKey<string>("ingressClassName", ingress_class_name, archive_in);
    parseAppsecJSONKey<vector<IngressDefinedRule>>("rules", rules, archive_in);
    parseAppsecJSONKey<DefaultBackend>("defaultBackend", default_backend, archive_in);
}

const string &
IngressSpec::getIngressClassName() const
{
    return ingress_class_name;
}

const vector<IngressDefinedRule> &
IngressSpec::getRules() const
{
    return rules;
}
bool
IngressSpec::isDefaultBackendExists() const
{
    return default_backend.isExists();
}

void
SingleIngressData::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_K8S_POLICY) << "Loading single ingress data";
    parseAppsecJSONKey<IngressMetadata>("metadata", metadata, archive_in);
    parseAppsecJSONKey<IngressSpec>("spec", spec, archive_in);
}

const IngressMetadata &
SingleIngressData::getMetadata() const
{
    return metadata;
}

const IngressSpec &
SingleIngressData::getSpec() const
{
    return spec;
}

bool
IngressData::loadJson(const string &json)
{
    string modified_json = json;
    modified_json.pop_back();
    stringstream in;
    in.str(modified_json);
    dbgTrace(D_K8S_POLICY) << "Loading ingress data";
    try {
        cereal::JSONInputArchive in_ar(in);
        in_ar(
            cereal::make_nvp("apiVersion", apiVersion),
            cereal::make_nvp("items", items)
        );
    } catch (cereal::Exception &e) {
        dbgError(D_K8S_POLICY) << "Failed to load ingress data JSON. Error: " << e.what();
        return false;
    }
    return true;
}

const string &
IngressData::getapiVersion() const
{
    return apiVersion;
}

const vector<SingleIngressData> &
IngressData::getItems() const
{
    return items;
}
// LCOV_EXCL_STOP
