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
#include "customized_cereal_map.h"

using namespace std;

USE_DEBUG_FLAG(D_LOCAL_POLICY);
void
IngressMetadata::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "IngressMetadata load";
    parseAppsecJSONKey<string>("name", name, archive_in);
    parseAppsecJSONKey<string>("resourceVersion", resourceVersion, archive_in);
    parseAppsecJSONKey<string>("namespace", namespace_name, archive_in);
    parseAppsecJSONKey<map<string, string>>("annotations", annotations, archive_in);
}

const map<string, string> &
IngressMetadata::getAnnotations() const
{
    return annotations;
}

void
IngressRulePath::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading ingress defined rule path";
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
    dbgTrace(D_LOCAL_POLICY) << "Loading ingress defined rule path wrapper";
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
    dbgTrace(D_LOCAL_POLICY) << "Loading ingress defined rule";
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
    dbgTrace(D_LOCAL_POLICY) << "Loading Default Backend";
    is_exists = true;
}

void
IngressSpec::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading single ingress spec";
    parseAppsecJSONKey<string>("ingressClassName", ingress_class_name, archive_in);
    parseAppsecJSONKey<vector<IngressDefinedRule>>("rules", rules, archive_in);
    parseAppsecJSONKey<DefaultBackend>("defaultBackend", default_backend, archive_in);
}

const vector<IngressDefinedRule> &
IngressSpec::getRules() const
{
    return rules;
}

void
SingleIngressData::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading single ingress data";
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
    dbgTrace(D_LOCAL_POLICY) << "Loading ingress data";
    try {
        cereal::JSONInputArchive in_ar(in);
        in_ar(
            cereal::make_nvp("apiVersion", apiVersion),
            cereal::make_nvp("items", items)
        );
    } catch (cereal::Exception &e) {
        dbgError(D_LOCAL_POLICY) << "Failed to load ingress data JSON. Error: " << e.what();
        return false;
    }
    return true;
}

const vector<SingleIngressData> &
IngressData::getItems() const
{
    return items;
}
