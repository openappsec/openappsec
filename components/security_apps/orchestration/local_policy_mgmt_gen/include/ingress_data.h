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

#ifndef __INGRESS_DATA_H__
#define __INGRESS_DATA_H__

#include <vector>
#include <map>

#include "config.h"
#include "debug.h"
#include "rest.h"
#include "cereal/archives/json.hpp"

USE_DEBUG_FLAG(D_K8S_POLICY);
// LCOV_EXCL_START Reason: no test exist
class IngressMetadata
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_K8S_POLICY) << "IngressMetadata load";
        parseAppsecJSONKey<std::string>("name", name, archive_in);
        parseAppsecJSONKey<std::string>("resourceVersion", resourceVersion, archive_in);
        parseAppsecJSONKey<std::string>("namespace", namespace_name, archive_in);
        parseAppsecJSONKey<std::map<std::string, std::string>>("annotations", annotations, archive_in);
    }

    const std::string & getName() const { return name; }
    const std::string & getResourceVersion() const { return resourceVersion; }
    const std::string & getNamespace() const { return namespace_name; }
    const std::map<std::string, std::string> & getAnnotations() const { return annotations; }

private:
    std::string name;
    std::string resourceVersion;
    std::string namespace_name;
    std::map<std::string, std::string> annotations;
};

class IngressRulePath
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_K8S_POLICY) << "Loading ingress defined rule path";
        parseAppsecJSONKey<std::string>("path", path, archive_in);
    }

    const std::string & getPath() const { return path; }

private:
    std::string path;
};

std::ostream &
operator<<(std::ostream &os, const IngressRulePath &obj)
{
    os << obj.getPath();
    return os;
}

class IngressRulePathsWrapper
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_K8S_POLICY) << "Loading ingress defined rule path wrapper";
        parseAppsecJSONKey<std::vector<IngressRulePath>>("paths", paths, archive_in);
    }

    const std::vector<IngressRulePath> & getRulePaths() const { return paths; }

private:
    std::vector<IngressRulePath> paths;
};

class IngressDefinedRule
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_K8S_POLICY) << "Loading ingress defined rule";
        parseAppsecJSONKey<std::string>("host", host, archive_in);
        parseAppsecJSONKey<IngressRulePathsWrapper>("http", paths_wrapper, archive_in);
    }

    const std::string & getHost() const { return host; }
    const IngressRulePathsWrapper & getPathsWrapper() const { return paths_wrapper; }

private:
    std::string host;
    IngressRulePathsWrapper paths_wrapper;
};

std::ostream &
operator<<(std::ostream &os, const IngressDefinedRule &obj)
{
    os
        << "host: "
        << obj.getHost()
        << ", paths: [" << std::endl
        << makeSeparatedStr(obj.getPathsWrapper().getRulePaths(), ",")
        << std::endl << "]";
    return os;
}

class DefaultBackend
{
public:
    void
    load(cereal::JSONInputArchive &)
    {
        dbgTrace(D_K8S_POLICY) << "Loading Default Backend";
        is_exists = true;
    }

    bool isExists() const { return is_exists; }

private:
    bool is_exists = false;
};

class IngressSpec
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_K8S_POLICY) << "Loading single ingress spec";
        parseAppsecJSONKey<std::string>("ingressClassName", ingress_class_name, archive_in);
        parseAppsecJSONKey<std::vector<IngressDefinedRule>>("rules", rules, archive_in);
        parseAppsecJSONKey<DefaultBackend>("defaultBackend", default_backend, archive_in);
    }

    const std::string & getIngressClassName() const { return ingress_class_name; }
    const std::vector<IngressDefinedRule> & getRules() const { return rules; }
    bool isDefaultBackendExists() const { return default_backend.isExists(); }

private:
    std::string ingress_class_name;
    std::vector<IngressDefinedRule> rules;
    DefaultBackend default_backend;
};

std::ostream &
operator<<(std::ostream &os, const IngressSpec &obj)
{
    os
        << "Ingress Spec - ingressClassName: "
        << obj.getIngressClassName()
        << ", rules: [" << std::endl
        << makeSeparatedStr(obj.getRules(), ",")
        << std::endl << "]";
    return os;
}

class SingleIngressData
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_K8S_POLICY) << "Loading single ingress data";
        parseAppsecJSONKey<IngressMetadata>("metadata", metadata, archive_in);
        parseAppsecJSONKey<IngressSpec>("spec", spec, archive_in);
    }

    const IngressMetadata & getMetadata() const { return metadata; }
    const IngressSpec & getSpec() const { return spec; }

private:
    IngressMetadata metadata;
    IngressSpec spec;
};


class IngressData : public ClientRest
{
public:
    bool
    loadJson(const std::string &json)
    {
        std::string modified_json = json;
        modified_json.pop_back();
        std::stringstream in;
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

    const std::string & getapiVersion() const { return apiVersion; }
    const std::vector<SingleIngressData> & getItems() const { return items; }

private:
    std::string apiVersion;
    std::vector<SingleIngressData> items;
};
// LCOV_EXCL_STOP
#endif // __INGRESS_DATA_H__
