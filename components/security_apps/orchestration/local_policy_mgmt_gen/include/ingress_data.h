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
#include <cereal/types/map.hpp>

#include "k8s_policy_common.h"

USE_DEBUG_FLAG(D_K8S_POLICY);
// LCOV_EXCL_START Reason: no test exist
class IngressMetadata
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const std::string & getName() const;
    const std::string & getResourceVersion() const;
    const std::string & getNamespace() const;
    const std::map<std::string, std::string> & getAnnotations() const;

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
    load(cereal::JSONInputArchive &archive_in);

    const std::string & getPath() const;

private:
    std::string path;
};

inline std::ostream &
operator<<(std::ostream &os, const IngressRulePath &obj)
{
    os << obj.getPath();
    return os;
}

class IngressRulePathsWrapper
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const std::vector<IngressRulePath> & getRulePaths() const;

private:
    std::vector<IngressRulePath> paths;
};

class IngressDefinedRule
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const std::string & getHost() const;
    const IngressRulePathsWrapper & getPathsWrapper() const;

private:
    std::string host;
    IngressRulePathsWrapper paths_wrapper;
};

inline std::ostream &
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
    load(cereal::JSONInputArchive &);

    bool isExists() const;

private:
    bool is_exists = false;
};

class IngressSpec
{
public:
    void
    load(cereal::JSONInputArchive &archive_in);

    const std::string & getIngressClassName() const;
    const std::vector<IngressDefinedRule> & getRules() const;
    bool isDefaultBackendExists() const;

private:
    std::string ingress_class_name;
    std::vector<IngressDefinedRule> rules;
    DefaultBackend default_backend;
};

class SingleIngressData
{
public:
    void
    load(cereal::JSONInputArchive &archive_in);

    const IngressMetadata & getMetadata() const;
    const IngressSpec & getSpec() const;

private:
    IngressMetadata metadata;
    IngressSpec spec;
};


class IngressData : public ClientRest
{
public:
    bool loadJson(const std::string &json);

    const std::string & getapiVersion() const;
    const std::vector<SingleIngressData> & getItems() const;

private:
    std::string apiVersion;
    std::vector<SingleIngressData> items;
};
// LCOV_EXCL_STOP
#endif // __INGRESS_DATA_H__
