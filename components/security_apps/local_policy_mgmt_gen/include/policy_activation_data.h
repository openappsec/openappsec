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

#ifndef __POLICY_ACTIVATION_DATA_H__
#define __POLICY_ACTIVATION_DATA_H__

#include <vector>
#include <map>

#include "config.h"
#include "debug.h"
#include "rest.h"
#include "cereal/archives/json.hpp"
#include <cereal/types/map.hpp>
#include "customized_cereal_map.h"

#include "local_policy_common.h"

class PolicyActivationMetadata
{
public:
    void load(cereal::JSONInputArchive &archive_in);

private:
    std::string name;
};

class EnabledPolicy
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const std::string & getName() const;
    const std::vector<std::string> & getHosts() const;

private:
    std::string name;
    std::string mode;
    std::vector<std::string> hosts;
};

class PolicyActivationSpec
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const std::vector<EnabledPolicy> & getPolicies() const;

private:
    std::string appsec_class_name;
    std::vector<EnabledPolicy> policies;
};

class SinglePolicyActivationData
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const PolicyActivationSpec & getSpec() const;

private:
    std::string api_version;
    std::string kind;
    PolicyActivationMetadata metadata;
    PolicyActivationSpec spec;
};

class PolicyActivationData : public ClientRest
{
public:
    bool loadJson(const std::string &json);

    const std::vector<SinglePolicyActivationData> & getItems() const;

private:
    std::string api_version;
    std::vector<SinglePolicyActivationData> items;
};

#endif // __POLICY_ACTIVATION_DATA_H__
