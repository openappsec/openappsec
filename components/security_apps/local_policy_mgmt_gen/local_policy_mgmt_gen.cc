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
#include "i_agent_details.h"
#include "customized_cereal_map.h"
#include "include/appsec_practice_section.h"
#include "include/ingress_data.h"
#include "include/settings_section.h"
#include "include/triggers_section.h"
#include "include/local_policy_common.h"
#include "include/exceptions_section.h"
#include "include/rules_config_section.h"
#include "include/trusted_sources_section.h"
#include "include/policy_maker_utils.h"
#include "k8s_policy_utils.h"
#include "i_env_details.h"

using namespace std;

USE_DEBUG_FLAG(D_LOCAL_POLICY);

const static string default_local_appsec_policy_path = "/tmp/local_appsec.policy";
const static string default_local_mgmt_policy_path = "/conf/local_policy.yaml";

class LocalPolicyMgmtGenerator::Impl
        :
    public Singleton::Provide<I_LocalPolicyMgmtGen>::From<LocalPolicyMgmtGenerator>
{

public:
    void
    init()
    {
    }

    string
    parseLinuxPolicy(const string &policy_version, const string &local_policy_path)
    {
        dbgFlow(D_LOCAL_POLICY) << "Starting to parse policy - embedded environment";

        return policy_maker_utils.proccesSingleAppsecPolicy(
            local_policy_path,
            policy_version,
            default_local_appsec_policy_path
        );
    }

    string
    parseK8sPolicy(const string &policy_version)
    {
        dbgFlow(D_LOCAL_POLICY) << "Starting to parse policy - K8S environment";

        dbgInfo(D_LOCAL_POLICY) << "Initializing K8S policy generator";
        K8sPolicyUtils k8s_policy_utils;
        k8s_policy_utils.init();

        auto appsec_policies = k8s_policy_utils.createAppsecPoliciesFromIngresses();
        if (!std::get<0>(appsec_policies).empty()) {
            return policy_maker_utils.proccesMultipleAppsecPolicies<AppsecLinuxPolicy, ParsedRule>(
                std::get<0>(appsec_policies),
                policy_version,
                default_local_appsec_policy_path
            );
        }
        return policy_maker_utils.proccesMultipleAppsecPolicies<V1beta2AppsecLinuxPolicy, NewParsedRule>(
            std::get<1>(appsec_policies),
            policy_version,
            default_local_appsec_policy_path
        );
    }

    string
    generateAppSecLocalPolicy(EnvType env_type, const string &policy_version, const string &local_policy_paths)
    {
        return env_type == EnvType::K8S ?
            parseK8sPolicy(policy_version) : parseLinuxPolicy(policy_version, local_policy_paths);
    }

private:
    PolicyMakerUtils policy_maker_utils;
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
