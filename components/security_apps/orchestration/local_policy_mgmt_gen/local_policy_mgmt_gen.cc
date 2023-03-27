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
#include "include/k8s_policy_utils.h"
#include "i_env_details.h"

using namespace std;

USE_DEBUG_FLAG(D_LOCAL_POLICY);

const static string local_appsec_policy_path = "/tmp/local_appsec.policy";
const static string open_appsec_io = "openappsec.io/";
const static string policy_key = "policy";
const static string syslog_key = "syslog";
const static string mode_key = "mode";
const static string local_mgmt_policy_path = "/conf/local_policy.yaml";

// LCOV_EXCL_STOP
class LocalPolicyMgmtGenerator::Impl
        :
    public Singleton::Provide<I_LocalPolicyMgmtGen>::From<LocalPolicyMgmtGenerator>,
    public Singleton::Consume<I_MainLoop>,
    public Singleton::Consume<I_EnvDetails>
{

public:
// LCOV_EXCL_START Reason: no test exist
    void
    init()
    {
        env_details = Singleton::Consume<I_EnvDetails>::by<LocalPolicyMgmtGenerator::Impl>();
        env_type = env_details->getEnvType();
        if (env_type == EnvType::LINUX) {
            dbgInfo(D_LOCAL_POLICY) << "Initializing Linux policy generator";
            return;
        }
        dbgInfo(D_LOCAL_POLICY) << "Initializing K8S policy generator";
        k8s_policy_utils.init();

        Singleton::Consume<I_MainLoop>::by<LocalPolicyMgmtGenerator::Impl>()->addOneTimeRoutine(
            I_MainLoop::RoutineType::Offline,
            [this] ()
            {
                while(!k8s_policy_utils.getClusterId()) {
                    Singleton::Consume<I_MainLoop>::by<LocalPolicyMgmtGenerator::Impl>()->yield(chrono::seconds(1));
                }
                return;
            },
            "Get k8s cluster ID"
        );
    }

    string
    parseLinuxPolicy(const string &policy_version)
    {
        dbgFlow(D_LOCAL_POLICY) << "Starting to parse policy - embedded environment";

        string policy_path = getConfigurationFlagWithDefault(
            getFilesystemPathConfig() + local_mgmt_policy_path,
            "local_mgmt_policy"
        );

        Maybe<AppsecLinuxPolicy> maybe_policy = policy_maker_utils.openPolicyAsJson(policy_path);
        if (!maybe_policy.ok()){
            dbgWarning(D_LOCAL_POLICY) << maybe_policy.getErr();
            return "";
        }
        AppsecLinuxPolicy policy = maybe_policy.unpack();
        string policy_name = policy_maker_utils.getPolicyName(policy_path);
        dbgTrace(D_LOCAL_POLICY) << "Proccesing policy, name: " << policy_name;

        ParsedRule default_rule = policy.getAppsecPolicySpec().getDefaultRule();

        // add default rule to policy
        policy_maker_utils.createPolicyElementsByRule(default_rule, default_rule, policy, policy_name);

        vector<ParsedRule> specific_rules = policy.getAppsecPolicySpec().getSpecificRules();
        policy_maker_utils.createPolicyElements(
                specific_rules,
                default_rule,
                policy,
                policy_name
        );
        PolicyWrapper policy_wrapper = policy_maker_utils.combineElementsToPolicy(policy_version);
        return policy_maker_utils.dumpPolicyToFile(
            policy_wrapper,
            local_appsec_policy_path
        );
    }

    string
    parseK8sPolicy(const string &policy_version)
    {
        dbgFlow(D_LOCAL_POLICY) << "Starting to parse policy - K8S environment";

        map<string, AppsecLinuxPolicy> appsec_policies = k8s_policy_utils.createAppsecPoliciesFromIngresses();

        for (const auto &appsec_policy : appsec_policies) {
            string policy_name = appsec_policy.first;
            dbgTrace(D_LOCAL_POLICY) << "Proccesing policy, name: " << policy_name;
            AppsecLinuxPolicy policy = appsec_policy.second;

            ParsedRule default_rule = policy.getAppsecPolicySpec().getDefaultRule();

            // add default rule to policy
            policy_maker_utils.createPolicyElementsByRule(default_rule, default_rule, policy, policy_name);

            vector<ParsedRule> specific_rules = policy.getAppsecPolicySpec().getSpecificRules();
            policy_maker_utils.createPolicyElements(
                    specific_rules,
                    default_rule,
                    policy,
                    policy_name
            );
        }

        PolicyWrapper policy_wrapper = policy_maker_utils.combineElementsToPolicy(policy_version);
        return policy_maker_utils.dumpPolicyToFile(
            policy_wrapper,
            local_appsec_policy_path
        );
    }

    string
    parsePolicy(const string &policy_version)
    {
        return isK8sEnv() ? parseK8sPolicy(policy_version) : parseLinuxPolicy(policy_version);
    }

    const string & getPolicyPath(void) const override { return local_appsec_policy_path; }

private:
    bool
    isK8sEnv()
    {
        return env_type == EnvType::K8S;
    }

    I_EnvDetails* env_details = nullptr;
    EnvType env_type;
    PolicyMakerUtils policy_maker_utils;
    K8sPolicyUtils k8s_policy_utils;

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
