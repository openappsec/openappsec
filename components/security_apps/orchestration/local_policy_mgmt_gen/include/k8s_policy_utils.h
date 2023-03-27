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

#ifndef __K8S_POLICY_UTILS_H__
#define __K8S_POLICY_UTILS_H__

#include <string>
#include <fstream>
#include <utility>
#include <sys/types.h>

#include <cereal/archives/json.hpp>

#include "maybe_res.h"
#include "i_orchestration_tools.h"
#include "i_shell_cmd.h"
#include "i_messaging.h"
#include "i_env_details.h"
#include "i_agent_details.h"
#include "appsec_practice_section.h"
#include "policy_maker_utils.h"

enum class AnnotationKeys { PolicyKey, OpenAppsecIo, SyslogAddressKey, SyslogPortKey, ModeKey };

class K8sPolicyUtils
        :
    Singleton::Consume<I_Environment>,
    Singleton::Consume<I_OrchestrationTools>,
    Singleton::Consume<I_Messaging>,
    Singleton::Consume<I_ShellCmd>,
    Singleton::Consume<I_EnvDetails>,
    Singleton::Consume<I_AgentDetails>
{
public:
    void init();

    std::map<std::string, AppsecLinuxPolicy> createAppsecPoliciesFromIngresses();
    bool getClusterId() const;

private:
    std::map<AnnotationKeys, std::string> parseIngressAnnotations(
        const std::map<std::string, std::string> &annotations
    ) const;

    template<class T>
    Maybe<T, std::string> getObjectFromCluster(const std::string &path) const;

    std::map<AnnotationTypes, std::unordered_set<std::string>> extractElementsNames(
        const std::vector<ParsedRule> &specific_rules,
        const ParsedRule &default_rule
    ) const;

    template<class T>
    std::vector<T> extractElementsFromCluster(
        const std::string &crd_plural,
        const std::unordered_set<std::string> &elements_names
    ) const;

    Maybe<AppsecLinuxPolicy> createAppsecPolicyK8s(
        const std::string &policy_name,
        const std::string &ingress_mode
    ) const;

    I_EnvDetails* env_details = nullptr;
    I_Messaging* messaging = nullptr;
    EnvType env_type;
    Flags<MessageConnConfig> conn_flags;
    std::string token;
};

#endif // __K8S_POLICY_UTILS_H__
