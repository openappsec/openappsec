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

#ifndef __POLICY_MAKER_UTILS_H__
#define __POLICY_MAKER_UTILS_H__

#include <string>
#include <fstream>
#include <utility>
#include <sys/types.h>

#include <cereal/archives/json.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "debug.h"
#include "common.h"
#include "maybe_res.h"
#include "i_orchestration_tools.h"
#include "i_shell_cmd.h"
#include "i_messaging.h"
#include "appsec_practice_section.h"
#include "ingress_data.h"
#include "settings_section.h"
#include "triggers_section.h"
#include "local_policy_common.h"
#include "exceptions_section.h"
#include "rules_config_section.h"
#include "trusted_sources_section.h"
#include "new_appsec_linux_policy.h"
#include "access_control_practice.h"
#include "reverse_proxy_section.h"

enum class AnnotationTypes {
    PRACTICE,
    THREAT_PREVENTION_PRACTICE,
    ACCESS_CONTROL_PRACTICE,
    TRIGGER,
    EXCEPTION,
    WEB_USER_RES,
    SOURCE_IDENTIFIERS,
    TRUSTED_SOURCES,
    UPGRADE_SETTINGS,
    COUNT
};

class SecurityAppsWrapper
{
public:
    SecurityAppsWrapper(
        const AppSecWrapper                 &_waap,
        const TriggersWrapper               &_trrigers,
        const RulesConfigWrapper            &_rules,
        const IntrusionPreventionWrapper    &_ips,
        const SnortSectionWrapper           &_snort,
        const AccessControlRulebaseWrapper  &_rate_limit,
        const FileSecurityWrapper           &_file_security,
        const ExceptionsWrapper             &_exceptions,
        const std::string                   &_policy_version)
            :
        waap(_waap),
        trrigers(_trrigers),
        rules(_rules),
        ips(_ips),
        snort(_snort),
        rate_limit(_rate_limit),
        file_security(_file_security),
        exceptions(_exceptions),
        policy_version(_policy_version) {}

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    AppSecWrapper                   waap;
    TriggersWrapper                 trrigers;
    RulesConfigWrapper              rules;
    IntrusionPreventionWrapper      ips;
    SnortSectionWrapper             snort;
    AccessControlRulebaseWrapper    rate_limit;
    FileSecurityWrapper             file_security;
    ExceptionsWrapper               exceptions;
    std::string                     policy_version;
};

class PolicyWrapper
{
public:
    PolicyWrapper(
        const SettingsRulebase &_settings,
        const SecurityAppsWrapper &_security_apps)
            :
        settings(_settings),
        security_apps(_security_apps) {}

    const SettingsRulebase & getSettings() const { return settings; }
    const SecurityAppsWrapper & getSecurityApps() const { return security_apps; }

private:
    SettingsRulebase settings;
    SecurityAppsWrapper security_apps;
};

class PolicyMakerUtils
{
public:
    std::string proccesSingleAppsecPolicy(
        const std::string &policy_path,
        const std::string &policy_version,
        const std::string &local_appsec_policy_path
    );

    template<class T, class R>
    std::string proccesMultipleAppsecPolicies(
        const std::map<std::string, T> &appsec_policies,
        const std::string &policy_version,
        const std::string &local_appsec_policy_path
    );

private:
    std::string getPolicyName(const std::string &policy_path);

    template<class T>
    Maybe<T> openFileAsJson(const std::string &path);

    void clearElementsMaps();

    bool startsWith(const std::string &str, const std::string &prefix);

    bool endsWith(const std::string &str, const std::string &suffix);

    std::tuple<std::string, std::string, std::string> splitHostName(const std::string &host_name);

    std::string dumpPolicyToFile(
        const PolicyWrapper &policy,
        const std::string &policy_path,
        const std::string &settings_path = "/etc/cp/conf/settings.json"
    );

    PolicyWrapper combineElementsToPolicy(const std::string &policy_version);

    void
    createIpsSections(
        const std::string &asset_id,
        const std::string &asset_name,
        const std::string &practice_id,
        const std::string &practice_name,
        const std::string &source_identifier,
        const std::string & context,
        const V1beta2AppsecLinuxPolicy &policy,
        std::map<AnnotationTypes, std::string> &rule_annotations
    );

    void createSnortProtecionsSection(const std::string &file_name, bool is_temporary);

    void
    createSnortSections(
        const std::string & context,
        const std::string &asset_name,
        const std::string &asset_id,
        const std::string &practice_name,
        const std::string &practice_id,
        const std::string &source_identifier,
        const V1beta2AppsecLinuxPolicy &policy,
        std::map<AnnotationTypes, std::string> &rule_annotations
    );

    void
    createFileSecuritySections(
        const std::string &asset_id,
        const std::string &asset_name,
        const std::string &practice_id,
        const std::string &practice_name,
        const std::string & context,
        const V1beta2AppsecLinuxPolicy &policy,
        std::map<AnnotationTypes, std::string> &rule_annotations
    );

    void
    createRateLimitSection(
        const std::string &asset_name,
        const std::string &url,
        const std::string &uri,
        const std::string &trigger_id,
        const V1beta2AppsecLinuxPolicy &policy,
        std::map<AnnotationTypes, std::string> &rule_annotations
    );

    void createWebAppSection(
        const V1beta2AppsecLinuxPolicy &policy,
        const RulesConfigRulebase& rule_config,
        const std::string &practice_id, const std::string &full_url,
        const std::string &default_mode,
        std::map<AnnotationTypes, std::string> &rule_annotations
    );

    void
    createThreatPreventionPracticeSections(
        const std::string &asset_name,
        const std::string &url,
        const std::string &port,
        const std::string &uri,
        const std::string &default_mode,
        const V1beta2AppsecLinuxPolicy &policy,
        std::map<AnnotationTypes, std::string> &rule_annotations
    );

    template<class T, class R>
    void createPolicyElementsByRule(
        const R &rule,
        const R &default_rule,
        const T &policy,
        const std::string &policy_name
    );

    template<class T, class R>
    void createPolicyElements(
        const std::vector<R> &rules,
        const R &default_rule,
        const T &policy,
        const std::string &policy_name
    );

    template<class T, class R>
    void createAgentPolicyFromAppsecPolicy(const std::string &policy_name, const T &appsec_policy);

    void rpmBuildNginxServers(const AppsecLinuxPolicy &policy);
    void rpmReportInfo(const std::string &msg);
    void rpmReportError(const std::string &msg);

    std::string policy_version_name;
    std::map<std::string, LogTriggerSection> log_triggers;
    std::map<std::string, WebUserResponseTriggerSection> web_user_res_triggers;
    std::map<std::string, std::vector<InnerException>> inner_exceptions;
    std::map<std::string, WebAppSection> web_apps;
    std::map<std::string, RulesConfigRulebase> rules_config;
    std::map<std::string, IpsProtectionsSection> ips;
    std::map<std::string, SnortProtectionsSection> snort;
    std::map<std::string, ProtectionsSection> snort_protections;
    std::map<std::string, FileSecurityProtectionsSection> file_security;
    std::map<std::string, RateLimitSection> rate_limit;
    std::map<std::string, UsersIdentifiersRulebase> users_identifiers;
    std::map<std::string, AppSecTrustedSources> trusted_sources;
    AppSecAutoUpgradeSpec upgrade_settings;
};

template<class T, class R>
std::string
PolicyMakerUtils::proccesMultipleAppsecPolicies(
    const std::map<std::string, T> &appsec_policies,
    const std::string &policy_version,
    const std::string &local_appsec_policy_path)
{
    for (const auto &appsec_policy : appsec_policies) {
        createAgentPolicyFromAppsecPolicy<T, R>(appsec_policy.first, appsec_policy.second);
    }

    PolicyWrapper policy_wrapper = combineElementsToPolicy(policy_version);
    return dumpPolicyToFile(
        policy_wrapper,
        local_appsec_policy_path
    );
}

#endif // __POLICY_MAKER_UTILS_H__
