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

#ifndef __NEW_LOG_TRIGGERS_H__
#define __NEW_LOG_TRIGGERS_H__

#include <cereal/archives/json.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "config.h"
#include "debug.h"
#include "local_policy_common.h"
#include "i_agent_details.h"
#include "i_env_details.h"

class NewAppsecTriggerAccessControlLogging
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    bool isAcAllowEvents() const { return ac_allow_events; }
    bool isAcDropEvents() const { return ac_drop_events; }
private:
    bool ac_allow_events = false;
    bool ac_drop_events = false;
};

class NewAppsecTriggerAdditionalSuspiciousEventsLogging : public ClientRest
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    bool isEnabled() const;
    bool isResponseBody() const;
    const std::string & getMinimumSeverity() const;

private:
    bool enabled = true;
    bool response_body = false;
    bool response_code = false;
    std::string minimum_severity = "high";
};

class NewAppsecTriggerLogging : public ClientRest
{
public:
    void
    load(cereal::JSONInputArchive &archive_in);

    bool isAllWebRequests() const;
    bool isDetectEvents() const;
    bool isPreventEvents() const;

private:
    bool all_web_requests = false;
    bool detect_events = false;
    bool prevent_events = true;
};

class NewAppsecTriggerExtendedLogging : public ClientRest
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    bool isHttpHeaders() const;
    bool isRequestBody() const;
    bool isUrlPath() const;
    bool isUrlQuery() const;

private:
    bool http_headers = false;
    bool request_body = false;
    bool url_path = false;
    bool url_query = false;
};

class NewLoggingService
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const std::string & getAddress() const;
    int getPort() const;

private:
    std::string address;
    std::string proto;
    int port = 514;
};

class NewStdoutLogging
{
public:
    // LCOV_EXCL_START Reason: no test exist
    NewStdoutLogging() : format("json") {}
    // LCOV_EXCL_STOP

    void load(cereal::JSONInputArchive &archive_in);
    const std::string & getFormat() const;

private:
    std::string format;
};

class NewAppsecTriggerLogDestination
        :
    public ClientRest,
    Singleton::Consume<I_AgentDetails>,
    Singleton::Consume<I_EnvDetails>
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    int getCefServerUdpPort() const;
    int getSyslogServerUdpPort() const;
    bool isAgentLocal() const;
    bool shouldBeautifyLogs() const;

    bool getCloud() const;
    bool isK8SNeeded() const;
    bool isCefNeeded() const;
    bool isSyslogNeeded() const;
    const std::string & getSyslogServerIpv4Address() const;
    const std::string & getCefServerIpv4Address() const;

private:
    const NewLoggingService & getSyslogServiceData() const;
    const NewLoggingService & getCefServiceData() const;

    bool cloud = false;
    bool k8s_service = false;
    bool agent_local = true;
    bool beautify_logs = true;
    NewLoggingService syslog_service;
    NewLoggingService cef_service;
};

class NewAppsecLogTrigger
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const std::string & getName() const;
    const std::string & getAppSecClassName() const;
    void setName(const std::string &_name);
    const NewAppsecTriggerAdditionalSuspiciousEventsLogging &
    getAppsecTriggerAdditionalSuspiciousEventsLogging() const;
    const NewAppsecTriggerLogging & getAppsecTriggerLogging() const;
    const NewAppsecTriggerExtendedLogging & getAppsecTriggerExtendedLogging() const;
    const NewAppsecTriggerLogDestination & getAppsecTriggerLogDestination() const;
    const NewAppsecTriggerAccessControlLogging & getAppsecTriggerAccessControlLogging() const;

private:
    NewAppsecTriggerAccessControlLogging access_control_logging;
    NewAppsecTriggerAdditionalSuspiciousEventsLogging additional_suspicious_events_logging;
    NewAppsecTriggerLogging appsec_logging;
    NewAppsecTriggerExtendedLogging extended_logging;
    NewAppsecTriggerLogDestination log_destination;
    std::string name;
    std::string appsec_class_name;
};

#endif // __NEW_LOG_TRIGGERS_H__
