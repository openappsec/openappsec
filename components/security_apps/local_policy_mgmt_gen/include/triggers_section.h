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

#ifndef __TRIGGERS_SECTION_H__
#define __TRIGGERS_SECTION_H__

#include <cereal/archives/json.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "config.h"
#include "debug.h"
#include "local_policy_common.h"
#include "i_agent_details.h"
#include "i_env_details.h"

class LogTriggerSection
{
public:
    LogTriggerSection()
    {}

    LogTriggerSection(
        const std::string &_name,
        const std::string &_verbosity,
        const std::string &_extendloggingMinSeverity,
        bool _extendlogging,
        bool _logToAgent,
        bool _logToCef,
        bool _logToCloud,
        bool _logToK8sService,
        bool _logToSyslog,
        bool _responseBody,
        bool _tpDetect,
        bool _tpPrevent,
        bool _acAllow,
        bool _acDrop,
        bool _webBody,
        bool _webHeaders,
        bool _webRequests,
        bool _webUrlPath,
        bool _webUrlQuery,
        int _cefPortNum,
        const std::string &_cefIpAddress,
        int _syslogPortNum,
        const std::string &_syslogIpAddress,
        bool _beautify_logs
    );

    void save(cereal::JSONOutputArchive &out_ar) const;

    const std::string & getTriggerId() const;
    const std::string & getTriggerName() const;

private:
    std::string id;
    std::string name;
    std::string context;
    std::string verbosity;
    std::string extendloggingMinSeverity;
    bool extendlogging;
    bool logToAgent;
    bool logToCef;
    bool logToCloud;
    bool logToK8sService;
    bool logToSyslog;
    bool responseBody;
    bool tpDetect;
    bool tpPrevent;
    bool acAllow;
    bool acDrop;
    bool webBody;
    bool webHeaders;
    bool webRequests;
    bool webUrlPath;
    bool webUrlQuery;
    int cefPortNum;
    std::string cefIpAddress;
    int syslogPortNum;
    std::string syslogIpAddress;
    bool beautify_logs;
};

class WebUserResponseTriggerSection
{
public:
    WebUserResponseTriggerSection() {}

    WebUserResponseTriggerSection(
        const std::string &_name,
        const std::string &_details_level,
        const std::string &_response_body,
        int _response_code,
        const std::string &_response_title
    );

    void save(cereal::JSONOutputArchive &out_ar) const;

    const std::string & getTriggerId() const;

private:
    std::string id;
    std::string name;
    std::string context;
    std::string details_level;
    std::string response_body;
    std::string response_title;
    int response_code;
};

class AppSecCustomResponseSpec
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    int getHttpResponseCode() const;
    const std::string & getMessageBody() const;
    const std::string & getMessageTitle() const;
    const std::string & getMode() const;
    const std::string & getName() const;
    void setName(const std::string &_name);

private:
    int httpResponseCode;
    std::string messageBody;
    std::string messageTitle;
    std::string mode;
    std::string name;
};

class TriggersRulebase
{
public:
    TriggersRulebase(
        std::vector<LogTriggerSection> _logTriggers,
        std::vector<WebUserResponseTriggerSection> _webUserResponseTriggers)
            :
        logTriggers(_logTriggers),
        webUserResponseTriggers(_webUserResponseTriggers) {}


    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    std::vector<LogTriggerSection> logTriggers;
    std::vector<WebUserResponseTriggerSection> webUserResponseTriggers;
};

class AppsecTriggerAccessControlLogging
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    bool isAcAllowEvents() const { return ac_allow_events; }
    bool isAcDropEvents() const { return ac_drop_events; }
private:
    bool ac_allow_events = false;
    bool ac_drop_events = false;
};

class AppsecTriggerAdditionalSuspiciousEventsLogging : public ClientRest
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    bool isEnabled() const;
    bool isResponseBody() const;
    const std::string & getMinimumSeverity() const;

private:
    bool enabled = true;
    bool response_body = false;
    std::string minimum_severity = "high";
};

class AppsecTriggerLogging : public ClientRest
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

class AppsecTriggerExtendedLogging : public ClientRest
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

class LoggingService
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

class StdoutLogging
{
public:
    StdoutLogging() : format("json") {}

    void load(cereal::JSONInputArchive &archive_in);
    const std::string & getFormat() const;

private:
    std::string format;
};

class AppsecTriggerLogDestination
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
    const LoggingService & getSyslogServiceData() const;
    const LoggingService & getCefServiceData() const;

    bool cloud = false;
    bool k8s_service = false;
    bool agent_local = true;
    bool beautify_logs = true;
    LoggingService syslog_service;
    LoggingService cef_service;
};

class AppsecTriggerSpec
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const std::string & getName() const;
    void setName(const std::string &_name);
    const AppsecTriggerAdditionalSuspiciousEventsLogging & getAppsecTriggerAdditionalSuspiciousEventsLogging() const;
    const AppsecTriggerLogging & getAppsecTriggerLogging() const;
    const AppsecTriggerExtendedLogging & getAppsecTriggerExtendedLogging() const;
    const AppsecTriggerLogDestination & getAppsecTriggerLogDestination() const;
    const AppsecTriggerAccessControlLogging & getAppsecTriggerAccessControlLogging() const;

private:
    AppsecTriggerAccessControlLogging access_control_logging;
    AppsecTriggerAdditionalSuspiciousEventsLogging additional_suspicious_events_logging;
    AppsecTriggerLogging appsec_logging;
    AppsecTriggerExtendedLogging extended_logging;
    AppsecTriggerLogDestination log_destination;
    std::string name;
};

class TriggersWrapper
{
public:
    TriggersWrapper(const TriggersRulebase &_triggers) : triggers_rulebase(_triggers)
    {}

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    TriggersRulebase triggers_rulebase;
};
#endif // __TRIGGERS_SECTION_H__
