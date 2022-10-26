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
#include "k8s_policy_common.h"

USE_DEBUG_FLAG(D_K8S_POLICY);

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
        bool _logToSyslog,
        bool _responseBody,
        bool _tpDetect,
        bool _tpPrevent,
        bool _webBody,
        bool _webHeaders,
        bool _webRequests,
        bool _webUrlPath,
        bool _webUrlQuery,
        int _cefPortNum,
        const std::string &_cefIpAddress,
        int _syslogPortNum,
        const std::string &_syslogIpAddress,
        bool _beautify_logs)
            :
        name(_name),
        verbosity(_verbosity),
        extendloggingMinSeverity(_extendloggingMinSeverity),
        extendlogging(_extendlogging),
        logToAgent(_logToAgent),
        logToCef(_logToCef),
        logToCloud(_logToCloud),
        logToSyslog(_logToSyslog),
        responseBody(_responseBody),
        tpDetect(_tpDetect),
        tpPrevent(_tpPrevent),
        webBody(_webBody),
        webHeaders(_webHeaders),
        webRequests(_webRequests),
        webUrlPath(_webUrlPath),
        webUrlQuery(_webUrlQuery),
        cefPortNum (_cefPortNum),
        cefIpAddress (_cefIpAddress),
        syslogPortNum (_syslogPortNum),
        syslogIpAddress (_syslogIpAddress),
        beautify_logs(_beautify_logs)
        {
            try {
                id = to_string(boost::uuids::random_generator()());
                context = "triggerId(" + id + ")";
            } catch (const boost::uuids::entropy_error &e) {
                dbgWarning(D_K8S_POLICY) << "Failed to generate log trigger UUID. Error: " << e.what();
            }
        }

    void
    serialize(cereal::JSONOutputArchive &out_ar) const
    {
        std::string trigger_type = "log";
        std::string urlForSyslog = syslogIpAddress + ":" + std::to_string(syslogPortNum);
        std::string urlForCef = cefIpAddress + ":" + std::to_string(cefPortNum);
        out_ar(
            cereal::make_nvp("context",                  context),
            cereal::make_nvp("triggerName",              name),
            cereal::make_nvp("triggerType",              trigger_type),
            cereal::make_nvp("verbosity",                verbosity),
            cereal::make_nvp("acAllow",                  false),
            cereal::make_nvp("acDrop",                   false),
            cereal::make_nvp("complianceViolations",     false),
            cereal::make_nvp("complianceWarnings",       false),
            cereal::make_nvp("extendloggingMinSeverity", extendloggingMinSeverity),
            cereal::make_nvp("extendlogging",            extendlogging),
            cereal::make_nvp("logToAgent",               logToAgent),
            cereal::make_nvp("logToCef",                 logToCef),
            cereal::make_nvp("logToCloud",               logToCloud),
            cereal::make_nvp("logToSyslog",              logToSyslog),
            cereal::make_nvp("responseBody",             responseBody),
            cereal::make_nvp("responseCode",             false),
            cereal::make_nvp("tpDetect",                 tpDetect),
            cereal::make_nvp("tpPrevent",                tpPrevent),
            cereal::make_nvp("webBody",                  webBody),
            cereal::make_nvp("webHeaders",               webHeaders),
            cereal::make_nvp("webRequests",              webRequests),
            cereal::make_nvp("webUrlPath",               webUrlPath),
            cereal::make_nvp("webUrlQuery",              webUrlQuery),
            cereal::make_nvp("urlForSyslog",             urlForSyslog),
            cereal::make_nvp("urlForCef",                urlForCef),
            cereal::make_nvp("formatLoggingOutput",      beautify_logs)
        );
    }

    const std::string & getTriggerId() const { return id; }
    const std::string & getTriggerName() const { return name; }

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
    bool logToSyslog;
    bool responseBody;
    bool tpDetect;
    bool tpPrevent;
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
    WebUserResponseTriggerSection(
        const std::string &_name,
        const std::string &_details_level,
        const std::string &_response_body,
        int _response_code,
        const std::string &_response_title)
            :
        name(_name),
        context(),
        details_level(_details_level),
        response_body(_response_body),
        response_title(_response_title),
        response_code(_response_code)
        {
            try {
                id = to_string(boost::uuids::random_generator()());
                context = "triggerId(" + id + ")";
            } catch (const boost::uuids::entropy_error &e) {
                dbgWarning(D_K8S_POLICY) << "Failed to generate webUserResponse trigger UUID. Error: " << e.what();
            }
        }

    void
    serialize(cereal::JSONOutputArchive &out_ar) const
    {
        out_ar(
            cereal::make_nvp("context",       context),
            cereal::make_nvp("triggerName",   name),
            cereal::make_nvp("details level", details_level),
            cereal::make_nvp("response body", response_body),
            cereal::make_nvp("response code", response_code),
            cereal::make_nvp("response title", response_title)
        );
    }

    const std::string & getTriggerId() const { return id; }
    const std::string & getTriggerName() const { return name; }

private:
    std::string id;
    std::string name;
    std::string context;
    std::string details_level;
    std::string response_body;
    std::string response_title;
    int response_code;
};

class AppSecWebUserResponseSpec
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_K8S_POLICY) << "Loading AppSec web user response spec";
        parseAppsecJSONKey<int>("http-response-code", httpResponseCode, archive_in, 403);
        parseAppsecJSONKey<std::string>("mode", mode, archive_in, "block-page");
        if (mode == "block-page") {
            parseAppsecJSONKey<std::string>(
                "message-body",
                messageBody,
                archive_in,
                "Openappsec's <b>Application Security</b> has detected an attack and blocked it."
            );
            parseAppsecJSONKey<std::string>(
                "message-title",
                messageTitle,
                archive_in,
                "Attack blocked by web application protection"
            );
        }
    }

    int getHttpResponseCode() const { return httpResponseCode; }
    const std::string & getMessageBody() const { return messageBody; }
    const std::string & getMessageTitle() const { return messageTitle; }
    const std::string & getMode() const { return mode; }

private:
    int httpResponseCode;
    std::string messageBody;
    std::string messageTitle;
    std::string mode;
};

std::ostream &
operator<<(std::ostream &os, const AppSecWebUserResponseSpec &obj)
{
    os
        << "mode: "
        << obj.getMode()
        << "," << std::endl << "message-title: "
        << obj.getMessageTitle()
        << "," << std::endl << "message-body: "
        << obj.getMessageBody()
        << "," << std::endl << "http-response-code: "
        << obj.getHttpResponseCode();
    return os;
}

class TriggersRulebase
{
public:
    TriggersRulebase(
        std::vector<LogTriggerSection> _logTriggers,
        std::vector<WebUserResponseTriggerSection> _webUserResponseTriggers)
            :
        logTriggers(_logTriggers),
        webUserResponseTriggers(_webUserResponseTriggers) {}


    void
    serialize(cereal::JSONOutputArchive &out_ar) const
    {
        out_ar(
            cereal::make_nvp("log",             logTriggers),
            cereal::make_nvp("webUserResponse", webUserResponseTriggers)
        );
    }

private:
    std::vector<LogTriggerSection> logTriggers;
    std::vector<WebUserResponseTriggerSection> webUserResponseTriggers;
};

class AppsecTriggerAccessControlLogging
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_K8S_POLICY) << "Loading AppSec Trigger - Access Control Logging";
        parseAppsecJSONKey<bool>("allow-events", allow_events, archive_in, false);
        parseAppsecJSONKey<bool>("drop-events", drop_events, archive_in, false);
    }

    bool isAllowEvents() const { return allow_events; }
    bool isDropEvents() const { return drop_events; }

private:
    bool allow_events = false;
    bool drop_events = false;
};

std::ostream &
operator<<(std::ostream &os, const AppsecTriggerAccessControlLogging &obj)
{
    os
        << "AppSec Trigger - Access Control Logging: "
        << "isAllowEvents: "
        << obj.isAllowEvents()
        << " , isDropEvents: "
        << obj.isDropEvents();
    return os;
}

class AppsecTriggerAdditionalSuspiciousEventsLogging : public ClientRest
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_K8S_POLICY) << "Loading AppSec Trigger - Additional Suspicious Events Logging";
        parseAppsecJSONKey<bool>("enabled", enabled, archive_in, true);
        parseAppsecJSONKey<bool>("response-body", response_body, archive_in, false);
        parseAppsecJSONKey<std::string>("minimum-severity", minimum_severity, archive_in, "high");
    }

    bool isEnabled() const { return enabled; }
    bool isResponseBody() const { return response_body; }
    const std::string & getMinimumSeverity() const { return minimum_severity; }

private:
    bool enabled = true;
    bool response_body = false;
    std::string minimum_severity = "high";
};

std::ostream &
operator<<(std::ostream &os, const AppsecTriggerAdditionalSuspiciousEventsLogging &obj)
{
    os
        << "AppsecTriggerAdditionalSuspiciousEventsLogging: "
        << "Enabled: "
        << obj.isEnabled()
        << " response_body: "
        << obj.isResponseBody()
        << " minimum_severity: "
        << obj.getMinimumSeverity();
    return os;
}

class AppsecTriggerLogging : public ClientRest
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_K8S_POLICY) << "Loading AppSec Trigger Logging";
        parseAppsecJSONKey<bool>("all-web-requests", all_web_requests, archive_in, false);
        parseAppsecJSONKey<bool>("detect-events", detect_events, archive_in, false);
        parseAppsecJSONKey<bool>("prevent-events", prevent_events, archive_in, true);
    }

    bool isAllWebRequests() const { return all_web_requests; }

    bool isDetectEvents() const { return detect_events; }

    bool isPreventEvents() const { return prevent_events; }

private:
    bool all_web_requests = false;
    bool detect_events = false;
    bool prevent_events = true;
};

std::ostream &
operator<<(std::ostream &os, const AppsecTriggerLogging &obj)
{
    os
        << "AppsecTriggerLogging: "
        << "all_web_requests: "
        << obj.isAllWebRequests()
        << ", detect_events: "
        << obj.isDetectEvents()
        << ", prevent_events: "
        << obj.isPreventEvents();
    return os;
}

class AppsecTriggerExtendedLogging : public ClientRest
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_K8S_POLICY) << "Loading AppSec Trigger Extended Logging";
        parseAppsecJSONKey<bool>("http-headers", http_headers, archive_in, false);
        parseAppsecJSONKey<bool>("request-body", request_body, archive_in, false);
        parseAppsecJSONKey<bool>("url-path", url_path, archive_in, false);
        parseAppsecJSONKey<bool>("url-query", url_query, archive_in, false);
    }

    bool isHttpHeaders() const { return http_headers; }
    bool isRequestBody() const { return request_body; }
    bool isUrlPath() const { return url_path; }
    bool isUrlQuery() const { return url_query; }

private:
    bool http_headers = false;
    bool request_body = false;
    bool url_path = false;
    bool url_query = false;
};

std::ostream &
operator<<(std::ostream &os, const AppsecTriggerExtendedLogging &obj)
{
    os
        << "AppsecTriggerExtendedLogging: "
        << "http_headers: "
        << obj.isHttpHeaders()
        << ", request_body: "
        << obj.isRequestBody()
        << ", url_path: "
        << obj.isUrlPath()
        << ", url_query: "
        << obj.isUrlQuery();
    return os;
}

class LoggingService
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        parseAppsecJSONKey<std::string>("address", address, archive_in);
        parseAppsecJSONKey<std::string>("proto", proto, archive_in);
        parseAppsecJSONKey<int>("port", port, archive_in, 514);
    }

    const std::string & getAddress() const { return address; }
    const std::string & getProto() const { return proto; }
    int getPort() const { return port; }

private:
    std::string address;
    std::string proto;
    int port = 514;
};

class StdoutLogging
{
public:
    StdoutLogging() : format("json") {}

    void
    load(cereal::JSONInputArchive &archive_in)
    {
        parseAppsecJSONKey<std::string>("format", format, archive_in, "json");
    }

    const std::string & getFormat() const { return format; }

private:
    std::string format;
};

class AppsecTriggerLogDestination : public ClientRest
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgError(D_K8S_POLICY) << "AppsecTriggerLogDestination load";
        // TBD: support "file"
        parseAppsecJSONKey<bool>("cloud", cloud, archive_in, false);

        StdoutLogging stdout_log;
        parseAppsecJSONKey<StdoutLogging>("stdout", stdout_log, archive_in);
        agent_local = !(stdout_log.getFormat().empty());
        beautify_logs = stdout_log.getFormat() == "json-formatted";
        parseAppsecJSONKey<LoggingService>("syslog-service", syslog_service, archive_in);
        parseAppsecJSONKey<LoggingService>("cef-service", cef_service, archive_in);
    }

    int getCefServerUdpPort() const { return getCefServiceData().getPort(); }
    int getSyslogServerUdpPort() const { return getSyslogServiceData().getPort(); }
    bool isAgentLocal() const { return agent_local; }
    bool shouldBeautifyLogs() const { return beautify_logs; }

    bool getCloud() const { return cloud; }
    bool isCefNeeded() const { return !getCefServiceData().getAddress().empty(); }
    bool isSyslogNeeded() const { return !getSyslogServiceData().getAddress().empty(); }
    const std::string & getSyslogServerIpv4Address() const { return getSyslogServiceData().getAddress(); }
    const std::string & getCefServerIpv4Address() const { return getCefServiceData().getAddress(); }

private:
    const LoggingService & getSyslogServiceData() const { return syslog_service; }
    const LoggingService & getCefServiceData() const { return cef_service; }

    bool cloud = false;
    bool agent_local = true;
    bool beautify_logs = true;
    LoggingService syslog_service;
    LoggingService cef_service;
};

std::ostream &
operator<<(std::ostream &os, const AppsecTriggerLogDestination &obj)
{
    os
        << "AppSec Trigger Log Destination:" << std::endl
        << "agent_local: "
        << obj.isAgentLocal()
        << ", beautify_logs: "
        << obj.shouldBeautifyLogs()
        << ", cef_server_udp_port: "
        << obj.getCefServerUdpPort()
        << ", syslog_server_udp_port: "
        << obj.getSyslogServerUdpPort()
        << ", cef_service: "
        << obj.isCefNeeded()
        << ", cloud: "
        << obj.getCloud()
        << ", syslog: "
        << obj.isSyslogNeeded()
        << ", syslog_server_ipv4_address: "
        << obj.getSyslogServerIpv4Address()
        << ", cef_server_ipv4_address: "
        << obj.getCefServerIpv4Address();
    return os;
}

class AppsecTriggerSpec
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_K8S_POLICY) << "Loading AppSec trigger spec";
        parseAppsecJSONKey<AppsecTriggerAccessControlLogging>(
            "access-control-logging",
            access_control_logging,
            archive_in
        );
        parseAppsecJSONKey<AppsecTriggerAdditionalSuspiciousEventsLogging>(
            "additional-suspicious-events-logging",
            additional_suspicious_events_logging,
            archive_in
        );
        parseAppsecJSONKey<AppsecTriggerLogging>("appsec-logging", appsec_logging, archive_in);
        parseAppsecJSONKey<AppsecTriggerExtendedLogging>("extended-logging", extended_logging, archive_in);
        parseAppsecJSONKey<AppsecTriggerLogDestination>("log-destination", log_destination, archive_in);
    }

    const AppsecTriggerAccessControlLogging &
    getAppsecTriggerAccessControlLogging() const
    {
        return access_control_logging;
    }

    const AppsecTriggerAdditionalSuspiciousEventsLogging &
    getAppsecTriggerAdditionalSuspiciousEventsLogging() const
    {
        return additional_suspicious_events_logging;
    }

    const AppsecTriggerLogging &
    getAppsecTriggerLogging() const
    {
        return appsec_logging;
    }

    const AppsecTriggerExtendedLogging &
    getAppsecTriggerExtendedLogging() const
    {
        return extended_logging;
    }

    const AppsecTriggerLogDestination &
    getAppsecTriggerLogDestination() const
    {
        return log_destination;
    }

private:
    AppsecTriggerAccessControlLogging access_control_logging;
    AppsecTriggerAdditionalSuspiciousEventsLogging additional_suspicious_events_logging;
    AppsecTriggerLogging appsec_logging;
    AppsecTriggerExtendedLogging extended_logging;
    AppsecTriggerLogDestination log_destination;
};

std::ostream &
operator<<(std::ostream &os, const AppsecTriggerSpec &obj)
{
    os
        << "AppSec Access Control Logging:" << std::endl
        << obj.getAppsecTriggerAccessControlLogging()
        << std::endl << "AppSec Additional Suspocious Events Logging:" << std::endl
        << obj.getAppsecTriggerAdditionalSuspiciousEventsLogging()
        << std::endl << "AppSec Trigger Logging:" << std::endl
        << obj.getAppsecTriggerLogging()
        << std::endl << "Appsec Trigger Extended Logging:" << std::endl
        << obj.getAppsecTriggerExtendedLogging()
        << std::endl << "AppSec Trigger Log Destination:" << std::endl
        << obj.getAppsecTriggerLogDestination();
    return os;
}

class TriggersWrapper
{
public:
    TriggersWrapper(const TriggersRulebase &_triggers) : triggers_rulebase(_triggers)
    {}

    void
    serialize(cereal::JSONOutputArchive &out_ar) const
    {
        out_ar(
            cereal::make_nvp("rulebase", triggers_rulebase)
        );
    }

private:
    TriggersRulebase triggers_rulebase;
};

#endif // __TRIGGERS_SECTION_H__
