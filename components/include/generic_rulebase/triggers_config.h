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

#ifndef __TRIGGERS_CONFIG_H__
#define __TRIGGERS_CONFIG_H__

#include <vector>
#include <string>

#include "environment/evaluator_templates.h"
#include "cereal/types/string.hpp"
#include "cereal/types/vector.hpp"
#include "cereal/archives/json.hpp"
#include "i_environment.h"
#include "i_logging.h"
#include "singleton.h"
#include "maybe_res.h"
#include "config.h"
#include "log_generator.h"
#include "generic_rulebase_utils.h"

class WebTriggerConf
{
public:
    WebTriggerConf();
    WebTriggerConf(const std::string &title, const std::string &body, uint code);

    static void
    preload()
    {
        registerExpectedConfiguration<WebTriggerConf>("rulebase", "webUserResponse");
    }

    void load(cereal::JSONInputArchive &archive_in);

    bool operator==(const WebTriggerConf &other) const;

    uint getResponseCode() const { return response_code; }

    const std::string & getResponseTitle() const { return response_title; }

    const std::string & getResponseBody() const { return response_body; }

    const std::string & getDetailsLevel() const { return details_level; }

    const std::string & getRedirectURL() const { return redirect_url; }

    bool getAddEventId() const { return add_event_id_to_header; }

    static WebTriggerConf default_trigger_conf;

private:
    std::string response_title;
    std::string details_level;
    std::string response_body;
    std::string redirect_url;
    uint        response_code;
    bool        add_event_id_to_header = false;
};

class LogTriggerConf : Singleton::Consume<I_Logging>
{
public:
    enum class SecurityType { AccessControl, ThreatPrevention, Compliance, COUNT };
    enum class extendLoggingSeverity { None, High, Critical };

    enum class WebLogFields {
        webBody,
        webHeaders,
        webRequests,
        webUrlPath,
        webUrlQuery,
        responseBody,
        responseCode,
        COUNT
    };

    LogTriggerConf() {}

    LogTriggerConf(std::string trigger_name, bool log_detect, bool log_prevent);

    static void
    preload()
    {
        registerExpectedConfiguration<LogTriggerConf>("rulebase", "log");
    }

    template <typename ...Tags>
    LogGen
    operator()(
        const std::string &title,
        SecurityType security,
        ReportIS::Severity severity,
        ReportIS::Priority priority,
        bool is_action_drop_or_prevent,
        Tags ...tags) const
    {
        return LogGen(
            title,
            ReportIS::Level::LOG,
            ReportIS::Audience::SECURITY,
            severity,
            priority,
            std::forward<Tags>(tags)...,
            getStreams(security, is_action_drop_or_prevent),
            getEnrechments(security)
        );
    }

    template <typename ...Tags>
    LogGen
    operator()(const std::string &title, SecurityType security, bool is_action_drop_or_prevent, Tags ...tags) const
    {
        return (*this)(
            title,
            security,
            getSeverity(is_action_drop_or_prevent),
            getPriority(is_action_drop_or_prevent),
            is_action_drop_or_prevent,
            std::forward<Tags>(tags)...
        );
    }

    void load(cereal::JSONInputArchive &archive_in);

    bool isWebLogFieldActive(WebLogFields log_field) const { return log_web_fields.isSet(log_field); }

    bool isLogStreamActive(ReportIS::StreamType stream_type) const { return active_streams.isSet(stream_type); }

    bool isPreventLogActive(SecurityType security_type) const { return should_log_on_prevent.isSet(security_type); }

    bool isDetectLogActive(SecurityType security_type) const { return should_log_on_detect.isSet(security_type); }

    bool isLogGeoLocationActive(SecurityType security_type) const { return log_geo_location.isSet(security_type); }

    extendLoggingSeverity getExtendLoggingSeverity() const { return extend_logging_severity; }

    const std::string & getVerbosity() const { return verbosity; }
    const std::string & getName() const { return name; }

    const std::string & getUrlForSyslog() const { return url_for_syslog; }
    const std::string & getUrlForCef() const { return url_for_cef; }

private:
    ReportIS::Severity getSeverity(bool is_action_drop_or_prevent) const;
    ReportIS::Priority getPriority(bool is_action_drop_or_prevent) const;

    Flags<ReportIS::StreamType> getStreams(SecurityType security_type, bool is_action_drop_or_prevent) const;
    Flags<ReportIS::Enreachments> getEnrechments(SecurityType security_type) const;

    std::string name;
    std::string verbosity;
    std::string url_for_syslog = "";
    std::string url_for_cef = "";
    Flags<ReportIS::StreamType> active_streams;
    Flags<SecurityType> should_log_on_detect;
    Flags<SecurityType> should_log_on_prevent;
    Flags<SecurityType> log_geo_location;
    Flags<WebLogFields> log_web_fields;
    extendLoggingSeverity extend_logging_severity = extendLoggingSeverity::None;
    bool should_format_output = false;
};

#endif //__TRIGGERS_CONFIG_H__
