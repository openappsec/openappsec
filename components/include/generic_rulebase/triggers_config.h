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

/// \file triggers_config.h
/// \brief Declaration of classes WebTriggerConf and LogTriggerConf, and related functions.
/// \author Check Point Software Technologies Ltd.
/// \date 2022

#ifndef __TRIGGERS_CONFIG_H__
#define __TRIGGERS_CONFIG_H__

#include <string>
#include <vector>

#include "cereal/archives/json.hpp"
#include "cereal/types/string.hpp"
#include "cereal/types/vector.hpp"
#include "config.h"
#include "environment/evaluator_templates.h"
#include "generic_rulebase_utils.h"
#include "i_environment.h"
#include "i_logging.h"
#include "log_generator.h"
#include "maybe_res.h"
#include "singleton.h"

/// \class WebTriggerConf
/// \brief Represents the configuration for a web trigger.
class WebTriggerConf
{
public:
    /// \brief Default constructor for WebTriggerConf.
    WebTriggerConf();

    /// \brief Constructor for WebTriggerConf.
    /// \param title The title of the trigger.
    /// \param body The body of the trigger.
    /// \param code The response code for the trigger.
    WebTriggerConf(const std::string &title, const std::string &body, uint code);

    /// \brief Preload function to register expected configuration.
    static void
    preload()
    {
        registerExpectedConfiguration<WebTriggerConf>("rulebase", "webUserResponse");
    }

    /// \brief Load function to deserialize configuration from JSONInputArchive.
    /// \param archive_in The JSON input archive.
    void load(cereal::JSONInputArchive &archive_in);

    /// \brief Equality operator for WebTriggerConf.
    /// \param other The WebTriggerConf to compare.
    /// \return True if the two WebTriggerConf objects are equal, otherwise false.
    bool operator==(const WebTriggerConf &other) const;

    /// \brief Get the response code for the trigger.
    /// \return The response code.
    uint
    getResponseCode() const
    {
        return response_code;
    }

    /// \brief Get the response title for the trigger.
    /// \return The response title.
    const std::string &
    getResponseTitle() const
    {
        return response_title;
    }

    /// \brief Get the response body for the trigger.
    /// \return The response body.
    const std::string &
    getResponseBody() const
    {
        return response_body;
    }

    /// \brief Get the details level for the trigger.
    /// \return The details level.
    const std::string &
    getDetailsLevel() const
    {
        return details_level;
    }

    /// \brief Get the redirect URL for the trigger.
    /// \return The redirect URL.
    const std::string &
    getRedirectURL() const
    {
        return redirect_url;
    }

    /// \brief Check if the trigger should add an event ID to the header.
    /// \return True if the trigger should add an event ID, otherwise false.
    bool
    getAddEventId() const
    {
        return add_event_id_to_header;
    }

    /// \brief Default trigger configuration for WebTriggerConf.
    static WebTriggerConf default_trigger_conf;

private:
    std::string response_title;
    std::string details_level;
    std::string response_body;
    std::string redirect_url;
    uint response_code;
    bool add_event_id_to_header = false;
};

/// \class LogTriggerConf
/// \brief Represents the configuration for a log trigger.
class LogTriggerConf : Singleton::Consume<I_Logging>
{
public:
    /// \enum SecurityType
    /// \brief Enumerates the security types for LogTriggerConf.
    enum class SecurityType
    {
        AccessControl,
        ThreatPrevention,
        Compliance,
        COUNT
    };

    /// \enum extendLoggingSeverity
    /// \brief Enumerates the extended logging severity for LogTriggerConf.
    enum class extendLoggingSeverity
    {
        None,
        High,
        Critical
    };

    /// \enum WebLogFields
    /// \brief Enumerates the web log fields for LogTriggerConf.
    enum class WebLogFields
    {
        webBody,
        webHeaders,
        webRequests,
        webUrlPath,
        webUrlQuery,
        responseBody,
        responseCode,
        COUNT
    };

    /// \brief Default constructor for LogTriggerConf.
    LogTriggerConf() {}

    /// \brief Constructor for LogTriggerConf.
    /// \param trigger_name The name of the trigger.
    /// \param log_detect Flag indicating whether to log on detect.
    /// \param log_prevent Flag indicating whether to log on prevent.
    LogTriggerConf(std::string trigger_name, bool log_detect, bool log_prevent);

    /// \brief Preload function to register expected configuration.
    static void
    preload()
    {
        registerExpectedConfiguration<LogTriggerConf>("rulebase", "log");
    }

    /// \brief LogGen operator for LogTriggerConf.
    /// \param title The title of the log.
    /// \param security The security type of the log.
    /// \param severity The severity of the log.
    /// \param priority The priority of the log.
    /// \param is_action_drop_or_prevent Flag indicating if the action is drop or prevent.
    /// \param tags Tags for the log.
    /// \return The LogGen object.
    template <typename... Tags>
    LogGen
    operator()(
        const std::string &title,
        SecurityType security,
        ReportIS::Severity severity,
        ReportIS::Priority priority,
        bool is_action_drop_or_prevent,
        Tags... tags
    ) const
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

    /// \brief LogGen operator for LogTriggerConf.
    /// \param title The title of the log.
    /// \param security The security type of the log.
    /// \param is_action_drop_or_prevent Flag indicating if the action is drop or prevent.
    /// \param tags Tags for the log.
    /// \return The LogGen object.
    template <typename... Tags>
    LogGen
    operator()(const std::string &title, SecurityType security, bool is_action_drop_or_prevent, Tags... tags) const
    {
        return operator()(
            title,
            security,
            getSeverity(is_action_drop_or_prevent),
            getPriority(is_action_drop_or_prevent),
            is_action_drop_or_prevent,
            std::forward<Tags>(tags)...
        );
    }

    /// \brief Load function to deserialize configuration from JSONInputArchive.
    /// \param archive_in The JSON input archive.
    void load(cereal::JSONInputArchive &archive_in);

    /// \brief Check if the web log field is active for the trigger.
    /// \param log_field The web log field to check.
    /// \return True if the web log field is active, otherwise false.
    bool
    isWebLogFieldActive(WebLogFields log_field) const
    {
        return log_web_fields.isSet(log_field);
    }

    /// \brief Check if the log stream is active for the trigger.
    /// \param stream_type The log stream type to check.
    /// \return True if the log stream is active, otherwise false.
    bool
    isLogStreamActive(ReportIS::StreamType stream_type) const
    {
        return active_streams.isSet(stream_type);
    }

    /// \brief Check if the log is active on prevent for the given security type.
    /// \param security_type The security type to check.
    /// \return True if the log is active on prevent, otherwise false.
    bool
    isPreventLogActive(SecurityType security_type) const
    {
        return should_log_on_prevent.isSet(security_type);
    }

    /// \brief Check if the log is active on detect for the given security type.
    /// \param security_type The security type to check.
    /// \return True if the log is active on detect, otherwise false.
    bool
    isDetectLogActive(SecurityType security_type) const
    {
        return should_log_on_detect.isSet(security_type);
    }

    /// \brief Check if the geo-location log is active for the given security type.
    /// \param security_type The security type to check.
    /// \return True if the geo-location log is active, otherwise false.
    bool
    isLogGeoLocationActive(SecurityType security_type) const
    {
        return log_geo_location.isSet(security_type);
    }

    /// \brief Get the extended logging severity.
    /// \return The extended logging severity.
    extendLoggingSeverity
    getExtendLoggingSeverity() const
    {
        return extend_logging_severity;
    }

    /// \brief Get the verbosity.
    /// \return The verbosity.
    const std::string &
    getVerbosity() const
    {
        return verbosity;
    }

    /// \brief Get the name.
    /// \return The name.
    const std::string &
    getName() const
    {
        return name;
    }

    /// \brief Get the URL for syslog.
    /// \return The URL for syslog.
    const std::string &
    getUrlForSyslog() const
    {
        return url_for_syslog;
    }

    /// \brief Get the URL for CEF.
    /// \return The URL for CEF.
    const std::string &
    getUrlForCef() const
    {
        return url_for_cef;
    }

private:
    ReportIS::Severity getSeverity(bool is_action_drop_or_prevent) const;
    ReportIS::Priority getPriority(bool is_action_drop_or_prevent) const;
    Flags<ReportIS::StreamType> getStreams(SecurityType security_type, bool is_action_drop_or_prevent) const;
    Flags<ReportIS::Enreachments> getEnrechments(SecurityType security_type) const;

    std::string name;
    std::string verbosity;
    std::string url_for_syslog = "UDP";
    std::string url_for_cef = "UDP";
    std::string syslog_protocol = "";
    std::string cef_protocol = "";
    Flags<ReportIS::StreamType> active_streams;
    Flags<SecurityType> should_log_on_detect;
    Flags<SecurityType> should_log_on_prevent;
    Flags<SecurityType> log_geo_location;
    Flags<WebLogFields> log_web_fields;
    extendLoggingSeverity extend_logging_severity = extendLoggingSeverity::None;
    bool should_format_output = false;
};

#endif //__TRIGGERS_CONFIG_H__
