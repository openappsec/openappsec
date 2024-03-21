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

#include <string>
#include <map>

#include "generic_rulebase/triggers_config.h"
#include "generic_rulebase/generic_rulebase_utils.h"

USE_DEBUG_FLAG(D_RULEBASE_CONFIG);

using namespace std;

WebTriggerConf::WebTriggerConf() :  response_title(""), response_body(""), response_code(0) {}
WebTriggerConf::WebTriggerConf(const string &title, const string &body, uint code)
        :
    response_title(title),
    response_body(body),
    response_code(code)
{}

WebTriggerConf WebTriggerConf::default_trigger_conf = WebTriggerConf(
    "Attack blocked by web application protection",                                     // title
    "Check Point's <b>Application Security</b> has detected an attack and blocked it.", // body
    403
);

void
WebTriggerConf::load(cereal::JSONInputArchive &archive_in)
{
    try {
        parseJSONKey<string>("details level", details_level, archive_in);
        if (details_level == "Redirect") {
            parseJSONKey<string>("redirect URL", redirect_url, archive_in);
            parseJSONKey<bool>("xEventId", add_event_id_to_header, archive_in);
            parseJSONKey<bool>("eventIdInHeader", add_event_id_to_header, archive_in);
            return;
        }
        parseJSONKey<uint>("response code", response_code, archive_in);
        if (response_code < 100 || response_code > 599) {
            throw cereal::Exception(
                "illegal web trigger response code: " +
                to_string(response_code) +
                " is out of range (100-599)"
            );
        }

        if (details_level == "Response Code") return;

        parseJSONKey<string>("response body", response_body, archive_in);
        parseJSONKey<string>("response title", response_title, archive_in);
    } catch (const exception &e) {
        dbgWarning(D_RULEBASE_CONFIG) << "Failed to parse the web trigger configuration: '" << e.what() << "'";
        archive_in.setNextName(nullptr);
    }
}

bool
WebTriggerConf::operator==(const WebTriggerConf &other) const
{
    return
        response_code == other.response_code &&
        response_title == other.response_title &&
        response_body == other.response_body;
}

LogTriggerConf::LogTriggerConf(string trigger_name, bool log_detect, bool log_prevent) : name(trigger_name)
{
    if (log_detect) should_log_on_detect.setAll();
    if (log_prevent) should_log_on_prevent.setAll();
    active_streams.setFlag(ReportIS::StreamType::JSON_FOG);
    active_streams.setFlag(ReportIS::StreamType::JSON_LOG_FILE);
}

ReportIS::Severity
LogTriggerConf::getSeverity(bool is_action_drop_or_prevent) const
{
    return is_action_drop_or_prevent ? ReportIS::Severity::MEDIUM : ReportIS::Severity::LOW;
}

ReportIS::Priority
LogTriggerConf::getPriority(bool is_action_drop_or_prevent) const
{
    return is_action_drop_or_prevent ? ReportIS::Priority::HIGH : ReportIS::Priority::MEDIUM;
}

Flags<ReportIS::StreamType>
LogTriggerConf::getStreams(SecurityType security_type, bool is_action_drop_or_prevent) const
{
    if (is_action_drop_or_prevent && should_log_on_prevent.isSet(security_type)) return active_streams;
    if (!is_action_drop_or_prevent && should_log_on_detect.isSet(security_type)) return active_streams;

    return Flags<ReportIS::StreamType>();
}

Flags<ReportIS::Enreachments>
LogTriggerConf::getEnrechments(SecurityType security_type) const
{
    Flags<ReportIS::Enreachments> enreachments;

    if (log_geo_location.isSet(security_type)) enreachments.setFlag(ReportIS::Enreachments::GEOLOCATION);
    if (should_format_output) enreachments.setFlag(ReportIS::Enreachments::BEAUTIFY_OUTPUT);

    return enreachments;
}

template <typename EnumClass>
static void
setTriggersFlag(const string &key, cereal::JSONInputArchive &ar, EnumClass flag, Flags<EnumClass> &flags)
{
    bool value = false;
    parseJSONKey<bool>(key, value, ar);
    if (value) flags.setFlag(flag);
}

static void
setLogConfiguration(
    const ReportIS::StreamType &log_type,
    const string &log_server_url = "",
    const string &protocol = ""
)
{
    dbgTrace(D_RULEBASE_CONFIG) << "log server url:" << log_server_url;
    if (log_server_url != "" && protocol != "") {
        Singleton::Consume<I_Logging>::by<LogTriggerConf>()->addStream(log_type, log_server_url, protocol);
    } else {
        Singleton::Consume<I_Logging>::by<LogTriggerConf>()->addStream(log_type);
    }
}

static string
parseProtocolWithDefault(
    const std::string &default_value,
    const std::string &key_name,
    cereal::JSONInputArchive &archive_in
)
{
    string value;
    try {
        archive_in(cereal::make_nvp(key_name, value));
    } catch (const cereal::Exception &e) {
        return default_value;
    }
    return value;
}

void
LogTriggerConf::load(cereal::JSONInputArchive& archive_in)
{
    try {
        parseJSONKey<string>("triggerName", name, archive_in);
        parseJSONKey<string>("verbosity", verbosity, archive_in);
        parseJSONKey<string>("urlForSyslog", url_for_syslog, archive_in);
        parseJSONKey<string>("urlForCef", url_for_cef, archive_in);
        parseJSONKey<string>("syslogProtocol", syslog_protocol, archive_in);
        syslog_protocol = parseProtocolWithDefault("UDP", "syslogProtocol", archive_in);
        cef_protocol = parseProtocolWithDefault("UDP", "cefProtocol", archive_in);

        setTriggersFlag("webBody",  archive_in, WebLogFields::webBody, log_web_fields);
        setTriggersFlag("webHeaders", archive_in, WebLogFields::webHeaders, log_web_fields);
        setTriggersFlag("webRequests", archive_in, WebLogFields::webRequests, log_web_fields);
        setTriggersFlag("webUrlPath", archive_in, WebLogFields::webUrlPath, log_web_fields);
        setTriggersFlag("webUrlQuery", archive_in, WebLogFields::webUrlQuery, log_web_fields);
        setTriggersFlag("logToAgent", archive_in, ReportIS::StreamType::JSON_LOG_FILE, active_streams);
        setTriggersFlag("logToCloud", archive_in, ReportIS::StreamType::JSON_FOG, active_streams);
        setTriggersFlag("logToK8sService", archive_in, ReportIS::StreamType::JSON_K8S_SVC, active_streams);
        setTriggersFlag("logToSyslog", archive_in, ReportIS::StreamType::SYSLOG, active_streams);
        setTriggersFlag("logToCef", archive_in, ReportIS::StreamType::CEF, active_streams);
        setTriggersFlag("acAllow", archive_in, SecurityType::AccessControl, should_log_on_detect);
        setTriggersFlag("acDrop", archive_in, SecurityType::AccessControl, should_log_on_prevent);
        setTriggersFlag("tpDetect", archive_in, SecurityType::ThreatPrevention, should_log_on_detect);
        setTriggersFlag("tpPrevent", archive_in, SecurityType::ThreatPrevention, should_log_on_prevent);
        setTriggersFlag("complianceWarnings", archive_in, SecurityType::Compliance, should_log_on_detect);
        setTriggersFlag("complianceViolations", archive_in, SecurityType::Compliance, should_log_on_prevent);
        setTriggersFlag("acLogGeoLocation", archive_in, SecurityType::AccessControl, log_geo_location);
        setTriggersFlag("tpLogGeoLocation", archive_in, SecurityType::ThreatPrevention, log_geo_location);
        setTriggersFlag("complianceLogGeoLocation", archive_in, SecurityType::Compliance, log_geo_location);

        bool extend_logging = false;
        parseJSONKey<bool>("extendLogging", extend_logging, archive_in);
        if (extend_logging) {
            setTriggersFlag("responseCode", archive_in, WebLogFields::responseCode, log_web_fields);
            setTriggersFlag("responseBody", archive_in, WebLogFields::responseBody, log_web_fields);

            string severity;
            static const map<string, extendLoggingSeverity> extend_logging_severity_strings = {
                {"High", extendLoggingSeverity::High},
                {"Critical", extendLoggingSeverity::Critical}
            };
            parseJSONKey<string>("extendLoggingMinSeverity", severity, archive_in);
            auto extended_severity = extend_logging_severity_strings.find(severity);
            if (extended_severity != extend_logging_severity_strings.end()) {
                extend_logging_severity = extended_severity->second;
            } else {
                dbgWarning(D_RULEBASE_CONFIG)
                    << "Failed to parse the extendLoggingMinSeverityfield: '"
                    << severity
                    << "'";
            }
        }

        for (ReportIS::StreamType log_stream : makeRange<ReportIS::StreamType>()) {
            if (!active_streams.isSet(log_stream)) continue;
            switch (log_stream) {
                case ReportIS::StreamType::JSON_DEBUG:
                    setLogConfiguration(ReportIS::StreamType::JSON_DEBUG);
                    break;
                case ReportIS::StreamType::JSON_FOG:
                    setLogConfiguration(ReportIS::StreamType::JSON_FOG);
                    break;
                case ReportIS::StreamType::JSON_LOG_FILE:
                    setLogConfiguration(ReportIS::StreamType::JSON_LOG_FILE);
                    break;
                case ReportIS::StreamType::JSON_K8S_SVC:
                    setLogConfiguration(ReportIS::StreamType::JSON_K8S_SVC);
                    break;
                case ReportIS::StreamType::SYSLOG:
                    setLogConfiguration(ReportIS::StreamType::SYSLOG, getUrlForSyslog(), syslog_protocol);
                    break;
                case ReportIS::StreamType::CEF:
                    setLogConfiguration(ReportIS::StreamType::CEF, getUrlForCef(), cef_protocol);
                    break;
                case ReportIS::StreamType::NONE: break;
                case ReportIS::StreamType::COUNT: break;
            }
        }

        parseJSONKey<bool>("formatLoggingOutput", should_format_output, archive_in);
    } catch (const exception &e) {
        dbgWarning(D_RULEBASE_CONFIG) << "Failed to parse the log trigger configuration: '" << e.what() << "'";
        archive_in.setNextName(nullptr);
    }
}
