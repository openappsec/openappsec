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

#include "tag_and_enum_management.h"
#include "debug.h"

using namespace std;
using namespace ReportIS;

#include <unordered_map>

Maybe<ReportIS::Severity>
TagAndEnumManagement::convertStringToSeverity(const string &severity)
{
    if (severity == "Critical") return ReportIS::Severity::CRITICAL;
    if (severity == "High") return ReportIS::Severity::HIGH;
    if (severity == "Medium") return ReportIS::Severity::MEDIUM;
    if (severity == "Low") return ReportIS::Severity::LOW;
    if (severity == "Info") return ReportIS::Severity::INFO;
    return genError("illegal severity: " + severity);
}

Maybe<ReportIS::Priority>
TagAndEnumManagement::convertStringToPriority(const string &priority)
{
    if (priority == "Urgent") return ReportIS::Priority::URGENT;
    if (priority == "High") return ReportIS::Priority::HIGH;
    if (priority == "Medium") return ReportIS::Priority::MEDIUM;
    if (priority == "Low") return ReportIS::Priority::LOW;
    return genError("illegal priority: " + priority);
}

Maybe<ReportIS::Audience>
TagAndEnumManagement::convertStringToAudience(const string &audience)
{
    if (audience == "Security") return ReportIS::Audience::SECURITY;
    if (audience == "Internal") return ReportIS::Audience::INTERNAL;
    return genError("illegal audience: " + audience);
}

Maybe<ReportIS::Level>
TagAndEnumManagement::convertStringToLevel(const string &level)
{
    if (level == "Action Item") return ReportIS::Level::ACTION;
    if (level == "Custom") return ReportIS::Level::CUSTOM;
    if (level == "Incident") return ReportIS::Level::INCIDENT;
    if (level == "Insight") return ReportIS::Level::INSIGHT;
    if (level == "Log") return ReportIS::Level::LOG;
    return genError("illegal level: " + level);
}

Maybe<ReportIS::LogLevel>
TagAndEnumManagement::convertStringToLogLevel(const string &log_level)
{
    if (log_level == "Trace") return ReportIS::LogLevel::TRACE;
    if (log_level == "Debug") return ReportIS::LogLevel::DEBUG;
    if (log_level == "Info") return ReportIS::LogLevel::INFO;
    if (log_level == "Warning") return ReportIS::LogLevel::WARNING;
    if (log_level == "Error") return ReportIS::LogLevel::ERROR;
    return genError("illegal log level: " + log_level);
}

Maybe<ReportIS::Tags>
TagAndEnumManagement::convertStringToTag(const string &tag)
{
    static const unordered_map<string, ReportIS::Tags> strings_to_tags = {
        {"Threat Prevention", ReportIS::Tags::THREAT_PREVENTION},
        {"Remote Code Execution", ReportIS::Tags::REMOTE_CODE_EXECUTION},
        {"Elevation Of Privileges", ReportIS::Tags::ELEVATION_OF_PRIVILEGES},
        {"New Connection", ReportIS::Tags::NEW_CONNECTION},
        {"Policy Installation", ReportIS::Tags::POLICY_INSTALLATION},
        {"Access Control", ReportIS::Tags::ACCESS_CONTROL},
        {"Data Leak", ReportIS::Tags::DATA_LEAK},
        {"New Approve Transaction", ReportIS::Tags::NEW_APPROVE_TRANSACTION},
        {"Firewall Information", ReportIS::Tags::FW},
        {"Web Application & API Protection", ReportIS::Tags::WAF},
        {"IPS", ReportIS::Tags::IPS},
        {"URL Filtering", ReportIS::Tags::URLF},
        {"Informational", ReportIS::Tags::INFORMATIONAL},
        {"Orchestration", ReportIS::Tags::ORCHESTRATOR},
        {"Compliance", ReportIS::Tags::COMPLIANCE},
        {"IoT", ReportIS::Tags::IOT},
        {"SDWAN", ReportIS::Tags::SDWAN},
        {"CP_SDWAN", ReportIS::Tags::CP_SDWAN},
        {"SDWAN_DATA_SHARING", ReportIS::Tags::SDWAN_DATA_SHARING},
        {"SDWAN_POLICY_ERROR", ReportIS::Tags::SDWAN_POLICY_ERROR},
        {"CPView Monitoring", ReportIS::Tags::CPVIEW_METRICS},
        {"Reverse Proxy", ReportIS::Tags::REVERSE_PROXY},
        {"Http Geo Filter", ReportIS::Tags::HTTP_GEO_FILTER},
        {"File Upload", ReportIS::Tags::FILE_UPLOAD},
        {"Identity Awareness", ReportIS::Tags::IDENTITY_AWARENESS},
        {"Rate Limit", ReportIS::Tags::RATE_LIMIT},
        {"NGINX Server", ReportIS::Tags::WEB_SERVER_NGINX},
        {"Kong Server", ReportIS::Tags::WEB_SERVER_KONG},
        {"Embedded Deployment", ReportIS::Tags::DEPLOYMENT_EMBEDDED},
        {"Kubernetes Deployment", ReportIS::Tags::DEPLOYMENT_K8S},
        {"Layer 7 Access Control", ReportIS::Tags::LAYER_7_ACCESS_CONTROL},
        {"Horizon Telemetry Metrics", ReportIS::Tags::HORIZON_TELEMETRY_METRICS},
        {"Crowdsec", ReportIS::Tags::CROWDSEC},
        {"apiDiscoveryCloudMessaging", ReportIS::Tags::API_DISCOVERY},
        {"Playground", ReportIS::Tags::PLAYGROUND},
        {"Nginx Proxy Manager", ReportIS::Tags::NGINX_PROXY_MANAGER},
        {"APISIX Server", ReportIS::Tags::WEB_SERVER_APISIX}
    };
    
    auto report_is_tag = strings_to_tags.find(tag);
    if (report_is_tag != strings_to_tags.end()) return report_is_tag->second;
    return genError("illegal tag: " + tag);
}

void
TagAndEnumManagement::print(Tags tag, ostream& os)
{
    os << tags_translation_arr[tag];
}

set<string>
TagAndEnumManagement::convertToString(const set<Tags> &tags)
{
    set<string> result;
    for (auto &tag : tags) {
        result.insert(tags_translation_arr[tag]);
    }
    return result;
}

string
TagAndEnumManagement::convertToString(const AudienceTeam &audience_team)
{
    return audience_team_translation[audience_team];
}

string
TagAndEnumManagement::convertToString(const StreamType &stream_type)
{
    switch (stream_type) {
        case StreamType::JSON_DEBUG:    return "JSON Debug stream";
        case StreamType::JSON_FOG:      return "JSON FOG stream";
        case StreamType::JSON_LOG_FILE: return "JSON File stream";
        case StreamType::JSON_K8S_SVC:  return "JSON K8S service stream";
        case StreamType::SYSLOG:        return "Syslog stream";
        case StreamType::CEF:           return "CEF stream";

        case StreamType::NONE: break;
        case StreamType::COUNT: break;
    }

    dbgAssert(false) << "Unknown log stream type. Type: " << static_cast<int>(stream_type);
    return "";
}

string
TagAndEnumManagement::convertToString(const Severity &severity)
{
    switch (severity) {
        case Severity::CRITICAL: return "Critical";
        case Severity::HIGH:     return "High";
        case Severity::MEDIUM:   return "Medium";
        case Severity::LOW:      return "Low";
        case Severity::INFO:     return "Info";
    }

    dbgAssert(false) << "Reached an impossible severity value of: " << static_cast<int>(severity);
    return "";
}

string
TagAndEnumManagement::convertToString(const Type &type)
{
    switch (type) {
        case Type::EVENT:    return "Event Driven";
        case Type::PERIODIC: return "Periodic";
        case Type::CODE:     return "Code Related";
    }

    dbgAssert(false) << "Reached an impossible type value of: " << static_cast<int>(type);
    return "";
}

string
TagAndEnumManagement::convertToString(const Level &level)
{
    switch (level) {
        case Level::LOG:      return "Log";
        case Level::INCIDENT: return "Incident";
        case Level::INSIGHT:  return "Insight";
        case Level::ACTION:   return "Action Item";
        case Level::CUSTOM:   return "Custom";
    }

    dbgAssert(false) << "Reached an impossible type value of: " << static_cast<int>(level);
    return "";
}

string
TagAndEnumManagement::convertToString(const LogLevel &log_level)
{
    switch (log_level) {
        case LogLevel::TRACE:   return "trace";
        case LogLevel::DEBUG:   return "debug";
        case LogLevel::INFO:    return "info";
        case LogLevel::WARNING: return "warning";
        case LogLevel::ERROR:   return "error";
    }

    dbgAssert(false) << "Reached an impossible type value of: " << static_cast<int>(log_level);
    return "";
}

string
TagAndEnumManagement::convertToString(const Audience &audience)
{
    switch (audience) {
        case Audience::SECURITY: return "Security";
        case Audience::INTERNAL: return "Internal";
    }

    dbgAssert(false) << "Reached an impossible audience value of: " << static_cast<int>(audience);
    return "";
}

string
TagAndEnumManagement::convertToString(const Priority &priority)
{
    switch (priority) {
        case Priority::URGENT: return "Urgent";
        case Priority::HIGH:   return "High";
        case Priority::MEDIUM: return "Medium";
        case Priority::LOW:    return "Low";
    }

    dbgAssert(false) << "Reached impossible priority value of: " << static_cast<int>(priority);
    return "";
}

string
TagAndEnumManagement::convertToString(const Notification &notification)
{
    switch (notification) {
        case Notification::POLICY_UPDATE: return "c0516360-a0b1-4246-af4c-2b6c586958e0";
        case Notification::FIRST_REQUEST_FOR_ASSET: return "a53a7091-5d7a-4881-9e64-0fa3a1fc5a93";
        case Notification::UPSTREAM_STATUS: return "46e5af4e-db29-444a-8f6b-2a6bd8f2e131";
        case Notification::SYNC_LEARNING: return "b9b9ab04-2e2a-4cd1-b7e5-2c956861fb69";
        case Notification::SDWAN_POLICY_UPDATE: return "2b18f5a0-5503-4c6b-967f-aa71dbced1aa";
        case Notification::SDWAN_POLICY_UPDATE_ERROR: return "8d2db6ea-30b7-11ec-8d3d-0242ac130003";
        case Notification::SDWAN_POLICY_UPDATE_LOG: return "97cb79e1-e873-4f28-b123-5e19f8dd6f99";
        case Notification::SDWAN_POLICY_UPDATE_ERROR_LOG: return "44ca5755-07a2-483c-b756-b7df444e175c";
        case Notification::SDWAN_POLICY_WARNING_LOG: return "c58d490e-6aa0-43da-bfaa-7edad0a57b7a";
    }

    dbgAssert(false) << "Reached impossible notification value of: " << static_cast<int>(notification);
    return "";
}

string
TagAndEnumManagement::convertToString(const IssuingEngine &issuing_engine)
{
    switch (issuing_engine) {
        case IssuingEngine::AGENT_CORE: return "Agent Core";
        case IssuingEngine::IOT_NEXT: return "iotNext";
        case IssuingEngine::SDWAN: return "sdwanGwSharing";
        case IssuingEngine::FILE_UPLOAD: return "fileUpload";
        case IssuingEngine::IDA_NEXT_BLADE_REGISTRATION: return "quantumMetaNotifyIdn";
        case IssuingEngine::IDA_NEXT_CLIENT_IP_NOTIFY: return "quantumIPNotifyIdn";
        case IssuingEngine::API_DISCOVERY: return "apiDiscoveryCloudMessaging";
        case IssuingEngine::HORIZON_TELEMETRY_METRICS: return "horizonTelemetryMetrics";
    }

    dbgAssert(false) << "Reached impossible engine value of: " << static_cast<int>(issuing_engine);
    return "";
}


EnumArray<Tags, string> TagAndEnumManagement::tags_translation_arr {
    "Threat Prevention",
    "Remote Code Execution",
    "Elevation Of Privileges",
    "New Connection",
    "Policy Installation",
    "Access Control",
    "Data Leak",
    "New Approve Transaction",
    "Firewall Information",
    "Web Application & API Protection",
    "IPS",
    "URL Filtering",
    "Informational",
    "Orchestration",
    "Compliance",
    "IoT",
    "SDWAN",
    "CP_SDWAN",
    "SDWAN_DATA_SHARING",
    "SDWAN_POLICY_ERROR",
    "CPView Monitoring",
    "Reverse Proxy",
    "Http Geo Filter",
    "File Upload",
    "Identity Awareness",
    "Rate Limit",
    "NGINX Server",
    "Kong Server",
    "Embedded Deployment",
    "Kubernetes Deployment",
    "Layer 7 Access Control",
    "Horizon Telemetry Metrics",
    "Crowdsec",
    "Playground",
    "apiDiscoveryCloudMessaging",
    "Nginx Proxy Manager",
    "APISIX Server"
};

EnumArray<AudienceTeam, string> TagAndEnumManagement::audience_team_translation {
    "Agent Core",
    "iotNext",
    "WAAP",
    "Agent Intelligence",
    "cpviewMonitoring",
    "Signature Developers",
    "Identity Awareness",
    "unifiedMonitoring"
};
