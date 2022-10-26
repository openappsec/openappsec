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

#ifndef __REPORT_ENUMS_H__
#define __REPORT_ENUMS_H__

namespace ReportIS
{

enum class StreamType {
    NONE,

    JSON_DEBUG,
    JSON_FOG,
    JSON_LOG_FILE,
    SYSLOG,
    CEF,

    COUNT
};

enum class Tags {
    THREAT_PREVENTION,
    REMOTE_CODE_EXECUTION,
    ELEVATION_OF_PRIVILEGES,
    NEW_CONNECTION,
    POLICY_INSTALLATION,
    ACCESS_CONTROL,
    DATA_LEAK,
    NEW_APPROVE_TRANSACTION,
    FW,
    WAF,
    IPS,
    URLF,
    INFORMATIONAL,
    ORCHESTRATOR,
    COMPLIANCE,
    IOT,
    SDWAN,
    CP_SDWAN,
    SDWAN_DATA_SHARING,
    SDWAN_POLICY_ERROR,
    CPVIEW_METRICS,
    REVERSE_PROXY,
    HTTP_GEO_FILTER,
    FILE_UPLOAD,

    COUNT
};

enum class AudienceTeam
{
    AGENT_CORE,
    IOT_NEXT,
    WAAP,
    AGENT_INTELLIGENCE,
    CPVIEW_MONITORING,
    SIGNATURE_DEVELOPERS,
    NONE,

    COUNT
};

enum class Enreachments {
    NONE,
    GEOLOCATION,
    BEAUTIFY_OUTPUT,

    COUNT
};

enum class Severity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO
};

enum class Type {
    EVENT,
    PERIODIC,
    CODE
};

enum class Level {
    LOG,
    INCIDENT,
    INSIGHT,
    ACTION,
    CUSTOM
};

enum class LogLevel {
    TRACE,
    DEBUG,
    INFO,
    WARNING,
    ERROR
};

enum class Audience {
    SECURITY,
    INTERNAL
};

enum class Priority {
    URGENT,
    HIGH,
    MEDIUM,
    LOW
};

enum class Notification {
    POLICY_UPDATE,
    FIRST_REQUEST_FOR_ASSET,
    UPSTREAM_STATUS,
    IOT_POLICY_UPDATE,
    SYNC_LEARNING,
    SDWAN_POLICY_UPDATE,
    SDWAN_POLICY_UPDATE_ERROR,
    SDWAN_POLICY_UPDATE_LOG,
    SDWAN_POLICY_UPDATE_ERROR_LOG
};

enum class IssuingEngine {
    AGENT_CORE,
    IOT_NEXT,
    SDWAN
};

} // namespace ReportIS

#endif // __REPORT_ENUMS_H___
