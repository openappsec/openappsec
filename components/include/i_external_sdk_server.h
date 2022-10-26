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

#ifndef __I_EXTERNAL_SDK_SERVER_H__
#define __I_EXTERNAL_SDK_SERVER_H__

#include <string>
#include <map>

#include "report/report.h"
#include "debug.h"

class I_ExternalSdkServer
{
public:
    virtual void
    sendLog(
        const std::string &event_name,
        ReportIS::Audience audience,
        ReportIS::Severity severity,
        ReportIS::Priority priority,
        const std::string &tag,
        const std::map<std::string, std::string> &additional_fields) = 0;

    virtual void
    sendDebug(
        const std::string &file_name,
        const std::string &function_name,
        unsigned int line_number,
        Debug::DebugLevel debug_level,
        const std::string &trace_id,
        const std::string &span_id,
        const std::string &message,
        const std::map<std::string, std::string> &additional_fields) = 0;

    virtual void
    sendMetric(
        const std::string &event_title,
        const std::string &service_name,
        ReportIS::AudienceTeam team,
        ReportIS::IssuingEngine issuing_engine,
        const std::map<std::string, std::string> &additional_fields) = 0;

    virtual Maybe<std::string> getConfigValue(const std::string &config_path) = 0;

protected:
    virtual ~I_ExternalSdkServer() {}
};

#endif // __I_EXTERNAL_SDK_SERVER_H__
