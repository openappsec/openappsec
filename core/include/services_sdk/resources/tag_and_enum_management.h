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

#ifndef __TAG_AND_ENUM_MANAGEMENT_H__
#define __TAG_AND_ENUM_MANAGEMENT_H__

#include <string>
#include <set>

#include "enum_array.h"
#include "report/report_enums.h"

class TagAndEnumManagement
{
public:
    static void                         print(ReportIS::Tags tag, std::ostream& os);
    static std::set<std::string>        convertToString(const std::set<ReportIS::Tags> &tags);
    static std::string                  convertToString(const ReportIS::AudienceTeam   &team);
    static std::string                  convertToString(const ReportIS::Severity       &severity);
    static std::string                  convertToString(const ReportIS::Type           &type);
    static std::string                  convertToString(const ReportIS::Level          &level);
    static std::string                  convertToString(const ReportIS::LogLevel       &log_level);
    static std::string                  convertToString(const ReportIS::Audience       &audience);
    static std::string                  convertToString(const ReportIS::Priority       &priority);
    static std::string                  convertToString(const ReportIS::StreamType     &stream_type);
    static std::string                  convertToString(const ReportIS::Notification   &notification);
    static std::string                  convertToString(const ReportIS::IssuingEngine  &issuing_engine);
    static Maybe<ReportIS::Severity>    convertStringToSeverity(const std::string &severity);
    static Maybe<ReportIS::Priority>    convertStringToPriority(const std::string &priority);
    static Maybe<ReportIS::Audience>    convertStringToAudience(const std::string &audience);
    static Maybe<ReportIS::Level>       convertStringToLevel(const std::string &level);
    static Maybe<ReportIS::LogLevel>    convertStringToLogLevel(const std::string &log_level);
    static Maybe<ReportIS::Tags>        convertStringToTag(const std::string &tag);

private:
    static EnumArray<ReportIS::Tags, std::string> tags_translation_arr;
    static EnumArray<ReportIS::AudienceTeam, std::string>  audience_team_translation;
};

#endif // __TAG_AND_ENUM_MANAGEMENT_H__
