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

#ifndef __REPORT_H__
#define __REPORT_H__

#include <set>
#include <chrono>

#include "report/base_field.h"
#include "report/report_enums.h"
#include "i_time_get.h"
#include "i_environment.h"
#include "i_agent_details.h"
#include "i_instance_awareness.h"
#include "flags.h"
#include "singleton.h"
#include "tag_and_enum_management.h"

class Report
        :
    Singleton::Consume<I_TimeGet>,
    Singleton::Consume<I_Environment>,
    Singleton::Consume<I_AgentDetails>,
    Singleton::Consume<I_InstanceAwareness>
{
public:
    Report() = default;

    template <typename ...Args>
    Report(
        const std::string &_title,
        std::chrono::microseconds _time,
        const ReportIS::Type &_type,
        const ReportIS::Level &_level,
        const ReportIS::LogLevel &_log_level,
        const ReportIS::Audience &_audience,
        const ReportIS::AudienceTeam &_audience_team,
        const ReportIS::Severity &_severity,
        const ReportIS::Priority &_priority,
        const std::chrono::seconds _frequency,
        Args ...args)
            :
        title(_title),
        time(_time),
        type(_type),
        level(_level),
        log_level(_log_level),
        audience(_audience),
        audience_team(_audience_team),
        severity(_severity),
        priority(_priority),
        frequency(_frequency.count())
    {
        readFirstSource(args...);
        setTenantID();
        setTraceID();
        setSpanID();
        setEngineVersion();
        setServiceName();
        setInstanceAwareness();
    }

    void serialize(cereal::JSONOutputArchive &ar) const;
    std::string getSyslog() const;
    std::string getCef() const;

    template <typename ErrorType>
    Report & operator<<(const Maybe<LogField, ErrorType> &log) { return log.ok() ? (*this << *log) : *this; }
    Report & operator<<(const LogField &log);
    void addToOrigin(const LogField &log);

    void setIndex(size_t index) { reportIndex = index;}
    bool isStreamActive(const ReportIS::StreamType stream_type) const { return stream_types.isSet(stream_type); }
    bool isEnreachmentActive(const ReportIS::Enreachments type) const { return enreachments.isSet(type); }

    std::map<std::string, std::string> & getMarkers() { return markers; }
    const std::map<std::string, std::string> & getMarkers() const { return markers; }

    template <typename ... Strings>
    Maybe<std::string, void> getStringData(const Strings & ... path) const { return event_data.getString(path ...); }

private:
    std::string title;
    std::chrono::microseconds time;
    ReportIS::Type type;
    ReportIS::Level level;
    ReportIS::LogLevel log_level;
    ReportIS::Audience audience;
    ReportIS::AudienceTeam audience_team;
    ReportIS::Severity severity;
    ReportIS::Priority priority;
    uint frequency;
    LogField origin{"eventSource"};
    LogField event_data{"eventData"};
    std::set<ReportIS::Tags> tags;
    Flags<ReportIS::StreamType> stream_types;
    Flags<ReportIS::Enreachments> enreachments;
    size_t reportIndex;
    std::map<std::string, std::string> markers;

    void setTenantID();
    void setTraceID();
    void setSpanID();
    void setEngineVersion();
    void setServiceName();
    void setInstanceAwareness();

    template <typename ...Args>
    void
    readFirstSource(const LogField &f, Args ...args)
    {
        origin.addFields(f);
        readNextSource(args...);
    }

    template <typename ...Args>
    void
    readFirstSource(const ReportIS::Tags &tag, Args ...args)
    {
        readNextTag(tag, args...);
    }

    template <typename ...Args>
    void
    readNextSource(const LogField &f, Args ...args)
    {
        origin.addFields(f);
        readNextSource(args...);
    }

    template <typename ...Args>
    void
    readNextSource(const ReportIS::Tags &tag, Args ...args)
    {
        readNextTag(tag, args...);
    }

    template <typename ...Args>
    void
    readNextSource(const std::set<ReportIS::Tags> &more_tags, Args ...args)
    {
        readNextTag(more_tags, args...);
    }

    template <typename ...Args>
    void
    readNextTag(const ReportIS::Tags &tag, Args ...args)
    {
        tags.insert(tag);
        readNextTag(args...);
    }

    template <typename ...Args>
    void
    readNextTag(const std::set<ReportIS::Tags> &more_tags, Args ...args)
    {
        tags.insert(more_tags.begin(), more_tags.end());
        readNextTag(args...);
    }

    template <typename ...Args>
    void
    readNextTag(const std::set<ReportIS::Tags> &more_tags)
    {
        tags.insert(more_tags.begin(), more_tags.end());
        stream_types.setAll();
    }

    void
    readNextTag(const ReportIS::Tags &tag)
    {
        tags.insert(tag);
        stream_types.setAll();
    }

    template <typename ...Args>
    void
    readNextTag(const ReportIS::Tags &tag, const ReportIS::Notification &_notification, Args ...args)
    {
        tags.insert(tag);
        readNextNotification(_notification, args...);
    }

    template <typename ...Args>
    void
    readNextTag(const ReportIS::Tags &tag, const ReportIS::IssuingEngine &_issuing_engine, Args ...args)
    {
        tags.insert(tag);
        readNextEngineName(_issuing_engine, args...);
    }

    template <typename ...Args>
    void
    readNextTag(const ReportIS::Tags &tag, const ReportIS::StreamType &stream, Args ...args)
    {
        tags.insert(tag);
        readNextStream(stream, args...);
    }

    template <typename ...Args>
    void
    readNextTag(const ReportIS::Tags &tag, const Flags<ReportIS::StreamType> &streams, Args ...args)
    {
        tags.insert(tag);
        readNextStream(streams, args...);
    }

    template <typename ...Args>
    void
    readNextTag(const ReportIS::Tags &tag, const ReportIS::Enreachments &enreachment, Args ...args)
    {
        tags.insert(tag);
        stream_types.setAll();
        readNextEnreachment(enreachment, args...);
    }

    template <typename ...Args>
    void
    readNextTag(const Flags<ReportIS::Enreachments> &enreachments, Args ...args)
    {
        stream_types.setAll();
        readNextEnreachment(enreachments, args...);
    }

    template <typename ...Args>
    void
    readNextNotification(
        const ReportIS::Notification &_notification,
        const ReportIS::IssuingEngine &issuing_engine,
        Args ...args
    ) {
        event_data.addFields(LogField("notificationId", TagAndEnumManagement::convertToString(_notification)));
        readNextEngineName(issuing_engine, args...);
    }

    template <typename ...Args>
    void
    readNextNotification(
        const ReportIS::Notification &_notification,
        const ReportIS::StreamType &stream,
        Args ...args
    ) {
        event_data.addFields(LogField("notificationId", TagAndEnumManagement::convertToString(_notification)));
        readNextStream(stream, args...);
    }

    template <typename ...Args>
    void
    readNextNotification(
        const ReportIS::Notification &_notification,
        const Flags<ReportIS::StreamType> &streams,
        Args ...args
    ) {
        event_data.addFields(LogField("notificationId", TagAndEnumManagement::convertToString(_notification)));
        readNextStream(streams, args...);
    }

    template <typename ...Args>
    void
    readNextNotification(
        const ReportIS::Notification &_notification,
        const ReportIS::Enreachments &enreachment,
        Args ...args
    ) {
        stream_types.setAll();
        event_data.addFields(LogField("notificationId", TagAndEnumManagement::convertToString(_notification)));
        readNextEnreachment(enreachment, args...);
    }

    template <typename ...Args>
    void
    readNextNotification(
        const ReportIS::Notification &_notification,
        const Flags<ReportIS::Enreachments> &enreachment,
        Args ...args
    ) {
        stream_types.setAll();
        event_data.addFields(LogField("notificationId", TagAndEnumManagement::convertToString(_notification)));
        readNextEnreachment(enreachment, args...);
    }

    template <typename ...Args>
    void
    readNextNotification(const ReportIS::Notification &_notification)
    {
        stream_types.setAll();
        event_data.addFields(LogField("notificationId", TagAndEnumManagement::convertToString(_notification)));
    }

    template <typename ...Args>
    void
    readNextEngineName(
        const ReportIS::IssuingEngine &_issuing_engine,
        const ReportIS::StreamType &stream,
        Args ...args
    ) {
        origin.addFields(LogField("issuingEngine", TagAndEnumManagement::convertToString(_issuing_engine)));
        readNextStream(stream, args...);
    }

    template <typename ...Args>
    void
    readNextEngineName(
        const ReportIS::IssuingEngine &_issuing_engine,
        const Flags<ReportIS::StreamType> &streams,
        Args ...args
    ) {
        origin.addFields(LogField("issuingEngine", TagAndEnumManagement::convertToString(_issuing_engine)));
        readNextStream(streams, args...);
    }

    template <typename ...Args>
    void
    readNextEngineName(
        const ReportIS::IssuingEngine &_issuing_engine,
        const ReportIS::Enreachments &enreachment,
        Args ...args
    ) {
        stream_types.setAll();
        origin.addFields(LogField("issuingEngine", TagAndEnumManagement::convertToString(_issuing_engine)));
        readNextEnreachment(enreachment, args...);
    }

    template <typename ...Args>
    void
    readNextEngineName(
        const ReportIS::IssuingEngine &_issuing_engine,
        const Flags<ReportIS::Enreachments> &enreachment,
        Args ...args
    ) {
        stream_types.setAll();
        origin.addFields(LogField("issuingEngine", TagAndEnumManagement::convertToString(_issuing_engine)));
        readNextEnreachment(enreachment, args...);
    }

    template <typename ...Args>
    void
    readNextEngineName(const ReportIS::IssuingEngine &_issuing_engine)
    {
        stream_types.setAll();
        origin.addFields(LogField("issuingEngine", TagAndEnumManagement::convertToString(_issuing_engine)));
    }

    template <typename ...Args>
    void
    readNextStream(const ReportIS::StreamType &stream, Args ...args)
    {
        stream_types.setFlag(stream);
        readNextStream(args...);
    }

    template <typename ...Args>
    void
    readNextStream(const Flags<ReportIS::StreamType> &streams, Args ...args)
    {
        stream_types = streams;
        readNextStream(args...);
    }

    void readNextStream() {}

    template <typename ...Args>
    void
    readNextStream(const ReportIS::Enreachments &enreachment, Args ...args)
    {
        readNextEnreachment(enreachment, args...);
    }

    template <typename ...Args>
    void
    readNextStream(const Flags<ReportIS::Enreachments> &enreachments, Args ...args)
    {
        readNextEnreachment(enreachments, args...);
    }

    template <typename ...Args>
    void
    readNextEnreachment(const ReportIS::Enreachments &enreachment, Args ...args)
    {
        enreachments.setFlag(enreachment);
        readNextEnreachment(args...);
    }

    template <typename ...Args>
    void
    readNextEnreachment(const Flags<ReportIS::Enreachments> &more_enreachments, Args ...args)
    {
        enreachments = more_enreachments;
        readNextEnreachment(args...);
    }

    void readNextEnreachment() {}
};

#endif // __REPORT_H__
