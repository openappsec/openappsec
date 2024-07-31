#include "external_sdk_server.h"

#include "external_agent_sdk.h"
#include "log_generator.h"
#include "rest_server.h"
#include "generic_metric.h"
#include "customized_cereal_map.h"
#include "report/log_rest.h"

using namespace std;

USE_DEBUG_FLAG(D_EXTERNAL_SDK_USER);
USE_DEBUG_FLAG(D_EXTERNAL_SDK_SERVER);

class ExternalSdkRest : public ServerRest
{
public:
    void
    doCall() override
    {
        dbgFlow(D_EXTERNAL_SDK_SERVER);
        Maybe<SdkApiType> sdk_event_type = convertToEnum<SdkApiType>(event_type.get());
        if (!sdk_event_type.ok()) {
            dbgWarning(D_EXTERNAL_SDK_SERVER) << "Received illegal event type. Type : " << event_type.get();
            throw JsonError("Illegal event type provided");
        }
        dbgDebug(D_EXTERNAL_SDK_SERVER)
            << "Handling a new external sdk api call event. Type : "
            << convertApiTypeToString(sdk_event_type.unpack());

        I_ExternalSdkServer *sdk_server = Singleton::Consume<I_ExternalSdkServer>::from<ExternalSdkServer>();
        switch(sdk_event_type.unpack()) {
            case SdkApiType::SendCodeEvent: {
                if (!file.isActive()) {
                    throw JsonError("File was not provided for code event");
                }
                if (!func.isActive()) {
                    throw JsonError("Function was not provided for code event");
                }
                if (!line.isActive()) {
                    throw JsonError("Line path was not provided for code event");
                }
                if (!trace_id.isActive()) {
                    throw JsonError("Trace ID was not provided for code event");
                }
                if (!span_id.isActive()) {
                    throw JsonError("Span ID was not provided for code event");
                }
                if (!message.isActive()) {
                    throw JsonError("Message was not provided for code event");
                }
                sdk_server->sendDebug(
                    file.get(),
                    func.get(),
                    line.get(),
                    getDebugLevel(),
                    trace_id.get(),
                    span_id.get(),
                    message.get(),
                    additional_fields.isActive() ? additional_fields.get() : map<string, string>()
                );
                return;
            }
            case SdkApiType::SendEventDrivenEvent: {
                if (!event_name.isActive()) {
                    throw JsonError("Event name was not provided for event");
                }
                sdk_server->sendLog(
                    event_name.get(),
                    getAudience(),
                    getSeverity(),
                    getPriority(),
                    tag.get(),
                    additional_fields.isActive() ? additional_fields.get() : map<string, string>()
                );
                return;
            }
            case SdkApiType::SendGetConfigRequest: {
                if (!config_path.isActive()) {
                    throw JsonError("Config path was not provided for get configuration event");
                }
                Maybe<string> config_val = sdk_server->getConfigValue(config_path.get());
                config_value = config_val.ok() ? config_val.unpack() : "";
                return;
            }
            case SdkApiType::SendPeriodicEvent: {
                if (!event_name.isActive()) {
                    throw JsonError("Event name was not provided for periodic event");
                }
                if (!service_name.isActive()) {
                    throw JsonError("Service name was not provided for periodic event");
                }
                sdk_server->sendMetric(
                    event_name,
                    service_name,
                    getAudienceTeam(),
                    ReportIS::IssuingEngine::AGENT_CORE,
                    additional_fields.isActive() ? additional_fields.get() : map<string, string>()
                );
                return;
            }
            default: {
                dbgError(D_EXTERNAL_SDK_SERVER) << "Received illegal event type. Type : " << event_type.get();
            }
        }
    }

private:
    static string
    convertApiTypeToString(SdkApiType type)
    {
        static const EnumArray<SdkApiType, string> api_type_string {
            "Code Event",
            "Periodic Event",
            "Event Driven",
            "Get Configuration",
        };
        return api_type_string[type];
    }

    Debug::DebugLevel
    getDebugLevel()
    {
        static const map<int, Debug::DebugLevel> debug_levels = {
            {0, Debug::DebugLevel::TRACE},
            {1, Debug::DebugLevel::DEBUG},
            {2, Debug::DebugLevel::INFO},
            {3, Debug::DebugLevel::WARNING},
            {4, Debug::DebugLevel::ERROR}
        };
        if (!debug_level.isActive()) {
            throw JsonError("Debug level was not provided for code event");
        }
        auto level = debug_levels.find(debug_level.get());
        if(level == debug_levels.end()) {
            throw JsonError("Illegal debug level provided");
        }

        return level->second;
    }

    ReportIS::Severity
    getSeverity()
    {
        if (!severity.isActive()) {
            throw JsonError("Event severity was not provided for periodic event");
        }
        switch (severity.get()) {
            case EventSeverity::SeverityCritical: return ReportIS::Severity::CRITICAL;
            case EventSeverity::SeverityHigh: return ReportIS::Severity::HIGH;
            case EventSeverity::SeverityMedium: return ReportIS::Severity::MEDIUM;
            case EventSeverity::SeverityLow: return ReportIS::Severity::LOW;
            case EventSeverity::SeverityInfo: return ReportIS::Severity::INFO;
            default:
                throw JsonError("Illegal event severity provided");
        }
    }

    ReportIS::Priority
    getPriority()
    {
        if (!priority.isActive()) {
            throw JsonError("Event priority was not provided");
        }
        switch (priority.get()) {
            case EventPriority::PriorityUrgent: return ReportIS::Priority::URGENT;
            case EventPriority::PriorityHigh: return ReportIS::Priority::HIGH;
            case EventPriority::PriorityMedium: return ReportIS::Priority::MEDIUM;
            case EventPriority::PriorityLow: return ReportIS::Priority::LOW;
            default:
                throw JsonError("Illegal event priority provided");
        }
    }

    ReportIS::Audience
    getAudience()
    {
        if (!audience.isActive()) {
            throw JsonError("Event audience was not provided");
        }
        switch (audience.get()) {
            case EventAudience::AudienceSecurity: return ReportIS::Audience::SECURITY;
            case EventAudience::AudienceInternal: return ReportIS::Audience::INTERNAL;
            default:
                throw JsonError("Illegal event audience provided");
        }
    }

    ReportIS::AudienceTeam
    getAudienceTeam()
    {
        if (!team.isActive()) {
            throw JsonError("Event audience team was not provided");
        }
        switch (team.get()) {
            case EventAudienceTeam::AudienceTeamAgentCore: return ReportIS::AudienceTeam::AGENT_CORE;
            case EventAudienceTeam::AudienceTeamIot: return ReportIS::AudienceTeam::IOT_NEXT;
            case EventAudienceTeam::AudienceTeamWaap: return ReportIS::AudienceTeam::WAAP;
            case EventAudienceTeam::AudienceTeamAgentIntelligence: return ReportIS::AudienceTeam::AGENT_INTELLIGENCE;
            default:
                throw JsonError("Illegal event audience team provided");
        }
    }

    using additional_fields_map = map<string, string>;
    C2S_LABEL_PARAM(int, event_type, "eventType");
    C2S_LABEL_OPTIONAL_PARAM(additional_fields_map, additional_fields, "additionalFields");
    C2S_LABEL_OPTIONAL_PARAM(string, event_name, "eventName");
    C2S_LABEL_OPTIONAL_PARAM(string, service_name, "serviceName");
    C2S_OPTIONAL_PARAM(int, team);
    C2S_OPTIONAL_PARAM(int, audience);
    C2S_OPTIONAL_PARAM(int, severity);
    C2S_OPTIONAL_PARAM(int, priority);
    C2S_OPTIONAL_PARAM(string, tag);
    C2S_OPTIONAL_PARAM(string, file);
    C2S_OPTIONAL_PARAM(string, func);
    C2S_OPTIONAL_PARAM(int, line);
    C2S_LABEL_OPTIONAL_PARAM(int, debug_level, "debugLevel");
    C2S_LABEL_OPTIONAL_PARAM(string, trace_id, "traceId");
    C2S_LABEL_OPTIONAL_PARAM(string, span_id, "spanId");
    C2S_OPTIONAL_PARAM(string, message);
    C2S_LABEL_OPTIONAL_PARAM(string, config_path, "configPath");
    S2C_LABEL_OPTIONAL_PARAM(string, config_value, "configValue");
};

class ExternalSdkServer::Impl
        :
    public Singleton::Provide<I_ExternalSdkServer>::From<ExternalSdkServer>
{
public:
    void
    init()
    {
        auto rest = Singleton::Consume<I_RestApi>::by<ExternalSdkServer>();
        rest->addRestCall<ExternalSdkRest>(RestAction::ADD, "sdk-call");
    }

    void
    sendLog(
        const string &event_name,
        ReportIS::Audience audience,
        ReportIS::Severity severity,
        ReportIS::Priority priority,
        const string &tag_string,
        const map<string, string> &additional_fields)
    {
        Maybe<ReportIS::Tags> tag = TagAndEnumManagement::convertStringToTag(tag_string);
        set<ReportIS::Tags> tags;
        if (tag.ok()) tags.insert(tag.unpack());
        LogGen log(event_name, audience, severity, priority, tags);
        for (const auto &field : additional_fields) {
            log << LogField(field.first, field.second);
        }
    }

    void
    sendDebug(
        const string &file_name,
        const string &function_name,
        unsigned int line_number,
        Debug::DebugLevel debug_level,
        const string &trace_id,
        const string &span_id,
        const string &message,
        const map<string, string> &additional_fields)
    {
        (void)trace_id;
        (void)span_id;
        Debug debug(file_name, function_name, line_number, debug_level, D_EXTERNAL_SDK_USER);
        debug.getStreamAggr() << message;
        bool is_first_key = true;
        for (const auto &field : additional_fields) {
            if (is_first_key) {
                is_first_key = false;
                debug.getStreamAggr() << ". ";
            } else {
                debug.getStreamAggr() << ", ";
            }
            debug.getStreamAggr() << "\"" << field.first << "\": \"" << field.second << "\"";
        }
    }

    void
    sendMetric(
        const string &event_title,
        const string &service_name,
        ReportIS::AudienceTeam team,
        ReportIS::IssuingEngine issuing_engine,
        const map<string, string> &additional_fields)
    {
        ScopedContext ctx;
        ctx.registerValue("Service Name", service_name);

        set<ReportIS::Tags> tags;
        Report metric_to_fog(
            event_title,
            Singleton::Consume<I_TimeGet>::by<GenericMetric>()->getWalltime(),
            ReportIS::Type::PERIODIC,
            ReportIS::Level::LOG,
            ReportIS::LogLevel::INFO,
            ReportIS::Audience::INTERNAL,
            team,
            ReportIS::Severity::INFO,
            ReportIS::Priority::LOW,
            chrono::seconds(0),
            LogField("agentId", Singleton::Consume<I_AgentDetails>::by<GenericMetric>()->getAgentId()),
            tags,
            ReportIS::Tags::INFORMATIONAL,
            issuing_engine
        );

        for (const auto &field : additional_fields) {
            metric_to_fog << LogField(field.first, field.second);
        }

        LogRest metric_client_rest(metric_to_fog);

        string fog_metric_uri = getConfigurationWithDefault<string>("/api/v1/agents/events", "metric", "fogMetricUri");
        Singleton::Consume<I_Messaging>::by<ExternalSdkServer>()->sendAsyncMessage(
                HTTPMethod::POST,
                fog_metric_uri,
                metric_client_rest,
                MessageCategory::METRIC,
                MessageMetadata(),
                false
        );
    }

    Maybe<string>
    getConfigValue(const string &config_path)
    {
        auto config_val = getProfileAgentSetting<string>(config_path);
        if (!config_val.ok()) {
            stringstream error;
            error << "Failed to get configuration. Config path: " << config_path << ", Error: " << config_val.getErr();
            return genError(error.str());
        }
        return config_val.unpack();
    }
};

ExternalSdkServer::ExternalSdkServer() : Component("ExternalSdkServer"), pimpl(make_unique<Impl>()) {}
ExternalSdkServer::~ExternalSdkServer() {}

void ExternalSdkServer::init() { pimpl->init(); }
void ExternalSdkServer::fini() {}

void ExternalSdkServer::preload() {}
