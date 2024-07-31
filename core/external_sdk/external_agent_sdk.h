#ifndef __EXTERNAL_AGENT_SDK_H__
#define __EXTERNAL_AGENT_SDK_H__

#ifdef __cplusplus
enum class SdkApiType
#else
enum SdkApiType
#endif
{
    SendCodeEvent,
    SendPeriodicEvent,
    SendEventDrivenEvent,
    SendGetConfigRequest,

#ifndef __cplusplus
};
#else //__cplusplus
    COUNT
};

extern "C"
{
#endif // __cplusplus

enum DebugLevel { DebugTrace, DebugDebug, DebugInfo, DebugWarning, DebugError };
enum EventAudience { AudienceSecurity, AudienceInternal };
enum EventAudienceTeam { AudienceTeamAgentCore, AudienceTeamIot, AudienceTeamWaap, AudienceTeamAgentIntelligence };
enum EventSeverity { SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo };
enum EventPriority { PriorityUrgent, PriorityHigh, PriorityMedium, PriorityLow };

enum SdkReturn {
    SdkSuccess = 0,
    SdkUninitialized = -1,
    IlegalNumOfAdditionData = -2,
    EmptyConfigRespond = -3,
    InitCurlFailed = -4,
    ExecuteCurlFailed = -5,
    Non200Respond = -6,
    AllocationFailure = -7
};

void initAgentSdk();
void finiAgentSdk();

// Get configuration using path. Output is allocated internally and requires caller to free
enum SdkReturn getAgentConfiguration(const char *configuration_path, char **config_value_output);

enum SdkReturn
sendPeriodicData(
    const char *event_title,
    const char *service_name,
    enum EventAudienceTeam team,
    const char **periodic_data,
    int periodic_data_size
);

enum SdkReturn
sendEventDrivenLog(
    const char *event_name,
    enum EventAudience audience,
    enum EventSeverity severity,
    enum EventPriority priority,
    const char *tag,
    enum EventAudienceTeam team,
    const char **event_data,
    int event_data_size
);

enum SdkReturn
sendDebugMessage(
    const char *file_name,
    const char *function_name,
    unsigned int line_number,
    enum DebugLevel debug_level,
    const char *trace_id,
    const char *span_id,
    const char *message,
    enum EventAudienceTeam team,
    const char **event_data,
    int event_data_size
);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // __EXTERNAL_AGENT_SDK_H__
