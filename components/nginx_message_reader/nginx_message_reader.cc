#include "nginx_message_reader.h"

#include <string>
#include <boost/regex.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/regex.hpp>

#include "config.h"
#include "singleton.h"
#include "i_mainloop.h"
#include "enum_array.h"
#include "log_generator.h"
#include "maybe_res.h"
#include "http_transaction_data.h"
#include "generic_rulebase/rulebase_config.h"
#include "generic_rulebase/evaluators/asset_eval.h"
#include "generic_rulebase/triggers_config.h"
#include "agent_core_utilities.h"
#include "rate_limit_config.h"

USE_DEBUG_FLAG(D_NGINX_MESSAGE_READER);

using namespace std;

static const string syslog_regex_string = (
    "<[0-9]+>([A-Z][a-z][a-z]\\s{1,2}\\d{1,2}\\s\\d{2}"
    "[:]\\d{2}[:]\\d{2})\\s([\\w][\\w\\d\\.@-]*)\\s(nginx:)"
);

static const boost::regex socket_address_regex("(\\d+\\.\\d+\\.\\d+\\.\\d+):(\\d+)");
static const boost::regex syslog_regex(syslog_regex_string);
static const boost::regex alert_log_regex(
    "("
    + syslog_regex_string + ") "
    + "(.+?\\[alert\\] )(.+?)"
    ", (client: .+?)"
    ", (server: .+?)"
    ", (request: \".+?\")"
    ", (upstream: \".+?\")"
    ", (host: \".+?\")$"
);

static const boost::regex error_log_regex(
    "("
    + syslog_regex_string + ") "
    + "(.+?\\[error\\] )(.+?)"
    ", (client: .+?)"
    ", (server: .+?)"
    ", (request: \".+?\")"
    ", (upstream: \".+?\")"
    ", (host: \".+?\")$"
);
// Generic regexes for fallback parsing
static const boost::regex generic_crit_log_regex(
    "("
    + syslog_regex_string + ") "
    + "(?:\\d{4}/\\d{2}/\\d{2} \\d{2}:\\d{2}:\\d{2} )?"  // Optional nginx timestamp
    + "\\[crit\\] (.+)$"
);

static const boost::regex generic_emerg_log_regex(
    "("
    + syslog_regex_string + ") "
    + "(?:\\d{4}/\\d{2}/\\d{2} \\d{2}:\\d{2}:\\d{2} )?"  // Optional nginx timestamp
    + "\\[emerg\\] (.+)$"
);

// Generic regex to extract time, log level and message for fallback parsing
static const boost::regex generic_fallback_log_regex(
    "("
    + syslog_regex_string + ") "
    + "(?:\\d{4}/\\d{2}/\\d{2} \\d{2}:\\d{2}:\\d{2} )?"  // Optional nginx timestamp
    + "\\[(\\w+)\\] (.+)$"
);

static const boost::regex server_regex("(\\d+\\.\\d+\\.\\d+\\.\\d+)|(\\w+\\.\\w+)");
static const boost::regex uri_regex("^/");
static const boost::regex port_regex("\\d+");
static const boost::regex response_code_regex("[0-9]{3}");
static const boost::regex http_method_regex("[A-Za-z]+");

static const string central_nginx_manager = "Central NGINX Manager";
static const string reverse_proxe = "Reverse Proxy";

class NginxMessageReader::Impl
{
public:
    void
    init()
    {
        dbgFlow(D_NGINX_MESSAGE_READER);

        if (Singleton::exists<I_Environment>()) {
            auto name = Singleton::Consume<I_Environment>::by<Report>()->get<string>("Service Name");
            if (name.ok()) 
            {
                dbgInfo(D_NGINX_MESSAGE_READER) << "Service name: " << *name;
                service_name = *name;
            }
        }

        I_MainLoop *mainloop = Singleton::Consume<I_MainLoop>::by<NginxMessageReader>();
        mainloop->addOneTimeRoutine(
            I_MainLoop::RoutineType::System,
            [this] ()
            {
                initSyslogServerSocket();
                handleNginxLogs();
            },
            "Initialize nginx syslog",
            true
        );
    }

    void
    preload()
    {
        registerConfigLoadCb([this]() { loadNginxMessageReaderConfig(); });
    }

    void
    fini()
    {
        I_Socket *i_socket = Singleton::Consume<I_Socket>::by<NginxMessageReader>();
        i_socket->closeSocket(syslog_server_socket);
    }

    void
    loadNginxMessageReaderConfig()
    {
        rate_limit_status_code = getProfileAgentSettingWithDefault<string>(
            "429",
            "accessControl.rateLimit.returnCode"
        );
        dbgTrace(D_NGINX_MESSAGE_READER) << "Selected rate-limit status code: " << rate_limit_status_code;
    }

private:
    enum class LogInfo {
        HTTP_METHOD,
        URI,
        RESPONSE_CODE,
        HOST,
        SOURCE,
        DESTINATION_IP,
        DESTINATION_PORT,
        EVENT_MESSAGE,
        ASSET_ID,
        ASSET_NAME,
        RULE_NAME,
        RULE_ID,
        COUNT
    };

    struct GenericLogInfo {
        string timestamp;
        string severity;
        string message;
    };

    void
    initSyslogServerSocket()
    {
        dbgFlow(D_NGINX_MESSAGE_READER);
        I_MainLoop *mainloop = Singleton::Consume<I_MainLoop>::by<NginxMessageReader>();
        I_Socket *i_socket = Singleton::Consume<I_Socket>::by<NginxMessageReader>();
        string nginx_syslog_server_address = getProfileAgentSettingWithDefault<string>(
            "127.0.0.1:1514",
            "reverseProxy.nginx.syslogAddress"
        );
        dbgInfo(D_NGINX_MESSAGE_READER) << "Attempting to open a socket: " << nginx_syslog_server_address;
        do {
            Maybe<I_Socket::socketFd> new_socket = i_socket->genSocket(
                I_Socket::SocketType::UDP,
                false,
                true,
                nginx_syslog_server_address
            );
            if (!new_socket.ok()) {
                dbgError(D_NGINX_MESSAGE_READER) << "Failed to open a socket. Error: " << new_socket.getErr();
                mainloop->yield(chrono::milliseconds(500));
                continue;
            }

            if (new_socket.unpack() < 0) {
                dbgError(D_NGINX_MESSAGE_READER)<< "Generated socket is OK yet negative";
                mainloop->yield(chrono::milliseconds(500));
                continue;
            }
            syslog_server_socket = new_socket.unpack();
            dbgInfo(D_NGINX_MESSAGE_READER)
                << "Opened socket for nginx logs over syslog. Socket: "
                << syslog_server_socket;
        } while (syslog_server_socket < 0);
    }

    void
    handleNginxLogs()
    {
        dbgFlow(D_NGINX_MESSAGE_READER);
        I_MainLoop::Routine read_logs =
        [this] ()
        {
            Maybe<string> logs = getLogsFromSocket(syslog_server_socket);

            if (!logs.ok()) {
                dbgWarning(D_NGINX_MESSAGE_READER)
                    << "Failed to get NGINX logs from the socket. Error: "
                    << logs.getErr();
                return;
            }
            string raw_logs_to_parse = logs.unpackMove();
            vector<string> logs_to_parse = separateLogs(raw_logs_to_parse);

            for (auto const &log: logs_to_parse) {
                bool log_sent;
                if (isAccessLog(log)) {
                    log_sent = sendAccessLog(log);
                } else if (isAlertErrorLog(log) || isErrorLog(log) || isCritErrorLog(log) || isEmergErrorLog(log)) {
                    log_sent = sendErrorLog(log);
                } else {
                    dbgWarning(D_NGINX_MESSAGE_READER) << "Unexpected nginx log format for message: "<< log;
                    continue;
                }
                if (!log_sent) {
                    dbgWarning(D_NGINX_MESSAGE_READER) << "Failed to send Log to Infinity Portal";
                } else {
                    dbgTrace(D_NGINX_MESSAGE_READER) << "Succesfully sent nginx log to Infinity Portal";
                }
            }
        };
        I_MainLoop *mainloop = Singleton::Consume<I_MainLoop>::by<NginxMessageReader>();
        mainloop->addFileRoutine(
            I_MainLoop::RoutineType::RealTime,
            syslog_server_socket,
            read_logs,
            "Process nginx logs",
            true
        );
    }

    bool
    sendAccessLog(const string &log)
    {
        dbgFlow(D_NGINX_MESSAGE_READER) << "Access log" << log;
        Maybe<EnumArray<LogInfo, string>> log_info = parseAccessLog(log);
        if (!log_info.ok()) {
            dbgWarning(D_NGINX_MESSAGE_READER)
                << "Failed parsing the NGINX logs. Error: "
                << log_info.getErr();
            return false;
        }
        auto unpacked_log_info = log_info.unpack();

        if (unpacked_log_info[LogInfo::RESPONSE_CODE] == rate_limit_status_code) {
            return sendRateLimitLog(unpacked_log_info);
        }
        return sendLog(unpacked_log_info);
    }

    bool
    sendErrorLog(const string &log)
    {
        dbgFlow(D_NGINX_MESSAGE_READER) << "Error log" << log;
        Maybe<EnumArray<LogInfo, string>> log_info = parseErrorLog(log);
        if (log_info.ok()) {
            return sendLog(log_info.unpack());
        }

        if (service_name == central_nginx_manager) {
            dbgDebug(D_NGINX_MESSAGE_READER) << "Detailed parsing failed, trying generic parsing";
            Maybe<GenericLogInfo> generic_log = parseGenericErrorLog(log);
            if (generic_log.ok()) {
                return sendGenericLog(generic_log.unpack());
            }
        }

        dbgWarning(D_NGINX_MESSAGE_READER)
            << "Failed parsing the NGINX logs. Error: "
            << log_info.getErr();
        return false;
    }

    bool
    isAccessLog(const string &log) const
    {
        dbgFlow(D_NGINX_MESSAGE_READER) << "Chekck if string contains \"accessLog\"" << log;
        return log.find("accessLog") != string::npos;
    }

    bool
    isAlertErrorLog(const string &log) const
    {
        dbgFlow(D_NGINX_MESSAGE_READER) << "Check if log is of type 'error log'. Log: " << log;
        return log.find("[alert]") != string::npos;
    }

    bool
    isErrorLog(const string &log) const
    {
        dbgFlow(D_NGINX_MESSAGE_READER) << "Check if log is of type 'error log'. Log: " << log;
        return log.find("[error]") != string::npos;
    }

    bool
    isCritErrorLog(const string &log) const
    {
        dbgFlow(D_NGINX_MESSAGE_READER) << "Check if log is of type 'crit log'. Log: " << log;
        return log.find("[crit]") != string::npos;
    }

    bool
    isEmergErrorLog(const string &log) const
    {
        dbgFlow(D_NGINX_MESSAGE_READER) << "Check if log is of type 'emerg log'. Log: " << log;
        return log.find("[emerg]") != string::npos;
    }

    string
    getCNMEventName(const EnumArray<LogInfo, string> &log_info) const
    {
        dbgFlow(D_NGINX_MESSAGE_READER);
        string event_name;
        switch (log_info[LogInfo::RESPONSE_CODE][0]) {
            case '4': {
                event_name = "NGINX Proxy Error: Invalid request or incorrect NGINX configuration - Request dropped."
                " Please check the reverse proxy configuration of your relevant assets";
                break;
            }
            case '5': {
                event_name = "NGINX Proxy Error: Request failed! Please verify your proxy configuration."
                "If the issue persists please contact open-appsec support";
                break;
            }
            default: {
                dbgError(D_NGINX_MESSAGE_READER) << "Irrelevant status code";
                return "";
            }
        }
        return event_name;
    }

    string
    getRPMEventName(const EnumArray<LogInfo, string> &log_info) const
    {
        dbgFlow(D_NGINX_MESSAGE_READER);
        string event_name;
        switch (log_info[LogInfo::RESPONSE_CODE][0]) {
            case '4': {
                event_name = "Invalid request or incorrect reverse proxy configuration - Request dropped."
                " Please check the reverse proxy configuration of your relevant assets";
                break;
            }
            case '5': {
                event_name = "AppSec Gateway reverse proxy error - Request dropped. "
                "Please verify the reverse proxy configuration of your relevant assets. "
                "If the issue persists please contact Check Point Support";
                break;
            }
            default: {
                dbgError(D_NGINX_MESSAGE_READER) << "Irrelevant status code";
                return "";
            }
        }
        return event_name;
    }

    string 
    getServiceName()
    {
        string service_name = "Unnamed Nano Service";
        if (Singleton::exists<I_Environment>()) {
            auto name = Singleton::Consume<I_Environment>::by<Report>()->get<string>("Service Name");
            if (name.ok()) return *name;
        }
        return service_name;
    }

    string getEventName(const EnumArray<LogInfo, string> &log_info)
    {
        if (service_name == central_nginx_manager)
        {
            return getCNMEventName(log_info);
        }

        if (service_name != reverse_proxe)
        {
            dbgWarning(D_NGINX_MESSAGE_READER) 
                << "Unknown service name: "
                << service_name
                << " Response will be sent as RPM";
        }
        return getRPMEventName(log_info);
    }

    bool
    sendLog(const EnumArray<LogInfo, string> &log_info)
    {
        dbgFlow(D_NGINX_MESSAGE_READER);
        string event_name = getEventName(log_info);

        dbgTrace(D_NGINX_MESSAGE_READER)
            << "Nginx log's event name and response code: "
            << event_name
            << ", "
            << log_info[LogInfo::RESPONSE_CODE];
        LogGen log(
            event_name,
            ReportIS::Audience::SECURITY,
            ReportIS::Severity::HIGH,
            ReportIS::Priority::LOW,
            service_name == central_nginx_manager ?
                ReportIS::Tags::CENTRAL_NGINX_MANAGER :
                ReportIS::Tags::REVERSE_PROXY
        );
        log << LogField("eventConfidence", "High");

        for (LogInfo field : makeRange<LogInfo>()) {
            Maybe<string> string_field = convertLogFieldToString(field);
            if (!string_field.ok()) {
                dbgDebug(D_NGINX_MESSAGE_READER) << "Enum field was not converted: " <<  string_field.getErr();
                return false;
            }

            if (field != LogInfo::DESTINATION_PORT) {
                log << LogField(string_field.unpack(), log_info[field]);
                continue;
            }

            try {
                log << LogField(string_field.unpack(), stoi(log_info[field]));
            } catch (const exception &e) {
                dbgError(D_NGINX_MESSAGE_READER)
                    << "Unable to convert port to numeric value: "
                    << e.what();
                log << LogField(string_field.unpack(), 0);
            }
        }
        return true;
    }

    bool
    sendGenericLog(const GenericLogInfo &log_info)
    {
        dbgFlow(D_NGINX_MESSAGE_READER) << "Sending generic log";
        
        // check with christoper
        string event_name = "NGINX Proxy Error: Request failed! Please verify your proxy configuration."
                "If the issue persists please contact open-appsec support";
        
        // Convert string severity to ReportIS::Severity
        ReportIS::Severity severity = ReportIS::Severity::MEDIUM;
        ReportIS::Priority priority = ReportIS::Priority::MEDIUM;
        if (log_info.severity == "emerg" || log_info.severity == "crit") {
            severity = ReportIS::Severity::CRITICAL;
            priority = ReportIS::Priority::URGENT;
        } else if (log_info.severity == "error" || log_info.severity == "alert") {
            severity = ReportIS::Severity::HIGH;
            priority = ReportIS::Priority::HIGH;
        }
        
        LogGen log(
            event_name,
            ReportIS::Audience::SECURITY,
            severity,
            priority,
            ReportIS::Tags::CENTRAL_NGINX_MANAGER
        );
        
        log << LogField("eventConfidence", "High");
        log << LogField("timestamp", log_info.timestamp);
        log << LogField("httpResponseBody", formatGenericLogMessage(log_info));
        
        return true;
    }

    string
    formatGenericLogMessage(const GenericLogInfo &log_info)
    {
        return "[" + log_info.severity + "] " + log_info.message;
    }

    bool
    sendRateLimitLog(const EnumArray<LogInfo, string> &log_info)
    {
        dbgFlow(D_NGINX_MESSAGE_READER) << "Getting rate-limit rules of asset ID: " << log_info[LogInfo::ASSET_ID];

        ScopedContext rate_limit_ctx;

        rate_limit_ctx.registerValue<GenericConfigId>(AssetMatcher::ctx_key, log_info[LogInfo::ASSET_ID]);
        auto rate_limit_config = getConfiguration<RateLimitConfig>("rulebase", "rateLimit");
        if (!rate_limit_config.ok()) {
            dbgTrace(D_NGINX_MESSAGE_READER)
                << "Rate limit context does not match asset ID: " << log_info[LogInfo::ASSET_ID];
            return false;
        }
        RateLimitConfig unpacked_rate_limit_config = rate_limit_config.unpack();

        string nginx_uri = log_info[LogInfo::URI];
        const LogTriggerConf &rate_limit_trigger = unpacked_rate_limit_config.getRateLimitTrigger(nginx_uri);

        dbgTrace(D_NGINX_MESSAGE_READER)<< "About to generate NGINX rate-limit log";

        string event_name = "Rate limit";
        string security_action = "Drop";
        bool is_log_required = false;

        // Prevent events checkbox (in triggers)
        if (rate_limit_trigger.isPreventLogActive(LogTriggerConf::SecurityType::AccessControl)) {
            is_log_required = true;
        }

        if (!is_log_required) {
            dbgTrace(D_NGINX_MESSAGE_READER) << "Not sending NGINX rate-limit log as it is not required";
            return false;
        }

        ostringstream src_ip;
        ostringstream dst_ip;
        src_ip << log_info[LogInfo::SOURCE];
        dst_ip << log_info[LogInfo::DESTINATION_IP];

        ReportIS::Severity log_severity = ReportIS::Severity::MEDIUM;
        ReportIS::Priority log_priority = ReportIS::Priority::MEDIUM;

        LogGen log = rate_limit_trigger(
            event_name,
            LogTriggerConf::SecurityType::AccessControl,
            log_severity,
            log_priority,
            true, // is drop
            LogField("practiceType", "Rate Limit"),
            ReportIS::Tags::RATE_LIMIT
        );

        for (LogInfo field : makeRange<LogInfo>()) {
            Maybe<string> string_field = convertLogFieldToString(field);
            if (!string_field.ok()) {
                dbgDebug(D_NGINX_MESSAGE_READER) << "Enum field was not converted: " <<  string_field.getErr();
                return false;
            }
            
            if (
                field == LogInfo::HOST ||
                field == LogInfo::URI ||
                field == LogInfo::HTTP_METHOD ||
                field == LogInfo::SOURCE ||
                field == LogInfo::DESTINATION_IP ||
                field == LogInfo::ASSET_ID ||
                field == LogInfo::ASSET_NAME ||
                field == LogInfo::RESPONSE_CODE
            ) {
                if (!log_info[field].empty()) {
                    log << LogField(string_field.unpack(), log_info[field]);
                    continue;
                }
            }

            if (field == LogInfo::DESTINATION_PORT) {
                try {
                    int numeric_dst_port = stoi(log_info[field]);
                    log << LogField(string_field.unpack(), numeric_dst_port);
                } catch (const exception &e) {
                    dbgWarning(D_NGINX_MESSAGE_READER)
                        << "Unable to convert dst port: "
                        << log_info[field]
                        << " to numberic value. Error: "
                        << e.what();
                }
            }
        }

        return true;
    }

    Maybe<string>
    convertLogFieldToString(LogInfo field)
    {
        dbgFlow(D_NGINX_MESSAGE_READER);
        switch (field) {
            case LogInfo::HTTP_METHOD:
                return string("httpMethod");
            case LogInfo::URI:
                return string("httpUriPath");
            case LogInfo::RESPONSE_CODE:
                return string("httpResponseCode");
            case LogInfo::HOST:
                return string("httpHostName");
            case LogInfo::SOURCE:
                return string("httpSourceId");
            case LogInfo::DESTINATION_IP:
                return string("destinationIp");
            case LogInfo::DESTINATION_PORT:
                return string("destinationPort");
            case LogInfo::ASSET_ID:
                return string("assetId");
            case LogInfo::ASSET_NAME:
                return string("assetName");
            case LogInfo::EVENT_MESSAGE:
                return string("httpResponseBody");
            case LogInfo::RULE_ID:
                return string("ruleId");
            case LogInfo::RULE_NAME:
                return string("ruleName");
            case LogInfo::COUNT:
                dbgError(D_NGINX_MESSAGE_READER) << "LogInfo::COUNT is not allowed";
                return genError("LogInfo::COUNT is not allowed");
        }
        dbgError(D_NGINX_MESSAGE_READER) << "No Enum found, int value: " << static_cast<int>(field);
        return genError("No Enum found");
    }

    static vector<string>
    separateLogs(const string &raw_logs_to_parse)
    {
        dbgFlow(D_NGINX_MESSAGE_READER) << "separating logs. logs: " << raw_logs_to_parse;
        dbgTrace(D_NGINX_MESSAGE_READER) << "separateLogs start of function. Logs to parse: " << raw_logs_to_parse;
        boost::smatch matcher;
        vector<string> logs;

        if (raw_logs_to_parse.empty()) return logs;

        size_t pos = 0;
        while (NGEN::Regex::regexSearch(__FILE__, __LINE__, raw_logs_to_parse.substr(pos), matcher, syslog_regex)) {
            if (pos == 0) {
                dbgTrace(D_NGINX_MESSAGE_READER) << "separateLogs pos = 0";
                pos++;
                continue;
            }
            auto log_length = matcher.position();
            logs.push_back(raw_logs_to_parse.substr(pos - 1, log_length));

            pos += log_length + 1;
        }
        logs.push_back(raw_logs_to_parse.substr(pos - 1));
        dbgTrace(D_NGINX_MESSAGE_READER) << "separateLogs end of function";

        return logs;
    }

    static pair<string, string>
    parseErrorLogRequestField(const string &request)
    {
        dbgFlow(D_NGINX_MESSAGE_READER) << "parsing request field. request: " << request;
        string formatted_request = request;
        vector<string> result;
        boost::erase_all(formatted_request, "\"");
        boost::erase_all(formatted_request, "\n");
        boost::split(result, formatted_request, boost::is_any_of(" "), boost::token_compress_on);

        const int http_method_index = 1;
        const int uri_index = 2;
        return pair<string, string>(result[http_method_index], result[uri_index]);
    }

    static string
    parseErrorLogField(const string &field)
    {
        dbgFlow(D_NGINX_MESSAGE_READER) << "parsing error log field " << field;
        string formatted_field = field;
        vector<string> result;
        boost::erase_all(formatted_field, "\"");
        boost::erase_all(formatted_field, "\n");
        boost::split(result, formatted_field, boost::is_any_of(" "), boost::token_compress_on);

        const int field_index = 1;
        return result[field_index];
    }

    void
    addContextFieldsToLogInfo(EnumArray<LogInfo, string> &log_info)
    {
        dbgFlow(D_NGINX_MESSAGE_READER);
        ScopedContext ctx;

        try {
            ctx.registerValue<uint16_t>(
                HttpTransactionData::listening_port_ctx,
                static_cast<uint16_t>(stoi(log_info[LogInfo::DESTINATION_PORT]))
            );
        } catch (const exception &e) {
            dbgError(D_NGINX_MESSAGE_READER) << "Failed register values for context " << e.what();
        }
        ctx.registerValue<string>(HttpTransactionData::host_name_ctx, log_info[LogInfo::HOST]);
        ctx.registerValue<string>(HttpTransactionData::uri_ctx, log_info[LogInfo::URI]);
        auto rule_by_ctx = getConfiguration<BasicRuleConfig>("rulebase", "rulesConfig");
        if (!rule_by_ctx.ok()) {
            dbgWarning(D_NGINX_MESSAGE_READER)
                << "AssetId was not found by the given context. Reason: "
                << rule_by_ctx.getErr();
            return;
        }

        BasicRuleConfig context = rule_by_ctx.unpack();
        log_info[LogInfo::ASSET_ID] = context.getAssetId();
        log_info[LogInfo::ASSET_NAME] = context.getAssetName();
        log_info[LogInfo::RULE_ID] = context.getRuleId();
        log_info[LogInfo::RULE_NAME] = context.getRuleName();
    }

    Maybe<GenericLogInfo>
    parseGenericErrorLog(const string &log_line)
    {
        dbgFlow(D_NGINX_MESSAGE_READER) << "Parsing generic error log: " << log_line;
        
        boost::smatch matcher;
        GenericLogInfo generic_log;
        
        if (isCritErrorLog(log_line)) {
            if (NGEN::Regex::regexSearch(__FILE__, __LINE__, log_line, matcher, generic_crit_log_regex)) {
                const int timestamp_index = 2;  // Timestamp from within syslog_regex_string
                const int message_index = 5;    // The captured message after [crit]
                generic_log.timestamp = string(matcher[timestamp_index].first, matcher[timestamp_index].second);
                generic_log.severity = "crit";
                generic_log.message = string(matcher[message_index].first, matcher[message_index].second);
                return generic_log;
            }
        } else if (isEmergErrorLog(log_line)) {
            if (NGEN::Regex::regexSearch(__FILE__, __LINE__, log_line, matcher, generic_emerg_log_regex)) {
                const int timestamp_index = 2;  // Timestamp from within syslog_regex_string
                const int message_index = 5;    // The captured message after [emerg]
                generic_log.timestamp = string(matcher[timestamp_index].first, matcher[timestamp_index].second);
                generic_log.severity = "emerg";
                generic_log.message = string(matcher[message_index].first, matcher[message_index].second);
                return generic_log;
            }
        }
        
        if (NGEN::Regex::regexSearch(__FILE__, __LINE__, log_line, matcher, generic_fallback_log_regex)) {
            const int timestamp_index = 2;  // Timestamp from within syslog_regex_string
            const int severity_index = 5;   // The captured severity level
            const int message_index = 6;    // The captured message
            generic_log.timestamp = string(matcher[timestamp_index].first, matcher[timestamp_index].second);
            generic_log.severity = string(matcher[severity_index].first, matcher[severity_index].second);
            generic_log.message = string(matcher[message_index].first, matcher[message_index].second);
            return generic_log;
        }
        
        dbgWarning(D_NGINX_MESSAGE_READER) << "Could not parse log with generic method: " << log_line;
        return genError("Could not parse log with generic method");
    }

    Maybe<EnumArray<LogInfo, string>>
    parseErrorLog(const string &log_line)
    {
        dbgFlow(D_NGINX_MESSAGE_READER) << "Handling log line:" << log_line;
        string port;
        EnumArray<LogInfo, string> log_info(EnumArray<LogInfo, string>::Fill(), string(""));

        boost::smatch matcher;
        vector<string> result;
        boost::regex selected_regex;
        
        // Select appropriate regex based on log type
        if (isAlertErrorLog(log_line)) {
            selected_regex = alert_log_regex;
        } else if (isErrorLog(log_line)) {
            selected_regex = error_log_regex;
        } else {
            dbgWarning(D_NGINX_MESSAGE_READER) << "No matching log type found for log: " << log_line;
            return genError("No matching log type found");
        }

        if (
            !NGEN::Regex::regexSearch(
                __FILE__,
                __LINE__,
                log_line,
                matcher,
                selected_regex
            )
        ) {
            dbgWarning(D_NGINX_MESSAGE_READER) << "Detailed regex parsing failed for log: " << log_line;
            return genError("Detailed regex parsing failed");
        }

        const int event_message_index = 6;
        const int source_index = 7;
        const int request_index = 9;
        const int host_index = 11;
        string host = string(matcher[host_index].first, matcher[host_index].second);
        string source = string(matcher[source_index].first, matcher[source_index].second);
        string event_message = string(matcher[event_message_index].first, matcher[event_message_index].second);
        string request = string(matcher[request_index].first, matcher[request_index].second);

        host = parseErrorLogField(host);
        source = parseErrorLogField(source);
        pair<string, string> parsed_request = parseErrorLogRequestField(request);
        string http_method = parsed_request.first;
        string uri = parsed_request.second;

        if (NGEN::Regex::regexSearch(__FILE__, __LINE__, host, matcher, socket_address_regex)) {
            int host_index = 1;
            int port_index = 2;
            host = string(matcher[host_index].first, matcher[host_index].second);
            port = string(matcher[port_index].first, matcher[port_index].second);
        } else if (NGEN::Regex::regexSearch(__FILE__, __LINE__, host, matcher, boost::regex("https://"))) {
            port = "443";
        } else {
            port = "80";
        }

        log_info[LogInfo::HOST] = host;
        log_info[LogInfo::URI] = uri;
        log_info[LogInfo::RESPONSE_CODE] = "500";
        log_info[LogInfo::HTTP_METHOD] = http_method;
        log_info[LogInfo::SOURCE] = source;
        log_info[LogInfo::DESTINATION_IP] = host;
        log_info[LogInfo::DESTINATION_PORT] = port;
        log_info[LogInfo::EVENT_MESSAGE] = event_message;

        addContextFieldsToLogInfo(log_info);

        if (!validateLog(log_info)) {
            dbgWarning(D_NGINX_MESSAGE_READER) << "Log validation failed for detailed parsing";
            return genError("Log validation failed for detailed parsing");
        }

        return log_info;
    }

    Maybe<EnumArray<LogInfo, string>>
    parseAccessLog(const string &log_line)
    {
        dbgFlow(D_NGINX_MESSAGE_READER) << "Parsing log line: " << log_line;
        string formatted_log = log_line;
        EnumArray<LogInfo, string> log_info(EnumArray<LogInfo, string>::Fill(), string(""));
        vector<string> result;
        boost::erase_all(formatted_log, "\"");
        boost::erase_all(formatted_log, "\n");
        boost::split(result, formatted_log, boost::is_any_of(" "), boost::token_compress_on);

        const int valid_log_size = 20;

        if (result.size() < valid_log_size) {
            dbgWarning(D_NGINX_MESSAGE_READER) << "Unexpected nginx log format";
            return genError("Unexpected nginx log format");
        }

        const int host_index = 6;
        const int host_port_index = 7;
        const int http_method_index = 13;
        const int uri_index = 14;
        const int response_cod_index = 16;
        const int source_index = 8;

        log_info[LogInfo::HOST] = result[host_index];
        log_info[LogInfo::URI] = result[uri_index];
        log_info[LogInfo::RESPONSE_CODE] = result[response_cod_index];
        log_info[LogInfo::HTTP_METHOD] = result[http_method_index];
        log_info[LogInfo::SOURCE] = result[source_index];
        log_info[LogInfo::DESTINATION_IP] = result[host_index];
        log_info[LogInfo::DESTINATION_PORT] = result[host_port_index];
        log_info[LogInfo::EVENT_MESSAGE] = "Invalid request or incorrect reverse proxy configuration - "
        "Request dropped. Please check the reverse proxy configuration of your relevant assets";

        addContextFieldsToLogInfo(log_info);

        if (!validateLog(log_info)) {
            dbgWarning(D_NGINX_MESSAGE_READER) << "Unexpected nginx log format";
            return genError("Unexpected nginx log format");
        }
        return log_info;
    }

    static bool
    validateLog(const EnumArray<LogInfo, string> &log_info)
    {
        dbgFlow(D_NGINX_MESSAGE_READER);

        boost::smatch matcher;
        if (!NGEN::Regex::regexSearch(__FILE__, __LINE__, log_info[LogInfo::HOST], matcher, server_regex)) {
            dbgTrace(D_NGINX_MESSAGE_READER) << "Could not validate server (Host): " << log_info[LogInfo::HOST];
            return false;
        }
        if (!NGEN::Regex::regexSearch(__FILE__, __LINE__, log_info[LogInfo::URI], matcher, uri_regex)) {
            dbgTrace(D_NGINX_MESSAGE_READER) << "Could not validate Uri: " << log_info[LogInfo::URI];
            return false;
        }

        if (
            !NGEN::Regex::regexSearch(
                __FILE__,
                __LINE__,
                log_info[LogInfo::RESPONSE_CODE],
                matcher, response_code_regex
            )
        ) {
            dbgTrace(D_NGINX_MESSAGE_READER)
                << "Could not validate response code: "
                << log_info[LogInfo::RESPONSE_CODE];
            return false;
        }

        if (
            !NGEN::Regex::regexSearch(__FILE__, __LINE__, log_info[LogInfo::HTTP_METHOD], matcher, http_method_regex)
        ) {
            dbgTrace(D_NGINX_MESSAGE_READER) << "Could not validate HTTP method: " << log_info[LogInfo::HTTP_METHOD];
            return false;
        }

        if (!NGEN::Regex::regexSearch(__FILE__, __LINE__, log_info[LogInfo::DESTINATION_PORT], matcher, port_regex)) {
            dbgTrace(D_NGINX_MESSAGE_READER)
                << "Could not validate destination port : "
                << log_info[LogInfo::DESTINATION_PORT];
            return false;
        }

        if (!NGEN::Regex::regexSearch(__FILE__, __LINE__, log_info[LogInfo::SOURCE], matcher, server_regex)) {
            dbgTrace(D_NGINX_MESSAGE_READER) << "Could not validate source : " << log_info[LogInfo::SOURCE];
            return false;
        }

        return true;
    }

    Maybe<string>
    getLogsFromSocket(const I_Socket::socketFd &client_socket) const
    {
        dbgFlow(D_NGINX_MESSAGE_READER) << "Reading logs from socket. fd: " << client_socket;
        I_Socket *i_socket = Singleton::Consume<I_Socket>::by<NginxMessageReader>();
        Maybe<vector<char>> raw_log_data = i_socket->receiveData(client_socket, 0, false);
        if (!raw_log_data.ok()) {
            dbgWarning(D_NGINX_MESSAGE_READER) << "Error receiving data from socket";
            return genError("Error receiving data from socket");
        }

        string raw_log(raw_log_data.unpack().begin(), raw_log_data.unpack().end());
        return move(raw_log);
    }

    I_Socket::socketFd syslog_server_socket = -1;
    string rate_limit_status_code = "429";
    string service_name = "Unnamed Nano Service";
};

NginxMessageReader::NginxMessageReader() : Component("NginxMessageReader"), pimpl(make_unique<Impl>()) {}

NginxMessageReader::~NginxMessageReader() {}

void
NginxMessageReader::init()
{
    pimpl->init();
}

void
NginxMessageReader::preload()
{
    pimpl->preload();
}

void
NginxMessageReader::fini()
{
    pimpl->fini();
}
