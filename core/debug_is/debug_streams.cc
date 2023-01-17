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

#include "debug_ex.h"

#include "i_time_get.h"
#include "config.h"
#include "i_messaging.h"
#include "i_mainloop.h"
#include "rest.h"
#include "report/report.h"
#include "report/log_rest.h"

using namespace std;
using namespace ReportIS;

USE_DEBUG_FLAG(D_DEBUG_FOG);

static const int minimal_location_info_length = 60;
static const int tracing_info_len = 6;
static const int tracing_info_total_len = (2 * tracing_info_len) + 3;
extern const string unnamed_service = "Unnamed Nano Service";

static const map<Debug::DebugLevel, string> prompt = {
    { Debug::DebugLevel::NOISE,     "***" },
    { Debug::DebugLevel::TRACE,     ">>>" },
    { Debug::DebugLevel::DEBUG,     "@@@" },
    { Debug::DebugLevel::WARNING,   "###" },
    { Debug::DebugLevel::INFO,      "---" },
    { Debug::DebugLevel::ERROR,     "!!!" },
    { Debug::DebugLevel::ASSERTION, "~~~" }
};

static string
getTracingHeader(I_Environment *env)
{
    auto current_trace = env->getCurrentTrace();
    if (current_trace.empty()) return ": ";
    string tracing_data;
    tracing_data.reserve(tracing_info_total_len);
    tracing_data.append(current_trace, 0, tracing_info_len);

    auto current_span = env->getCurrentSpan();
    if (!current_span.empty()) {
        tracing_data += '-';
        tracing_data.append(current_span, 0, tracing_info_len);
    }
    tracing_data += ": ";
    return tracing_data;
}

static string
getCurrentRoutineHeader(I_MainLoop *mainloop)
{
    auto current_routine_id = mainloop->getCurrentRoutineId();
    return current_routine_id.ok() ? "<" + to_string(*current_routine_id) + "> " : "";
}

void
Debug::DebugStream::printHeader(
    I_TimeGet *time,
    I_Environment *env,
    I_MainLoop *mainloop,
    DebugLevel curr_level,
    const string &file_name,
    const string &func_name,
    uint line)
{
    (*getStream()) << "[";
    if (time != nullptr) (*getStream()) << time->getWalltimeStr() << ": ";
    stringstream os;
    if (env != nullptr) os << getTracingHeader(env);
    if (mainloop != nullptr) os << getCurrentRoutineHeader(mainloop);
    os << func_name << '@' << file_name << ':' << line;
    stringstream location;
    location.width(minimal_location_info_length);
    location << left << os.str() <<  " | ";
    (*getStream()) << location.str() << prompt.at(curr_level) << "] ";
}

DebugFileStream::DebugFileStream(const string &_file_name)
        :
    Debug::DebugStream(&file),
    file_name(_file_name)
{
    openDebugFile();
}

DebugFileStream::~DebugFileStream() { closeDebugFile(); }

void
DebugFileStream::printHeader(
    I_TimeGet *time,
    I_Environment *env,
    I_MainLoop *mainloop,
    Debug::DebugLevel curr_level,
    const string &file_name,
    const string &func_name,
    uint line)
{
    (*Debug::DebugStream::getStream()) << "[";
    if (time != nullptr) (*Debug::DebugStream::getStream()) << time->getWalltimeStr() << ": ";
    stringstream os;
    if (env != nullptr) os << getTracingHeader(env);
    if (mainloop != nullptr) os << getCurrentRoutineHeader(mainloop);

    os << func_name << '@' << file_name << ':' << line;
    stringstream location;
    location.width(minimal_location_info_length);
    location << left << os.str() <<  " | ";
    (*Debug::DebugStream::getStream()) << location.str();
    (*Debug::DebugStream::getStream()) << prompt.at(curr_level) << "] ";
}

void
DebugFileStream::finishMessage()
{
    file << endl;
    if (file.good()) return;

    cerr
        << "Failed to write debug message to file, re-opening debug file and retrying to write. File path: "
        << file_name
        << endl;

    static const uint32_t max_num_retries = 3;
    for (uint32_t num_retries = 0; num_retries < max_num_retries; num_retries++) {

        closeDebugFile();
        openDebugFile();
        file << endl;

        if (file.good()) return;
    }
}

void
DebugFileStream::openDebugFile()
{
    cerr << "Opening debug file. File path: " << file_name << endl;
    file.open(file_name, ofstream::app);
    if (!file.good()) {
        cerr << "Failed to open debug file. File path: " << file_name << endl;
        return;
    }

    cerr << "Successfully opened debug file. File path: " << file_name << endl;
}

void
DebugFileStream::closeDebugFile()
{
    file.close();
    if (file.is_open() || file.failbit) {
        cerr << "Failed in closing debug file. File path: " << file_name << endl;
        return;
    }

    cerr << "Successfully closed debug file at path: " << file_name << endl;
}

DebugFogStream::DebugFogStream()
        :
    DebugStream(&message)
{
    if (!Singleton::exists<I_Messaging>() ||
        !Singleton::exists<Config::I_Config>() ||
        !Singleton::exists<I_MainLoop>()) {
            dbgError(D_DEBUG_FOG) << "Sending debugs to fog disabled due to missing components";
            return;
    }

    reports.setBulkSize(getConfigurationWithDefault<uint>(100, "Debug I/S", "Debug bulk size"));

    chrono::milliseconds sent_debug_bulk_interval_msec = chrono::milliseconds(
        getConfigurationWithDefault<uint>(
            30000,
            "Debug I/S",
            "Debug bulk sending interval in msec"
        )
    );
    auto mainloop = Singleton::Consume<I_MainLoop>::by<Debug>();
    debug_send_routine = mainloop->addRecurringRoutine(
        I_MainLoop::RoutineType::Offline,
        sent_debug_bulk_interval_msec,
        [this] () { sendBufferedMessages(); },
        "Debug Fog stream messaging"
    );
}

DebugFogStream::~DebugFogStream()
{
    if (!Singleton::exists<I_MainLoop>()) return;

    if (Singleton::Consume<I_MainLoop>::by<Debug>()->doesRoutineExist(debug_send_routine)) {
        Singleton::Consume<I_MainLoop>::by<Debug>()->stop(debug_send_routine);
    }
}

void
DebugFogStream::printHeader(
    I_TimeGet *time,
    I_Environment *env,
    I_MainLoop *,
    Debug::DebugLevel curr_level,
    const string &curr_file_name,
    const string &curr_func_name,
    uint curr_line)
{
    message.str("");
    tags.clear();
    level = curr_level;
    file_name = curr_file_name;
    func_name = curr_func_name;
    line = curr_line;
    curr_time = time!=nullptr ? time->getWalltime() : chrono::microseconds(0);
    if (env != nullptr) {
        trace_id = env->getCurrentTrace();
        span_id = env->getCurrentSpan();
    }
}

void
DebugFogStream::finishMessage()
{
    string service_name = unnamed_service;
    if (Singleton::exists<I_Environment>()) {
        auto name = Singleton::Consume<I_Environment>::by<DebugFogStream>()->get<string>("Service Name");
        if (name.ok()) service_name = *name;
    }

    AudienceTeam audience_team = AudienceTeam::NONE;
    if (Singleton::exists<I_Environment>()) {
        auto team = Singleton::Consume<I_Environment>::by<DebugFogStream>()->get<AudienceTeam>("Audience Team");
        if (team.ok()) audience_team = *team;
    }

    Report message_to_fog(
        "Debug message",
        curr_time,
        Type::CODE,
        Level::LOG,
        getLogLevel(),
        Audience::INTERNAL,
        audience_team,
        getSeverity(),
        Priority::LOW,
        chrono::seconds(0),
        LogField("agentId", Singleton::Consume<I_AgentDetails>::by<DebugFogStream>()->getAgentId()),
        LogField("issuingFunction", func_name),
        LogField("issuingFile", file_name),
        LogField("issuingLine", line),
        tags,
        Tags::INFORMATIONAL
    );
    message_to_fog << LogField("eventMessage", message.str());

    if (!getConfigurationWithDefault<bool>(true, "Debug I/S", "Enable bulk of debugs")) {
        LogRest rest(move(message_to_fog));
        Singleton::Consume<I_MainLoop>::by<Debug>()->addOneTimeRoutine(
            I_MainLoop::RoutineType::Offline,
            [this, rest] () { sendSingleMessage(rest); },
            "Debug Fog stream messaging"
        );
        return;
    }

    reports.push(move(message_to_fog));
}

void
DebugFogStream::sendBufferedMessages()
{
    auto threshold_bulk_size = getConfigurationWithDefault<uint>(300, "Debug I/S", "Threshold debug bulk size");
    if (reports.size() >= threshold_bulk_size) {
        handleThresholdReach();
    }

    string fog_debug_uri = getConfigurationWithDefault<string>(
        "/api/v1/agents/events/bulk",
        "Debug I/S",
        "Fog debug URI"
    );

    auto i_msg = Singleton::Consume<I_Messaging>::by<Debug>();

    while (!reports.empty()) {
        auto rest = reports.pop();
        using Method = I_Messaging::Method;
        i_msg->sendObjectWithPersistence(rest, Method::POST, fog_debug_uri, "", true, MessageTypeTag::DEBUG);
    }
}
void
DebugFogStream::sendSingleMessage(const LogRest &rest)
{
    string fog_debug_uri = getConfigurationWithDefault<string>(
        "/api/v1/agents/events",
        "Debug I/S",
        "Fog debug URI"
    );

    auto i_msg = Singleton::Consume<I_Messaging>::by<Debug>();
    i_msg->sendObjectWithPersistence(rest, I_Messaging::Method::POST, fog_debug_uri, "", true, MessageTypeTag::DEBUG);
}

void
DebugFogStream::handleThresholdReach()
{
    string service_name = unnamed_service;
    if (Singleton::exists<I_Environment>()) {
        auto name = Singleton::Consume<I_Environment>::by<DebugFogStream>()->get<string>("Service Name");
        if (name.ok()) service_name = *name;
    }

    AudienceTeam audience_team = AudienceTeam::NONE;
    if (Singleton::exists<I_Environment>()) {
        auto team = Singleton::Consume<I_Environment>::by<DebugFogStream>()->get<AudienceTeam>("Audience Team");
        if (team.ok()) audience_team = *team;
    }

    Report message_to_fog(
        "Debug message",
        curr_time,
        Type::CODE,
        Level::LOG,
        LogLevel::WARNING,
        Audience::INTERNAL,
        audience_team,
        Severity::MEDIUM,
        Priority::LOW,
        chrono::seconds(0),
        LogField("agentId", Singleton::Consume<I_AgentDetails>::by<DebugFogStream>()->getAgentId()),
        LogField("issuingFunction", __FUNCTION__),
        LogField("issuingFile", "debug_streams.cc"),
        LogField("issuingLine", __LINE__),
        tags,
        Tags::INFORMATIONAL
    );

    auto msg = "Threshold bulk size was reached, " + to_string(reports.size()) + " debug messages were discarded";
    message_to_fog << LogField("eventMessage", msg);

    reports.clear();
    reports.push(move(message_to_fog));
}

Severity
DebugFogStream::getSeverity() const
{
    switch (level) {
        case Debug::DebugLevel::NOISE:     return Severity::INFO;
        case Debug::DebugLevel::TRACE:     return Severity::INFO;
        case Debug::DebugLevel::DEBUG:     return Severity::LOW;
        case Debug::DebugLevel::WARNING:   return Severity::MEDIUM;
        case Debug::DebugLevel::INFO:      return Severity::MEDIUM;
        case Debug::DebugLevel::ERROR:     return Severity::HIGH;
        case Debug::DebugLevel::ASSERTION: return Severity::CRITICAL;
        case Debug::DebugLevel::NONE:      return Severity::CRITICAL;
    }

    return Severity::CRITICAL;
}

LogLevel
DebugFogStream::getLogLevel() const
{
    switch (level) {
        case Debug::DebugLevel::NOISE:     dbgAssert(false) << "Impossible LogLevel 'Noise'"; break;
        case Debug::DebugLevel::TRACE:     return LogLevel::TRACE;
        case Debug::DebugLevel::DEBUG:     return LogLevel::DEBUG;
        case Debug::DebugLevel::WARNING:   return LogLevel::WARNING;
        case Debug::DebugLevel::INFO:      return LogLevel::INFO;
        case Debug::DebugLevel::ERROR:     return LogLevel::ERROR;
        case Debug::DebugLevel::ASSERTION: return LogLevel::ERROR;
        case Debug::DebugLevel::NONE:      dbgAssert(false) << "Impossible LogLevel 'None'"; break;
    }

    return LogLevel::INFO;
}
