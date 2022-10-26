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

#ifndef __DEBUG_EX_H__
#define __DEBUG_EX_H__

#include "debug.h"

#include <fstream>

#include "report/report.h"
#include "i_agent_details.h"
#include "i_environment.h"
#include "i_mainloop.h"
#include "report/report_bulks.h"

enum class Debug::DebugFlags
{
    D_ALL,

#define DEFINE_FLAG(flag_name, parent_name) \
    flag_name,
#include "debug_flags.h"
#undef DEFINE_FLAG

    COUNT
};

class Debug::DebugStream
{
public:
    DebugStream(std::ostream *_stream) : stream(_stream) {}
    virtual ~DebugStream() {}

    virtual void
    printHeader(
        I_TimeGet *time,
        I_Environment *env,
        I_MainLoop *mainloop,
        DebugLevel curr_level,
        const std::string &file_name,
        const std::string &func_name,
        uint line
    );

    virtual void finishMessage() { *stream << std::endl; }

    std::ostream * getStream() const { return stream; }

private:
    std::ostream *stream;
};

class DebugFileStream : public Debug::DebugStream
{
public:
    DebugFileStream(const std::string &_file_name);
    ~DebugFileStream();

    void
    printHeader(
        I_TimeGet *time,
        I_Environment *env,
        I_MainLoop *mainloop,
        Debug::DebugLevel curr_level,
        const std::string &file_name,
        const std::string &func_name,
        uint line
    ) override;

    void finishMessage() override;

private:
    void openDebugFile();
    void closeDebugFile();
    bool retryFinishMessage();

    std::string   file_name;
    std::ofstream file;
};

class DebugFogStream
        :
    public Debug::DebugStream,
    Singleton::Consume<I_AgentDetails>,
    Singleton::Consume<I_Environment>
{
public:
    DebugFogStream();
    ~DebugFogStream();

    void
    printHeader(
        I_TimeGet *time,
        I_Environment *env,
        I_MainLoop *mainloop,
        Debug::DebugLevel curr_level,
        const std::string &file_name,
        const std::string &func_name,
        uint line
    ) override;

    void finishMessage() override;

private:
    void sendBufferedMessages();
    void sendSingleMessage(const LogRest &report);
    void handleThresholdReach();

    ReportIS::Severity getSeverity() const;
    ReportIS::LogLevel getLogLevel() const;

    ReportsBulk reports;
    I_MainLoop::RoutineID debug_send_routine = 0;

    std::stringstream message;
    std::set<ReportIS::Tags> tags;
    Debug::DebugLevel level;
    std::chrono::microseconds curr_time;
    std::string file_name;
    std::string func_name;
    std::string trace_id;
    std::string span_id;
    uint line;
};

#endif // __DEBUG_EX_H__
