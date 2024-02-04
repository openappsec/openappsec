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

#include "log_streams.h"
#include "debug.h"
#include "config.h"
#include "singleton.h"
#include "logging_comp.h"
#include "agent_core_utilities.h"

using namespace std;
using namespace cereal;

USE_DEBUG_FLAG(D_REPORT);

string
getLogFileName()
{
    string file_path = getConfigurationWithDefault<string>("", "Logging", "Log file name");
    if (file_path != "" && file_path.front() != '/') {
        file_path = getLogFilesPathConfig() + "/" + file_path;
    }
    
    if (Singleton::exists<I_InstanceAwareness>()) {
        file_path += Singleton::Consume<I_InstanceAwareness>::by<LoggingComp>()->getUniqueID("");
    }

    return file_path;
}

LogFileStream::LogFileStream() : log_file_name(getLogFileName())
{
    openLogFile();
}

LogFileStream::~LogFileStream()
{
    closeLogFile();
}

void
LogFileStream::sendLog(const Report &log)
{
    string maybe_new_log_file_name = getLogFileName();
    if(maybe_new_log_file_name == "") {
        closeLogFile();
        return;
    }
    if(maybe_new_log_file_name != log_file_name) {
        closeLogFile();
        openLogFile();
    }

    bool should_format_log = log.isEnreachmentActive(ReportIS::Enreachments::BEAUTIFY_OUTPUT);
    string logs_separator = getProfileAgentSettingWithDefault<string>("", "agent.config.logFileLineSeparator");
    logs_separator = getConfigurationWithDefault<string>(logs_separator, "Logging", "Log file line separator");

    stringstream ss;
    if (should_format_log) {
        {
            JSONOutputArchive ar(ss);
            log.serialize(ar);
        }
        log_stream << ss.str() << logs_separator << endl;
    } else {
        {
            JSONOutputArchive ar(ss, JSONOutputArchive::Options::NoIndent());
            log.serialize(ar);
        }
        static const boost::regex reg("\\n");
        log_stream << NGEN::Regex::regexReplace(__FILE__, __LINE__, ss.str(), reg, "") << logs_separator << endl;
    }

    if (!log_stream.good()) {
        dbgWarning(D_REPORT) << "Failed to write log to file, will retry. File path: " << log_file_name;

        if (!retryWritingLog(ss.str())) {
            dbgWarning(D_REPORT) << "Failed to write log to file";
            return;
        }
    }

    dbgDebug(D_REPORT) << "Successfully wrote log to file";
}

void
LogFileStream::openLogFile()
{
    log_file_name = getLogFileName();
    if (log_file_name == "") {
        dbgInfo(D_REPORT) << "Empty log file name, no log file will be written";
        return;
    }

    log_stream.open(log_file_name, ofstream::app);
    if (!log_stream.is_open()) {
        dbgWarning(D_REPORT) << "Failed in opening log file. File path: " << log_file_name;
        return;
    }

    dbgDebug(D_REPORT) << "Successfully opened log file at path: " << log_file_name;
}

void
LogFileStream::closeLogFile()
{
    log_stream.close();
    if (log_stream.is_open() || log_stream.failbit) {
        dbgWarning(D_REPORT) << "Failed in closing log file. File path: " << log_file_name;
        return;
    }

    dbgDebug(D_REPORT) << "Successfully closed log file at path: " << log_file_name;
}

bool
LogFileStream::retryWritingLog(const string &log)
{
    uint32_t max_num_retries = getConfigurationWithDefault<uint>(3, "Logging", "Maximum number of write retries");
    for (uint32_t num_retries = 0; num_retries < max_num_retries; num_retries++) {
        closeLogFile();
        openLogFile();

        log_stream << log << endl;
        if (log_stream.good()) return true;
    }

    return false;
}
