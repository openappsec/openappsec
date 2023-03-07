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

#include "logging_comp.h"

#include <map>
#include <sstream>
#include <fstream>

#include "log_streams.h"
#include "common.h"
#include "singleton.h"
#include "debug.h"
#include "rest.h"
#include "config.h"
#include "i_mainloop.h"
#include "report/report_bulks.h"
#include "report/log_rest.h"
#include "instance_awareness.h"
#include "logging_metric.h"
#include "tag_and_enum_management.h"

using namespace std;
using namespace cereal;

USE_DEBUG_FLAG(D_REPORT);

class LoggingComp::Impl
        :
    Singleton::Provide<I_Logging>::From<LoggingComp>
{
public:
    using StreamType = ReportIS::StreamType;

    void
    init()
    {
        streams = streams_preperation;
        i_mainloop = Singleton::Consume<I_MainLoop>::by<LoggingComp>();

        auto bulk_msec_interval = getConfigurationWithDefault<uint>(
            2000,
            "Logging",
            "Log bulk sending interval in msec"
        );
        log_send_routine = i_mainloop->addRecurringRoutine(
            I_MainLoop::RoutineType::Offline,
            chrono::milliseconds(bulk_msec_interval),
            [this] () { sendBufferedLogs(); },
            "Logging Fog stream messaging"
        );

        auto metrics_interval = getConfigurationWithDefault<uint64_t>(600, "Logging", "Metrics Routine Interval");
        log_metric.init(
            "Logging data",
            ReportIS::AudienceTeam::AGENT_CORE,
            ReportIS::IssuingEngine::AGENT_CORE,
            chrono::seconds(metrics_interval),
            false
        );
        log_metric.registerListener();
    }

    void
    fini()
    {
        streams.clear();
        if (i_mainloop != nullptr && i_mainloop->doesRoutineExist(log_send_routine)) {
            i_mainloop->stop(log_send_routine);
        }
    }

    void
    preload()
    {
        registerConfigPrepareCb([&] () { streams_preperation.clear(); });
        registerConfigLoadCb([&] () {
            streams.clear();
            selectStreams();
            streams = streams_preperation;
        });
        registerConfigAbortCb([&] () {
            streams_preperation.clear();
        });
    }

    bool
    addStream(StreamType type) override
    {
        if (streams_preperation.find(type) != streams_preperation.end()) {
            dbgWarning(D_REPORT)
                << "Cannot add second instance of the same stream. Stream type: "
                << TagAndEnumManagement::convertToString(type);
            return false;
        }
        streams_preperation[type] = makeStream(type);
        dbgInfo(D_REPORT)
            << "Successfully added log stream. Stream type: "
            << TagAndEnumManagement::convertToString(type);
        return true;
    }

    bool
    addStream(
        ReportIS::StreamType type,
        const string &log_server_url,
        const string &_protocol
    ) override
    {
        string log_type = TagAndEnumManagement::convertToString(type);
        if (streams_preperation.find(type) != streams_preperation.end()) {
            dbgWarning(D_REPORT)
                << "Cannot add second instance of the same stream. Stream type: "
                << log_type;
            return false;
        }
        try {
            string ip = log_server_url.substr(0, log_server_url.find(':'));
            string port = log_server_url.substr(log_server_url.find(':') + 1, log_server_url.length());
            int port_num = stoi(port);
            auto protocol = (_protocol == "TCP") ? I_Socket::SocketType::TCP : I_Socket::SocketType::UDP;

            streams_preperation[type] = makeStream(type, ip, port_num, protocol);
            dbgInfo(D_REPORT)
                << "Successfully added log stream. Stream type: "
                << log_type
                << " url: "
                << ip
                << ":"
                << port;
        } catch (const exception &e) {
            dbgWarning(D_REPORT) << "Error in stream configure: " << e.what();
            return false;
        }
        return true;
    }

    bool
    delStream(StreamType type) override
    {
        if (streams.find(type) == streams.end()) {
            dbgWarning(D_REPORT)
                << "Cannot delete stream. Error: Stream does not exist, Stream type: "
                << TagAndEnumManagement::convertToString(type);
            return false;
        }
        streams.erase(type);
        return true;
    }

    void
    sendLog(const Report &log) override
    {
        if (getConf("agent.config.log.useBulkMode", "Enable bulk of logs", true)) {
            reports.setBulkSize(getConfigurationWithDefault<uint>(100, "Logging", "Sent log bulk size"));
            reports.push(log);
            if (reports.sizeQueue() >= 4) {
                auto persistence_only = getConf("agent.config.log.skip.enable", "Enable Log skipping", true);
                sendBufferedLogsImpl(false, persistence_only);
            }
        } else {
            LogEventLogsSent(true).notify();
            for (auto &iter : streams) {
                if (log.isStreamActive(iter.first)) iter.second->sendLog(log);
            }
        }
    }

    uint64_t
    getCurrentLogId() override
    {
        ++log_id;
        return log_id;
    }

    void addGeneralModifier(const GeneralModifier &modifier) override { modifiers.push_back(modifier); }

    pair<bool, string>
    getLoggingModeConfig()
    {
        bool is_bulk_enabled = getConfigurationWithDefault<bool>(
            true,
            "Logging",
            "Enable bulk of logs"
        );
        is_bulk_enabled = getProfileAgentSettingWithDefault<bool>(
            is_bulk_enabled,
            "agent.config.log.useBulkMode"
        );
        static const string default_fog_uri = "/api/v1/agents/events";
        string default_fog_uri_to_use = default_fog_uri;
        if (is_bulk_enabled) default_fog_uri_to_use.append("/bulk");
        string fog_to_use = getConfigurationWithDefault<string>(default_fog_uri_to_use, "Logging", "Fog Log URI");
        return {is_bulk_enabled, fog_to_use};
    }

private:
    void
    sendBufferedLogs()
    {
        while (!reports.empty()) {
            sendBufferedLogsImpl(true, false);
        }
    }

    void
    sendBufferedLogsImpl(bool is_async, bool persistence_only)
    {
        LogEventQueueSize(reports.size()).notify();
        auto batch = reports.pop();
        LogEventLogsSent(false, batch.size()).notify();

        for (auto &modifier : modifiers) {
            modifier(batch);
        }

        // Copy in order to avoid invalidation during sending of logs
        auto local_streams = streams;
        for (auto &iter : local_streams) {
            LogBulkRest sub_batch;
            for (const auto &log : batch) {
                if (log.isStreamActive(iter.first)) sub_batch.push(log);
            }

            if (sub_batch.size()) {
                iter.second->sendLog(sub_batch, persistence_only);
                if (is_async) i_mainloop->yield();
            }
        }
    }

    bool
    getConf(const string &general_setings, const string &configuration, bool default_value)
    {
        bool setting_value = getProfileAgentSettingWithDefault<bool>(default_value, general_setings);
        return getConfigurationWithDefault<bool>(setting_value, "Logging", configuration);
    }

    void
    selectStreams()
    {
        if (getConfiguration<string>("Logging", "Log file name").ok()) {
            addStream(StreamType::JSON_LOG_FILE);
        } else {
            addStream(StreamType::JSON_DEBUG);
        }

        auto agent_mode = Singleton::Consume<I_AgentDetails>::by<LoggingComp>()->getOrchestrationMode();
        if (agent_mode == OrchestrationMode::OFFLINE) {
            dbgInfo(D_REPORT) << "Agent in offline mode, fog stream is no supported";
        } else {
            addStream(StreamType::JSON_FOG);
        }
    }

    shared_ptr<Stream>
    makeStream(StreamType type)
    {
        switch (type) {
            case StreamType::JSON_DEBUG: return make_shared<DebugStream>();
            case StreamType::JSON_FOG: return make_shared<FogStream>();
            case StreamType::JSON_LOG_FILE: return make_shared<LogFileStream>();
            case StreamType::JSON_K8S_SVC: return make_shared<K8sSvcStream>();
            case StreamType::SYSLOG: return nullptr;
            case StreamType::CEF: return nullptr;
            case StreamType::NONE: return nullptr;
            case StreamType::COUNT: return nullptr;
        }
        dbgError(D_REPORT) << "Unknown log stream type";
        return nullptr;
    }

    shared_ptr<Stream>
    makeStream(StreamType type, const string &ip, int port, I_Socket::SocketType protocol)
    {
        switch (type) {
            case StreamType::SYSLOG: return make_shared<SyslogStream>(ip, port, protocol);
            case StreamType::CEF: return make_shared<CefStream>(ip, port, protocol);
            default:
                dbgWarning(D_REPORT) << "Invalid stream type with url";
                return NULL;
        }
        dbgError(D_REPORT) << "Unknown log stream type";
        return nullptr;
    }

    uint64_t log_id = 0;
    map<StreamType, shared_ptr<Stream>> streams;
    map<StreamType, shared_ptr<Stream>> streams_preperation;
    I_MainLoop *i_mainloop;
    ReportsBulk reports;
    I_MainLoop::RoutineID log_send_routine = 0;
    LogMetric log_metric;
    vector<GeneralModifier> modifiers;
};

LoggingComp::LoggingComp() : Component("LoggingComp"), pimpl(make_unique<Impl>()) {}

LoggingComp::~LoggingComp() {}

void
LoggingComp::preload()
{
    registerExpectedConfiguration<bool>("Logging", "Enable event buffer");
    registerExpectedConfiguration<bool>("Logging", "Enable bulk of logs");
    registerExpectedConfiguration<bool>("Logging", "Enable Syslog");
    registerExpectedConfiguration<bool>("Logging", "Enable CEF");
    registerExpectedConfiguration<bool>("Logging", "Enable Log skipping");
    registerExpectedConfiguration<string>("Logging", "Log file name");
    registerExpectedConfiguration<string>("Logging", "Log file line separator");
    registerExpectedConfiguration<string>("Logging", "Fog Log URI");
    registerExpectedConfiguration<string>("Logging", "Syslog IP");
    registerExpectedConfiguration<uint>("Logging", "Syslog port");
    registerExpectedConfiguration<string>("Logging", "CEF IP");
    registerExpectedConfiguration<uint>("Logging", "CEF port");
    registerExpectedConfiguration<uint>("Logging", "Log bulk sending interval in msec");
    registerExpectedConfiguration<uint>("Logging", "Sent log bulk size");
    registerExpectedConfiguration<uint>("Logging", "Maximum number of write retries");
    registerExpectedConfiguration<uint>("Logging", "Metrics Routine Interval");

    pimpl->preload();
}

void
LoggingComp::init()
{
    pimpl->init();
}

void
LoggingComp::fini()
{
    pimpl->fini();
}
