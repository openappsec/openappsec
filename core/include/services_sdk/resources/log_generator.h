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

#ifndef __LOG_GENERATOR_H__
#define __LOG_GENERATOR_H__

#include "i_logging.h"
#include "singleton.h"
#include "report/report.h"
#include "i_time_get.h"
#include "config.h"
#include "i_agent_details.h"
#include "i_environment.h"
#include "flags.h"

class LogGen
        :
    Singleton::Consume<I_Logging>,
    Singleton::Consume<I_TimeGet>,
    Singleton::Consume<I_AgentDetails>,
    Singleton::Consume<I_Environment>
{
public:
    template <typename Trigger, typename ...Args>
    LogGen(
        const Trigger &trigger,
        const std::string &title,
        Args ...args)
            :
        LogGen(trigger(title, std::forward<Args>(args)...))
    {
    }

    template <typename ...Args>
    LogGen(
        const std::string &title,
        const ReportIS::Audience &_audience,
        const ReportIS::Severity &_severity,
        const ReportIS::Priority &_priority,
        Args ...args)
            :
        LogGen(
            title,
            ReportIS::Level::LOG,
            _audience,
            _severity,
            _priority,
            std::forward<Args>(args)...
        )
    {
    }

    template <typename ...Args>
    LogGen(
        const std::string &title,
        const ReportIS::Level &level,
        const ReportIS::Audience &_audience,
        const ReportIS::Severity &_severity,
        const ReportIS::Priority &_priority,
        Args ...args)
            :
        log(
            title,
            getCurrentTime(),
            ReportIS::Type::EVENT,
            level,
            ReportIS::LogLevel::INFO,
            _audience,
            getAudienceTeam(),
            _severity,
            _priority,
            std::chrono::seconds(0),
            LogField("agentId", Singleton::Consume<I_AgentDetails>::by<LogGen>()->getAgentId()),
            std::forward<Args>(args)...
        )
    {
        loadBaseLogFields();
    }

    ~LogGen();

    LogGen & operator<<(const LogField &field);

    template <typename Error>
    LogGen & operator<<(const Maybe<LogField, Error> &field) { log << field; return *this; }

    void addToOrigin(const LogField &field);

    void serialize(cereal::JSONOutputArchive &ar) const;

    ReportIS::AudienceTeam getAudienceTeam() const;

    std::string getLogInsteadOfSending();

private:
    std::chrono::microseconds getCurrentTime() const;
    void loadBaseLogFields();

    Report log;
    bool send_log = true;
};

#endif // __LOG_GENERATOR_H__
