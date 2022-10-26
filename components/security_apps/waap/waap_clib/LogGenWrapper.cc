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

#include "LogGenWrapper.h"
#include "log_generator.h"
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP);

LogGenWrapper::LogGenWrapper(
        const Maybe<LogTriggerConf, Config::Errors>& maybe_trigger,
        const std::string& title,
        const ReportIS::Audience& audience,
        const LogTriggerConf::SecurityType& security_type,
        const ReportIS::Severity& severity,
        const ReportIS::Priority& priority,
        bool is_action_drop_or_prevent) : m_log_gen(nullptr)
{
    if (!maybe_trigger.ok()) {
        dbgWarning(D_WAAP) << "Couldn't get log trigger from the I/S. " <<
            "Continuing with waap log trigger policy..." <<
            "Reason: " << maybe_trigger.getErr();
        m_log_gen = std::make_unique<LogGen>(
            title,
            audience,
            severity,
            priority,
            ReportIS::Tags::WAF,
            ReportIS::Tags::THREAT_PREVENTION
            );
    }
    else {
        m_log_gen = std::make_unique<LogGen>(
            maybe_trigger.unpack(),
            title,
            security_type,
            severity,
            priority,
            is_action_drop_or_prevent,
            ReportIS::Tags::WAF,
            ReportIS::Tags::THREAT_PREVENTION
            );
    }
}

LogGenWrapper::~LogGenWrapper()
{
}

LogGen& LogGenWrapper::getLogGen()
{
    return *m_log_gen;
}
