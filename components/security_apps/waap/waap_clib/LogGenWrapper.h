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

#ifndef __LOG_GEN_WRAPPER_H__
#define __LOG_GEN_WRAPPER_H__

#include "report/report_enums.h"
#include "maybe_res.h"
#include "config.h"
#include "generic_rulebase/triggers_config.h"
#include <string>
#include <memory>

class LogTriggerConf;
class LogGen;

class LogGenWrapper
{
public:
    LogGenWrapper(
        const Maybe<LogTriggerConf, Config::Errors>& maybe_trigger,
        const std::string& title,
        const ReportIS::Audience& audience,
        const LogTriggerConf::SecurityType& security_type,
        const ReportIS::Severity& severity,
        const ReportIS::Priority& priority,
        bool is_action_drop_or_prevent);
    ~LogGenWrapper();

    LogGen& getLogGen();

private:
    std::unique_ptr<LogGen> m_log_gen;
};

#endif
