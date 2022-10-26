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

#include "WaapTrigger.h"
#include "Waf2Util.h"

namespace Waap {
namespace Trigger {

Log::Log()
:
    verbosity("standard"),
    complianceWarnings(true),
    complianceViolations(true),
    acAllow(true),
    acDrop(true),
    tpDetect(true),
    tpPrevent(true),
    webRequests(true),
    webUrlPath(true),
    webUrlQuery(true),
    webHeaders(false),
    webBody(true),
    logToCloud(true),
    logToAgent(true),
    extendLogging(false),
    responseCode(false),
    responseBody(false),
    extendLoggingMinSeverity("")
{
}

bool
Log::operator==(const Log &other) const
{
    return (verbosity == other.verbosity) &&
        (complianceWarnings == other.complianceWarnings) &&
        (complianceViolations == other.complianceViolations) &&
        (acAllow == other.acAllow) &&
        (acDrop == other.acDrop) &&
        (tpDetect == other.tpDetect) &&
        (tpPrevent == other.tpPrevent) &&
        (webRequests == other.webRequests) &&
        (webUrlPath == other.webUrlPath) &&
        (webHeaders == other.webHeaders) &&
        (webUrlQuery == other.webUrlQuery) &&
        (webBody == other.webBody) &&
        (logToCloud == other.logToCloud) &&
        (logToAgent == other.logToAgent);
}

Trigger::Trigger():triggerType("log"), log(std::make_shared<Log>())
{
}

bool
Trigger::operator==(const Trigger &other) const
{
    return  (triggerType == other.triggerType) &&
            (Waap::Util::compareObjects(log, other.log));
}

bool Policy::operator==(const Policy &other) const
{
    return triggers == other.triggers;
}

}
}
