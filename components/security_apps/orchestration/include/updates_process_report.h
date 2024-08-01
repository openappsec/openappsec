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

#ifndef __UPDATES_PROCESS_REPORT_H__
#define __UPDATES_PROCESS_REPORT_H__

#include <sstream>
#include <string>

#include "singleton.h"
#include "i_time_get.h"
#include "updates_process_event.h"

class UpdatesProcessReport : Singleton::Consume<I_TimeGet>
{
public:
    UpdatesProcessReport(
        UpdatesProcessResult result,
        UpdatesConfigType type,
        UpdatesFailureReason reason,
        const std::string &description)
            :
        result(result), type(type), reason(reason), description(description)
    {
        time_stamp = Singleton::Consume<I_TimeGet>::by<UpdatesProcessReport>()->getWalltimeStr();
    }

    std::string
    toString() const
    {
        std::stringstream report;
        report
            << "["
            << time_stamp << "] - "
            << convertUpdateProcessResultToStr(result) << " | "
            << convertUpdatesConfigTypeToStr(type) << " | "
            << convertUpdatesFailureReasonToStr(reason) << " | "
            << description;

        return report.str();
    }

    UpdatesFailureReason getReason() const { return reason; }

private:
    UpdatesProcessResult result;
    UpdatesConfigType type;
    UpdatesFailureReason reason;
    std::string description;
    std::string time_stamp;
};

#endif // __UPDATES_PROCESS_EVENT_H__
