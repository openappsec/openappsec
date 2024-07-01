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

#include "updates_process_reporter.h"

#include <sstream>
#include <string>

#include "debug.h"
#include "log_generator.h"

using namespace std;

USE_DEBUG_FLAG(D_UPDATES_PROCESS_REPORTER);

vector<UpdatesProcessReport> UpdatesProcessReporter::reports;

void
UpdatesProcessReporter::upon(const UpdatesProcessEvent &event)
{
    if (event.getReason() == UpdatesFailureReason::CHECK_UPDATE) {
        if (event.getResult() == UpdatesProcessResult::SUCCESS && reports.empty()) {
            dbgTrace(D_UPDATES_PROCESS_REPORTER) << "Update proccess finished successfully";
            return;
        }
        dbgTrace(D_UPDATES_PROCESS_REPORTER) << "Update proccess finished with errors";
        reports.emplace_back(
            UpdatesProcessReport(
                event.getResult(),
                event.getType(),
                event.getReason(),
                event.parseDescription()
            )
        );
        sendReoprt();
        return;
    }
    if (event.getResult() == UpdatesProcessResult::SUCCESS || event.getResult() == UpdatesProcessResult::UNSET) return;
    reports.emplace_back(
        UpdatesProcessReport(event.getResult(), event.getType(), event.getReason(), event.parseDescription())
    );
}

void
UpdatesProcessReporter::sendReoprt()
{
    stringstream all_reports;
    all_reports << "Updates process reports:" << endl;
    for (const auto &report : reports) {
        all_reports << report.toString() << endl;
    }
    reports.clear();
    dbgTrace(D_UPDATES_PROCESS_REPORTER) << "Sending updates process report: " << endl << all_reports.str();
    LogGen(
        "Updates process report",
        ReportIS::Audience::INTERNAL,
        ReportIS::Severity::HIGH,
        ReportIS::Priority::HIGH,
        ReportIS::Tags::ORCHESTRATOR
    ) << LogField("eventMessage", all_reports.str());
}
