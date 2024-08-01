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
            report_failure_count = 0;
            return;
        }
        dbgTrace(D_UPDATES_PROCESS_REPORTER) << "Update proccess finished with errors";
        report_failure_count++;
        if (report_failure_count <= 1) {
            reports.clear();
            return;
        }
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
    stringstream full_reports;
    UpdatesFailureReason failure_reason = UpdatesFailureReason::NONE;
    full_reports << "Updates process reports:" << endl;
    full_reports << "report failure count:" << report_failure_count << endl;
    for (const auto &report : reports) {
        if (report.getReason() != UpdatesFailureReason::CHECK_UPDATE) {
            failure_reason = report.getReason();
        }
        full_reports << report.toString() << endl;
    }
    reports.clear();
    dbgTrace(D_UPDATES_PROCESS_REPORTER) << "Sending updates process report: " << endl << full_reports.str();
    LogGen log (
        "Updates process report",
        ReportIS::Audience::INTERNAL,
        ReportIS::Severity::HIGH,
        ReportIS::Priority::HIGH,
        ReportIS::Tags::ORCHESTRATOR
    );
    log << LogField("eventMessage", full_reports.str());
    if (failure_reason != UpdatesFailureReason::NONE) {
        log.addToOrigin(LogField("eventCategory", convertUpdatesFailureReasonToStr(failure_reason)));
    }
}
