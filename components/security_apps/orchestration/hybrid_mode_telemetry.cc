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

#include "hybrid_mode_telemetry.h"
#include "debug.h"
#include "orchestration_comp.h"
#include "i_shell_cmd.h"
#include <algorithm>

using namespace std;

USE_DEBUG_FLAG(D_ORCHESTRATOR);

static inline string &
trim(string &in)
{
    in.erase(in.begin(), find_if(in.begin(), in.end(), [] (char c) { return !isspace(c); }));
    in.erase(find_if(in.rbegin(), in.rend(), [] (char c) { return !isspace(c); }).base(), in.end());
    return in;
}

void
HybridModeMetric::upon(const HybridModeMetricEvent &)
{
    auto shell_cmd = Singleton::Consume<I_ShellCmd>::by<OrchestrationComp>();
    auto maybe_cmd_output = shell_cmd->getExecOutput(
        getFilesystemPathConfig() + "/watchdog/cp-nano-watchdog --restart_count"
    );

    // get wd process restart count
    if (!maybe_cmd_output.ok()) {
        dbgWarning(D_ORCHESTRATOR)
            << "Watchdog was unable to provide the process restart count. Error: "
            << maybe_cmd_output.getErr();
        return;
    }
    string cmd_output = maybe_cmd_output.unpack();
    trim(cmd_output);
    dbgDebug(D_ORCHESTRATOR) << "Watchdog process counter: " << cmd_output;

    try {
        wd_process_restart.report(stoi(cmd_output));
        dbgDebug(D_ORCHESTRATOR) << "Succesfully reported Watchdog process counter: " << cmd_output;
    } catch (invalid_argument &) {
        dbgWarning(D_ORCHESTRATOR) << "counter value is not a number: " << cmd_output;
    } catch (...) {
        dbgWarning(D_ORCHESTRATOR) << "Reporting counter value failed with unexpected error";
    }
}
