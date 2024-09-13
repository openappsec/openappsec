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

#ifndef __UPDATES_PROCESS_REPORTER_H__
#define __UPDATES_PROCESS_REPORTER_H__

#include <string>

#include "event.h"
#include "singleton.h"
#include "config.h"
#include "debug.h"
#include "i_orchestration_status.h"
#include "i_service_controller.h"
#include "health_check_status/health_check_status.h"
#include "updates_process_event.h"
#include "updates_process_report.h"

class UpdatesProcessReporter
        :
    public Listener<UpdatesProcessEvent>,
    Singleton::Consume<I_ServiceController>
{
public:
    void upon(const UpdatesProcessEvent &event) override;

private:
    void sendReoprt(const std::string &version);

    static std::vector<UpdatesProcessReport> reports;
    std::map<std::string, uint> report_failure_count_map;
};

#endif // __UPDATES_PROCESS_REPORTER_H__
