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

#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <unistd.h>

#include "time_proxy.h"
#include "shell_cmd.h"
#include "debug.h"
#include "config.h"
#include "config_component.h"
#include "orchestration_comp.h"
#include "mainloop.h"
#include "version.h"
#include "signal_handler.h"
#include "environment.h"
#include "rest_server.h"
#include "logging_comp.h"
#include "rest.h"
#include "proto_message_comp.h"
#include "encryptor.h"
#include "downloader.h"
#include "orchestration_tools.h"
#include "service_controller.h"
#include "manifest_controller.h"
#include "package_handler.h"
#include "update_communication.h"
#include "orchestration_status.h"
#include "details_resolver.h"
#include "agent_details.h"
#include "signal_handler.h"
#include "cpu.h"
#include "memory_consumption.h"
#include "messaging_buffer.h"
#include "agent_details_reporter.h"
#include "instance_awareness.h"
#include "socket_is.h"
#include "health_checker.h"
#include "health_check_manager.h"
#include "generic_metric.h"
#include "tenant_manager.h"
#include "local_policy_mgmt_gen.h"

using namespace std;

#include "components_list.h"

int
main(int argc, char **argv)
{
    NodeComponents<
        OrchestrationStatus,
        OrchestrationTools,
        PackageHandler,
        Downloader,
        ServiceController,
        ManifestController,
        UpdateCommunication,
        AgentDetailsReporter,
        DetailsResolver,
        OrchestrationComp,
        HealthChecker,
        HealthCheckManager,
        LocalPolicyMgmtGenerator
    > comps;

    comps.registerGlobalValue<uint>("Nano service API Port Primary", 7777);
    comps.registerGlobalValue<uint>("Nano service API Port Alternative", 7778);
    comps.registerGlobalValue<string>("Tenant manager type", "server");

    return comps.run("Orchestration", argc, argv);
}
