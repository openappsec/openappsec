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

#include "log_streams.h"
#include "logging_comp.h"

using namespace std;
using namespace cereal;

USE_DEBUG_FLAG(D_REPORT);

FogStream::FogStream()
        :
    i_msg(Singleton::Consume<I_Messaging>::by<LoggingComp>())
{
}

FogStream::~FogStream()
{
}

void
FogStream::sendLog(const Report &log)
{
    auto fog_log_uri = getConfigurationWithDefault<string>("/api/v1/agents/events", "Logging", "Fog Log URI");

    ScopedContext ctx;
    ctx.registerValue<bool>("Obfuscate log field", true);

    LogRest rest(log);
    i_msg->sendObjectWithPersistence(rest, I_Messaging::Method::POST, fog_log_uri, "", true, MessageTypeTag::LOG);
}

void
FogStream::sendLog(const LogBulkRest &logs, bool persistence_only)
{
    ScopedContext ctx;
    ctx.registerValue<bool>("Obfuscate log field", true);

    auto fog_log_uri = getConfigurationWithDefault<string>("/api/v1/agents/events/bulk", "Logging", "Fog Log URI");
    if (!persistence_only) {
        i_msg->sendObjectWithPersistence(logs, I_Messaging::Method::POST, fog_log_uri, "", true, MessageTypeTag::LOG);
    } else {
        i_msg->sendObjectWithPersistence(
            logs,
            I_Messaging::Method::POST,
            fog_log_uri,
            "",
            false,
            MessageTypeTag::LOG,
            true
        );
    }
}
