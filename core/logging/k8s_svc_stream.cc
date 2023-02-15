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

const static string default_host = "open-appsec-tuning-svc";
const static string default_bulk_uri = "/api/v1/agents/events/bulk";
const static string default_log_uri = "/api/v1/agents/events";

USE_DEBUG_FLAG(D_REPORT);

K8sSvcStream::K8sSvcStream()
        :
    i_msg(Singleton::Consume<I_Messaging>::by<LoggingComp>())
{
}

K8sSvcStream::~K8sSvcStream()
{
}

string
K8sSvcStream::genHeader()
{
    return "X-Tenant-Id: " + Singleton::Consume<I_AgentDetails>::by<LoggingComp>()->getTenantId();
}

void
K8sSvcStream::sendLog(const Report &log)
{
    auto svc_host = getConfigurationWithDefault(default_host, "Logging", "K8sSvc Log host");
    auto K8sSvc_log_uri = getConfigurationWithDefault(default_log_uri, "Logging", "K8sSvc Log URI");
    LogRest rest(log);
    Flags<MessageConnConfig> conn_flags;
    conn_flags.setFlag(MessageConnConfig::EXTERNAL);

    bool ok = i_msg->sendNoReplyObject(
        rest,
        I_Messaging::Method::POST,
        svc_host,
        80,
        conn_flags,
        K8sSvc_log_uri,
        genHeader(),
        nullptr,
        MessageTypeTag::LOG
    );

    if (!ok) {
        dbgWarning(D_REPORT) << "failed to send log";
    }
}

void
K8sSvcStream::sendLog(const LogBulkRest &logs, bool persistence_only)
{
    dbgFlow(D_REPORT) << "send bulk logs";

    if (persistence_only) {
        dbgWarning(D_REPORT) << "Skipping logs due to persistence only setting";
        return;
    }

    auto svc_host = getConfigurationWithDefault(default_host, "Logging", "K8sSvc Log host");
    auto K8sSvc_log_uri = getConfigurationWithDefault(default_bulk_uri, "Logging", "K8sSvc Bulk Log URI");
    Flags<MessageConnConfig> conn_flags;
    conn_flags.setFlag(MessageConnConfig::EXTERNAL);

    bool ok = i_msg->sendNoReplyObject(
        logs,
        I_Messaging::Method::POST,
        svc_host,
        80,
        conn_flags,
        K8sSvc_log_uri,
        genHeader(),
        nullptr,
        MessageTypeTag::LOG
    );

    if (!ok) {
        dbgWarning(D_REPORT) << "failed to send bulk logs";
    }
}
