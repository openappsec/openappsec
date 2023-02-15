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

#include "report_messaging.h"

#include <string>

#include "report/log_rest.h"

using namespace std;

static const string url = "/api/v1/agents/events";

ReportMessaging::~ReportMessaging()
{
    if (!Singleton::exists<I_Messaging>()) return;

    LogRest log_rest(report);

    auto messaging = Singleton::Consume<I_Messaging>::by<ReportMessaging>();
    try {
        messaging->sendObjectWithPersistence(
            log_rest,
            I_Messaging::Method::POST,
            url,
            "",
            true,
            message_type_tag,
            is_async_message
        );
    } catch (...) {
    }
}

ReportMessaging &
ReportMessaging::operator<<(const LogField &field)
{
    report << field;
    return *this;
}
