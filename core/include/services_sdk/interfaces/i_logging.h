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

#ifndef __I_LOGGING_H__
#define __I_LOGGING_H__

#include <functional>

#include "report/report.h"
#include "report/log_rest.h"

class I_Logging
{
public:
    using GeneralModifier = std::function<void(LogBulkRest &)>;

    virtual bool addStream(ReportIS::StreamType type) = 0;
    virtual bool addStream(
        ReportIS::StreamType type,
        const std::string &log_server_url,
        const std::string &protocol
    ) = 0;
    virtual bool delStream(ReportIS::StreamType type) = 0;

    virtual void sendLog(const Report &msg) = 0;

    virtual uint64_t getCurrentLogId() = 0;

    virtual void addGeneralModifier(const GeneralModifier &modifier) = 0;

protected:
    virtual ~I_Logging() {}
};

#endif // __I_LOGGING_H__
