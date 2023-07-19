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

#ifndef __LOG_UTILS_H__
#define __LOG_UTILS_H__

#include <sstream>

#include "log_generator.h"

template <ReportIS::Tags tag>
struct ErrorCode
{
    template <typename CastableToUInt>
    static LogField logError(CastableToUInt val) { return logError(static_cast<uint>(val)); }

    static LogField
    logError(uint val)
    {
        std::stringstream code;
        code << std::setw(3) << std::setfill('0') << static_cast<uint>(tag) << '-' << std::setw(4) << val;
        return LogField("eventCode", code.str());
    }
};

#endif // __LOG_UTILS_H__
