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

#include "WaapConversions.h"
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP);

namespace Waap {
namespace Conversions {
    ThreatLevel convertFinalScoreToThreatLevel(double finalScore)
    {
        if (finalScore == NO_THREAT_FINAL_SCORE)
        {
            return NO_THREAT;
        }
        if (finalScore < INFO_THREAT_THRESHOLD)
        {
            return THREAT_INFO;
        }
        if (finalScore < LOW_THREAT_THRESHOLD)
        {
            return LOW_THREAT;
        }
        if (finalScore < MED_THREAT_THRESHOLD)
        {
            return MEDIUM_THREAT;
        }
        return HIGH_THREAT;
    }

    bool shouldDoWafBlocking(const IWaapConfig* pWaapConfig, ThreatLevel threatLevel)
    {
        if (pWaapConfig == NULL)
        {
            return false;
        }

        if (threatLevel <= THREAT_INFO)
        {
            return false;
        }

        BlockingLevel blockLevel = pWaapConfig->get_BlockingLevel();

        switch (blockLevel)
        {
        case BlockingLevel::LOW_BLOCKING_LEVEL:
            return threatLevel >= HIGH_THREAT;
        case BlockingLevel::MEDIUM_BLOCKING_LEVEL:
            return threatLevel >= MEDIUM_THREAT;
        case BlockingLevel::HIGH_BLOCKING_LEVEL:
            return true;
        case BlockingLevel::NO_BLOCKING:
            return false;
        default:
            dbgDebug(D_WAAP) << "Invalid blocking level in WAAP Config: " << static_cast<std::underlying_type<
                BlockingLevel>::type>(blockLevel);
        }
        return false;
    }
}
}
