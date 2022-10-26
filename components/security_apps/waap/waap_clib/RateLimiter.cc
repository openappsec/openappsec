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

#include "RateLimiter.h"

namespace Waap {
namespace Util {

RateLimiter::RateLimiter(unsigned events, std::chrono::seconds interval)
:
m_max_events(events),
m_interval(interval),
m_hitsPerSecond(),
m_recentIdx(0),
m_recentHitTime(0),
m_hitsCount(0)
{
    m_hitsPerSecond.resize(interval.count(), 0);
}

void
RateLimiter::clear(const std::chrono::seconds& now)
{
    for (unsigned int i=0; i<m_hitsPerSecond.size(); ++i) {
        m_hitsPerSecond[i] = 0;
    }

    m_recentIdx=0;
    m_recentHitTime = now;
    m_hitsCount = 0;
}

bool
RateLimiter::event(const std::chrono::seconds& now)
{
    if (m_hitsPerSecond.empty()) {
        // Handle the case when rate limiter object is initialized with 0-seconds interval - always pass
        return true;
    }

    // Clear counts buffer on the very first event, of after whole interval passed without events
    if (m_recentHitTime == std::chrono::seconds(0) || now - m_recentHitTime >= m_interval) {
        clear(now);
    }

    while (m_recentHitTime < now) {
        // switch idx to next slot (with wrap since this is circular buffer).
        // since this is circular buffer, the next slot is actually a tail (oldest): wrap --->[HEAD][TAIL]---> wrap
        m_recentIdx++;

        if (m_recentIdx >= m_hitsPerSecond.size()) {
            m_recentIdx = 0;
        }

        // forget the hits from the oldest second in this interval (deduct them from total count)
        m_hitsCount -= m_hitsPerSecond[m_recentIdx];
        m_hitsPerSecond[m_recentIdx] = 0;

        // Update recentHitTime (switch to next second)
        m_recentHitTime += std::chrono::seconds(1);
    }

    // increment hitcount in the most recent second's slot, and also the total count
    m_hitsPerSecond[m_recentIdx]++;
    m_hitsCount++;
    return m_hitsCount <= m_max_events;
}

}
}
