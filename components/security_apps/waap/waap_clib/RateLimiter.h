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

#pragma once
#include <chrono>
#include <vector>

namespace Waap {
namespace Util {

// Simple rate limiter primitive that collects events() and only allows up to X events per Y seconds.
// For each event, call RateLimiter::event() passing real or simulated timestamp (in seconds).
// The returned boolean value will tell the caller whether this event must pass (true) or be blocked (false).

class RateLimiter {
public:
    RateLimiter(unsigned int events, std::chrono::seconds interval);
    void clear(const std::chrono::seconds& now);
    bool event(const std::chrono::seconds& now);

private:

    unsigned m_max_events; // max events allowed during the recent interval window
    std::chrono::seconds m_interval; // configured interval window
    std::vector<unsigned> m_hitsPerSecond; // array of hitcounts per second (remembers up to interval recent seconds)
    unsigned m_recentIdx;  // index of recent second
    std::chrono::seconds m_recentHitTime; // timestamp of recent second
    unsigned m_hitsCount; // total events during last interval seconds (rolling update)
};

}
}
