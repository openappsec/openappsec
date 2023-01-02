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

#include "orchestration_policy.h"

using namespace std;
using namespace cereal;

const string &
OrchestrationPolicy::getFogAddress() const
{
    return fog_address;
}

const unsigned long &
OrchestrationPolicy::getSleepInterval() const
{
    return sleep_interval;
}

const unsigned long &
OrchestrationPolicy::getErrorSleepInterval() const
{
    return error_sleep_interval;
}

void
OrchestrationPolicy::serialize(JSONInputArchive &archive)
{
    // Split it, so the order doesn't matter.
    archive(make_nvp("fog-address",             fog_address));
    archive(make_nvp("pulling-interval",          sleep_interval));
    archive(make_nvp("error-pulling-interval",    error_sleep_interval));
}

bool
OrchestrationPolicy::operator==(const OrchestrationPolicy &other) const
{
    return  error_sleep_interval == other.error_sleep_interval &&
            sleep_interval       == other.sleep_interval       &&
            fog_address          == other.fog_address;
}

bool
OrchestrationPolicy::operator!=(const OrchestrationPolicy &other) const
{
    return !((*this) == other);
}
