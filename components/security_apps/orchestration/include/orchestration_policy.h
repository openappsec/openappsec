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

#ifndef __ORCHESTRATION_POLICY_H__
#define __ORCHESTRATION_POLICY_H__

#include <string>
#include "cereal/archives/json.hpp"

class OrchestrationPolicy
{
public:
    const std::string & getFogAddress() const;
    const unsigned long & getSleepInterval() const;
    const unsigned long & getErrorSleepInterval() const;

    void serialize(cereal::JSONInputArchive & archive);

    bool operator==(const OrchestrationPolicy &other) const;
    bool operator!=(const OrchestrationPolicy &other) const;

private:
    std::string fog_address;
    unsigned long sleep_interval;
    unsigned long error_sleep_interval;
};

#endif // __ORCHESTRATION_POLICY_H__
