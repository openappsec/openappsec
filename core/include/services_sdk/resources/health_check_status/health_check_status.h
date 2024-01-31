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

#ifndef __HEALTH_CHECK_STATUS_H__
#define __HEALTH_CHECK_STATUS_H__

#include <unordered_map>
#include <map>
#include <string>

#include "event.h"
#include "singleton.h"
#include "debug.h"
#include "cereal/archives/json.hpp"
#include "customized_cereal_map.h"

USE_DEBUG_FLAG(D_HEALTH_CHECK_MANAGER);

enum class HealthCheckStatus {UNHEALTHY, DEGRADED, HEALTHY, IGNORED};

class HealthCheckStatusReply
{
public:
    HealthCheckStatusReply() = delete;

    HealthCheckStatusReply(
        const std::string &_comp_name,
        HealthCheckStatus _status,
        const std::map<std::string, std::string> &_extended_status
    )
            :
        comp_name(_comp_name),
        status(_status),
        extended_status(_extended_status)
    {}

    HealthCheckStatusReply &
    operator=(HealthCheckStatusReply reply)
    {
        std::string reply_name = reply.getCompName();
        HealthCheckStatus reply_status = reply.getStatus();
        std::map<std::string, std::string> reply_extended_status = reply.getExtendedStatus();

        std::swap(comp_name, reply_name);
        std::swap(status, reply_status);
        std::swap(extended_status, reply_extended_status);

        return *this;
    }

    void
    serialize(cereal::JSONOutputArchive &ar) const
    {
        ar(cereal::make_nvp("status", convertHealthCheckStatusToStr(status)));
        ar(cereal::make_nvp("extendedStatus", extended_status));
    }

    const std::string & getCompName() const { return comp_name; }
    HealthCheckStatus getStatus() const { return status; }
    const std::map<std::string, std::string> & getExtendedStatus() const { return extended_status; }

    static std::string
    convertHealthCheckStatusToStr(HealthCheckStatus status)
    {
        switch (status) {
            case HealthCheckStatus::UNHEALTHY : return "Unhealthy";
            case HealthCheckStatus::DEGRADED : return "Degraded";
            case HealthCheckStatus::HEALTHY : return "Healthy";
            case HealthCheckStatus::IGNORED : return "Ignored";
        }

        dbgError(D_HEALTH_CHECK_MANAGER) << "Trying to convert unknown health check status to string.";
        return "";
    }

private:
    std::string comp_name = "";
    HealthCheckStatus status = HealthCheckStatus::IGNORED;
    std::map<std::string, std::string> extended_status = {};
};

class HealthCheckStatusEvent : public Event<HealthCheckStatusEvent, HealthCheckStatusReply>
{
public:
    HealthCheckStatusEvent() {}
    ~HealthCheckStatusEvent() {}
};

#endif // __HEALTH_CHECK_STATUS_H__
