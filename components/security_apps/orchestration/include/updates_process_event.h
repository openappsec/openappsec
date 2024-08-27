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

#ifndef __UPDATES_PROCESS_EVENT_H__
#define __UPDATES_PROCESS_EVENT_H__

#include "event.h"
#include "singleton.h"
#include "config.h"
#include "debug.h"
#include "i_orchestration_status.h"
#include "health_check_status/health_check_status.h"
#include "customized_cereal_map.h"

USE_DEBUG_FLAG(D_UPDATES_PROCESS_REPORTER);

enum class UpdatesFailureReason {
    CHECK_UPDATE,
    REGISTRATION,
    ORCHESTRATION_SELF_UPDATE,
    GET_UPDATE_REQUEST,
    DOWNLOAD_FILE,
    HANDLE_FILE,
    INSTALLATION_QUEUE,
    INSTALL_PACKAGE,
    CHECKSUM_UNMATCHED,
    POLICY_CONFIGURATION,
    POLICY_FOG_CONFIGURATION,
    NONE

};

enum class UpdatesConfigType { MANIFEST, POLICY, SETTINGS, DATA, GENERAL };
enum class UpdatesProcessResult { UNSET, SUCCESS, FAILED, DEGRADED };

static inline std::string
convertUpdatesFailureReasonToStr(UpdatesFailureReason reason)
{
    switch (reason) {
        case UpdatesFailureReason::CHECK_UPDATE : return "CHECK_UPDATE";
        case UpdatesFailureReason::REGISTRATION : return "REGISTRATION";
        case UpdatesFailureReason::ORCHESTRATION_SELF_UPDATE : return "ORCHESTRATION_SELF_UPDATE";
        case UpdatesFailureReason::GET_UPDATE_REQUEST : return "GET_UPDATE_REQUEST";
        case UpdatesFailureReason::DOWNLOAD_FILE : return "DOWNLOAD_FILE";
        case UpdatesFailureReason::HANDLE_FILE : return "HANDLE_FILE";
        case UpdatesFailureReason::INSTALLATION_QUEUE : return "INSTALLATION_QUEUE";
        case UpdatesFailureReason::INSTALL_PACKAGE : return "INSTALL_PACKAGE";
        case UpdatesFailureReason::CHECKSUM_UNMATCHED : return "CHECKSUM_UNMATCHED";
        case UpdatesFailureReason::POLICY_CONFIGURATION : return "POLICY_CONFIGURATION";
        case UpdatesFailureReason::POLICY_FOG_CONFIGURATION : return "POLICY_FOG_CONFIGURATION";
        case UpdatesFailureReason::NONE : return "NONE";
    }

    dbgWarning(D_UPDATES_PROCESS_REPORTER) << "Trying to convert unknown updates failure reason to string.";
    return "";
}

static inline std::string
convertUpdatesConfigTypeToStr(UpdatesConfigType type)
{
    switch (type) {
        case UpdatesConfigType::MANIFEST : return "MANIFEST";
        case UpdatesConfigType::POLICY : return "POLICY";
        case UpdatesConfigType::SETTINGS : return "SETTINGS";
        case UpdatesConfigType::DATA : return "DATA";
        case UpdatesConfigType::GENERAL : return "GENERAL";
    }

    dbgWarning(D_UPDATES_PROCESS_REPORTER) << "Trying to convert unknown updates failure reason to string.";
    return "";
}

static inline std::string
convertUpdateProcessResultToStr(UpdatesProcessResult result)
{
    switch (result) {
        case UpdatesProcessResult::SUCCESS : return "SUCCESS";
        case UpdatesProcessResult::UNSET : return "UNSET";
        case UpdatesProcessResult::FAILED : return "FAILURE";
        case UpdatesProcessResult::DEGRADED : return "DEGRADED";
    }

    dbgWarning(D_UPDATES_PROCESS_REPORTER) << "Trying to convert unknown updates failure reason to string.";
    return "";
}

class UpdatesProcessEvent : public Event<UpdatesProcessEvent>
{
public:
    UpdatesProcessEvent() {}
    UpdatesProcessEvent(
        UpdatesProcessResult _result,
        UpdatesConfigType _type,
        UpdatesFailureReason _reason = UpdatesFailureReason::NONE,
        const std::string &_detail = "",
        const std::string &_description = "");

    ~UpdatesProcessEvent() {}

    UpdatesProcessResult getResult() const { return result; }
    UpdatesConfigType getType() const { return type; }
    UpdatesFailureReason getReason() const { return reason; }
    std::string getDetail() const { return detail; }
    std::string getDescription() const { return description; }

    OrchestrationStatusFieldType getStatusFieldType() const;
    OrchestrationStatusResult getOrchestrationStatusResult() const;

    std::string parseDescription() const;
    std::string getDescriptionWithoutErrors() const;

private:
    UpdatesProcessResult result;
    UpdatesConfigType type;
    UpdatesFailureReason reason;
    std::string detail;
    std::string description;

};

#endif // __UPDATES_PROCESS_EVENT_H__
