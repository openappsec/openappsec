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

#include "updates_process_event.h"

#include <sstream>
#include <string>

#include "debug.h"

using namespace std;

USE_DEBUG_FLAG(D_UPDATES_PROCESS_REPORTER);

UpdatesProcessEvent::UpdatesProcessEvent(
    UpdatesProcessResult _result,
    UpdatesConfigType _type,
    UpdatesFailureReason _reason,
    const std::string &_detail,
    const std::string &_description)
        :
    result(_result),
    type(_type),
    reason(_reason),
    detail(_detail),
    description(_description)
{
    string report =
        "Result: " + convertUpdateProcessResultToStr(result) +
        ", Reason: " + convertUpdatesFailureReasonToStr(reason) +
        ", Type: " + convertUpdatesConfigTypeToStr(type) +
        ", Detail: " + detail +
        ", Description: " + description;
    dbgTrace(D_UPDATES_PROCESS_REPORTER) << "Updates process event: " << report;
}

OrchestrationStatusFieldType
UpdatesProcessEvent::getStatusFieldType() const
{
    if (reason == UpdatesFailureReason::REGISTRATION) {
        return OrchestrationStatusFieldType::REGISTRATION;
    }
    if (type == UpdatesConfigType::MANIFEST) {
        return  OrchestrationStatusFieldType::MANIFEST;
    }
    return OrchestrationStatusFieldType::LAST_UPDATE;
}

OrchestrationStatusResult
UpdatesProcessEvent::getOrchestrationStatusResult() const
{
    return result == UpdatesProcessResult::SUCCESS ?
        OrchestrationStatusResult::SUCCESS :
        OrchestrationStatusResult::FAILED;
}

string
UpdatesProcessEvent::parseDescription() const
{
    stringstream err;
    if (description.empty() || result == UpdatesProcessResult::SUCCESS) return "";

    switch (reason) {
        case UpdatesFailureReason::CHECK_UPDATE: {
            err << description;
            break;
        }
        case UpdatesFailureReason::REGISTRATION: {
            err << "Registration failed. Error: " << description;
            break;
        }
        case UpdatesFailureReason::GET_UPDATE_REQUEST: {
            err << "Failed to get update request. Error: " << description;
            break;
        }
        case UpdatesFailureReason::DOWNLOAD_FILE : {
            err << "Failed to download the file " << detail << ". Error: " << description;
            break;
        }
        case UpdatesFailureReason::HANDLE_FILE : {
            err << "Failed to handle the file " << detail << ". " << description;
            break;
        }
        case UpdatesFailureReason::INSTALLATION_QUEUE : {
            err << "Installation queue creation failed. Error: " << description;
            break;
        }
        case UpdatesFailureReason::INSTALL_PACKAGE : {
            err << "Failed to install the package " << detail << ". Error: " << description;
            break;
        }
        case UpdatesFailureReason::CHECKSUM_UNMATCHED : {
            err << "Checksums do not match for the file: " << detail << ". " << description;
            break;
        }
        case UpdatesFailureReason::POLICY_CONFIGURATION : {
            err << "Failed to configure policy version: " << detail << ". Error: " << description;
            break;
        }
        case UpdatesFailureReason::POLICY_FOG_CONFIGURATION : {
            err << "Failed to configure the fog address: " << detail << ". Error: " << description;
            break;
        }
        case UpdatesFailureReason::SERVISE_CONFIGURATION : {
            err
                << "Request for service reconfiguration failed to complete. Service name: "
                << detail
                << ". Error: "
                << description;
            break;
        }
        case UpdatesFailureReason::SERVISE_CONFIGURATION_TIMEOUT : {
            err << detail;
            break;
        }
        case UpdatesFailureReason::ORCHESTRATION_SELF_UPDATE : {
            err << description;
            break;
        }
        case UpdatesFailureReason::NONE : {
            err << description;
            break;
        }
    }
    return err.str();
}

string
UpdatesProcessEvent::getDescriptionWithoutErrors() const
{
    stringstream err;
    if (description.empty() || result == UpdatesProcessResult::SUCCESS) return "";

    switch (reason) {
        case UpdatesFailureReason::CHECK_UPDATE: {
            err << description;
            break;
        }
        case UpdatesFailureReason::REGISTRATION: {
            err << "Registration failed.";
            break;
        }
        case UpdatesFailureReason::GET_UPDATE_REQUEST: {
            err << "Failed to get update request.";
            break;
        }
        case UpdatesFailureReason::DOWNLOAD_FILE : {
            err << "Failed to download the file " << detail;
            break;
        }
        case UpdatesFailureReason::HANDLE_FILE : {
            err << "Failed to handle the file " << detail;
            break;
        }
        case UpdatesFailureReason::INSTALLATION_QUEUE : {
            err << "Installation queue creation failed.";
            break;
        }
        case UpdatesFailureReason::INSTALL_PACKAGE : {
            err << "Failed to install the package " << detail;
            break;
        }
        case UpdatesFailureReason::CHECKSUM_UNMATCHED : {
            err << "Checksums do not match for the file: " << detail;
            break;
        }
        case UpdatesFailureReason::POLICY_CONFIGURATION : {
            err << "Failed to configure policy version: " << detail;
            break;
        }
        case UpdatesFailureReason::POLICY_FOG_CONFIGURATION : {
            err << "Failed to configure the fog address: " << detail;
            break;
        }
        case UpdatesFailureReason::SERVISE_CONFIGURATION : {
            err << "Request for service reconfiguration failed to complete. Service name: " << detail;
            break;
        }
        case UpdatesFailureReason::SERVISE_CONFIGURATION_TIMEOUT : {
            err << detail;
            break;
        }
        case UpdatesFailureReason::ORCHESTRATION_SELF_UPDATE : {
            err << description;
            break;
        }
        case UpdatesFailureReason::NONE : {
            err << description;
            break;
        }
    }
    return err.str();
}
