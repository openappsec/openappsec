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

#include "health_check_manager.h"

#include <fstream>
#include <map>

#include "health_check_status/health_check_status.h"
#include "i_rest_api.h"
#include "config.h"
#include "cereal/archives/json.hpp"
#include "customized_cereal_map.h"
#include "updates_process_event.h"

using namespace std;

USE_DEBUG_FLAG(D_HEALTH_CHECK_MANAGER);

class HealthCheckOnDemand : public ServerRest, Singleton::Consume<I_Health_Check_Manager>
{
public:
    void
    doCall() override
    {
        string output_path = getProfileAgentSettingWithDefault<string>(
            "/tmp/cpnano_health_check_output.txt",
            "agent.healthCheck.outputTmpFilePath"
        );
        ofstream health_check_output_file;
        health_check_output_file.open(output_path, ofstream::out | ofstream::trunc);

        auto manager = Singleton::Consume<I_Health_Check_Manager>::by<HealthCheckOnDemand>();
        manager->printRepliesHealthStatus(health_check_output_file);

        health_check_output_file.close();
    }
};

class HealthCheckError
{
public:
    HealthCheckError(const string &comp_name, const string &error)
            :
        code_name(comp_name),
        is_internal(true)
    {
        message.push_back(error);
    }

    template<class Archive>
    void
    serialize(Archive &ar)
    {
        ar(
            cereal::make_nvp("code", code_name),
            cereal::make_nvp("message", message),
            cereal::make_nvp("internal", is_internal)
        );
    }

private:
    string code_name;
    bool is_internal;
    vector<string> message;
};

class HealthCheckValue
{
public:
    HealthCheckValue() = default;

    HealthCheckValue(HealthCheckStatus raw_status, const HealthCheckStatusReply &description)
            :
        status(raw_status)
    {
        if (description.getStatus() == HealthCheckStatus::HEALTHY) {
            dbgTrace(D_HEALTH_CHECK_MANAGER)
                << "Ignoring healthy status reply. Comp name: "
                << description.getCompName();
            return;
        }

        for (const auto &extended_status : description.getExtendedStatus()) {
            errors.push_back(
                HealthCheckError(description.getCompName() + " " + extended_status.first,
                extended_status.second
            ));
        }
    }

    template<class Archive>
    void
    serialize(Archive &ar)
    {
        ar(
            cereal::make_nvp("status", HealthCheckStatusReply::convertHealthCheckStatusToStr(status)),
            cereal::make_nvp("errors", errors)
        );
    }

private:
    HealthCheckStatus status = HealthCheckStatus::IGNORED;
    vector<HealthCheckError> errors;
};

class HealthCheckPatch : public ClientRest
{
public:
    HealthCheckPatch(HealthCheckStatus raw_status, const HealthCheckStatusReply &description)
    {
        health_check = HealthCheckValue(raw_status, description);
    }

    C2S_LABEL_PARAM(HealthCheckValue, health_check, "healthCheck");
};

class HealthCheckManager::Impl
        :
    Singleton::Provide<I_Health_Check_Manager>::From<HealthCheckManager>,
    public Listener<UpdatesProcessEvent>
{
public:
    void
    init()
    {
        auto rest = Singleton::Consume<I_RestApi>::by<HealthCheckManager>();
        rest->addRestCall<HealthCheckOnDemand>(RestAction::SHOW, "health-check-on-demand");

        registerListener();
        int interval_in_seconds =
            getProfileAgentSettingWithDefault<int>(30, "agent.healthCheck.intervalInSeconds");

        auto i_mainloop = Singleton::Consume<I_MainLoop>::by<HealthCheckManager>();
        i_mainloop->addRecurringRoutine(
            I_MainLoop::RoutineType::System,
            chrono::seconds(interval_in_seconds),
            [this]() { executeHealthCheck(); },
            "Health check manager periodic check"
        );

        auto is_orch = Singleton::Consume<I_Environment>::by<HealthCheckManager>()->get<bool>("Is Orchestrator");
        should_patch_report = is_orch.ok() && *is_orch;
    }

    HealthCheckStatus
    getAggregatedStatus()
    {
        executeHealthCheck();
        return general_health_aggregated_status;
    }

    void
    printRepliesHealthStatus(ofstream &oputput_file)
    {
        cereal::JSONOutputArchive ar(oputput_file);
        ar(cereal::make_nvp(health_check_reply.getCompName(), health_check_reply));
    }

    void
    upon(const UpdatesProcessEvent &event)
    {

        OrchestrationStatusFieldType status_field_type = event.getStatusFieldType();
        HealthCheckStatus _status = convertResultToHealthCheckStatus(event.getResult());
        string status_field_type_str = convertOrchestrationStatusFieldTypeToStr(status_field_type);

        extended_status[status_field_type_str] =
            _status == HealthCheckStatus::HEALTHY ?
            "Success" :
            event.parseDescription();
        field_types_status[status_field_type_str] = _status;

        switch(_status) {
            case HealthCheckStatus::UNHEALTHY: {
                general_health_aggregated_status = HealthCheckStatus::UNHEALTHY;
                break;
            }
            case HealthCheckStatus::DEGRADED: {
                for (const auto &type_status : field_types_status) {
                    if ((type_status.first != status_field_type_str)
                            && (type_status.second == HealthCheckStatus::UNHEALTHY))
                    {
                        break;
                    }
                }
                general_health_aggregated_status = HealthCheckStatus::DEGRADED;
                break;
            }
            case HealthCheckStatus::HEALTHY: {
                for (const auto &type_status : field_types_status) {
                    if ((type_status.first != status_field_type_str)
                            && (type_status.second == HealthCheckStatus::UNHEALTHY
                                || type_status.second == HealthCheckStatus::DEGRADED)
                        )
                    {
                        break;
                    }
                    general_health_aggregated_status = HealthCheckStatus::HEALTHY;
                }
                break;
            }
            case HealthCheckStatus::IGNORED: {
                break;
            }
        }
        health_check_reply = HealthCheckStatusReply(
            "Orchestration",
            general_health_aggregated_status,
            extended_status
        );
    }

private:
    bool
    sendHealthCheckPatch()
    {
        dbgFlow(D_HEALTH_CHECK_MANAGER) << "Sending a health check patch";

        HealthCheckPatch patch_to_send(general_health_aggregated_status, health_check_reply);
        extended_status.clear();
        field_types_status.clear();
        return Singleton::Consume<I_Messaging>::by<HealthCheckManager>()->sendSyncMessageWithoutResponse(
            HTTPMethod::PATCH,
            "/agents",
            patch_to_send,
            MessageCategory::GENERIC
        );
    }

    void
    executeHealthCheck()
    {
        dbgFlow(D_HEALTH_CHECK_MANAGER) << "Collecting health status from all registered components.";

        dbgTrace(D_HEALTH_CHECK_MANAGER)
            << "Aggregated status: "
            << HealthCheckStatusReply::convertHealthCheckStatusToStr(general_health_aggregated_status);

        if (!should_patch_report) return;

        if (!sendHealthCheckPatch()) {
            dbgWarning(D_HEALTH_CHECK_MANAGER) << "Failed to send periodic health check patch to the fog";
        } else {
            dbgDebug(D_HEALTH_CHECK_MANAGER) << "Successfully sent periodic health check patch to the fog";
        };
    }

    string
    convertOrchestrationStatusFieldTypeToStr(OrchestrationStatusFieldType type)
    {
        switch (type) {
            case OrchestrationStatusFieldType::REGISTRATION : return "Registration";
            case OrchestrationStatusFieldType::MANIFEST : return "Manifest";
            case OrchestrationStatusFieldType::LAST_UPDATE : return "Last Update";
            case OrchestrationStatusFieldType::COUNT : return "Count";
        }

        dbgAssert(false)
            << AlertInfo(AlertTeam::CORE, "orchestration health")
            << "Trying to convert unknown orchestration status field to string.";
        return "";
    }

    HealthCheckStatus
    convertResultToHealthCheckStatus(UpdatesProcessResult result)
    {
        switch (result) {
            case UpdatesProcessResult::SUCCESS : return HealthCheckStatus::HEALTHY;
            case UpdatesProcessResult::UNSET : return HealthCheckStatus::IGNORED;
            case UpdatesProcessResult::FAILED : return HealthCheckStatus::UNHEALTHY;
            case UpdatesProcessResult::DEGRADED : return HealthCheckStatus::DEGRADED;
        }

        dbgAssert(false)
            << AlertInfo(AlertTeam::CORE, "orchestration health")
            << "Trying to convert unknown update process result field to health check status.";
        return HealthCheckStatus::IGNORED;
    }

    HealthCheckStatus general_health_aggregated_status = HealthCheckStatus::HEALTHY;
    HealthCheckStatusReply health_check_reply = HealthCheckStatusReply(
        "Orchestration",
        HealthCheckStatus::HEALTHY,
        {}
    );
    bool should_patch_report;
    map<string, string> extended_status;
    map<string, HealthCheckStatus> field_types_status;
};

HealthCheckManager::HealthCheckManager() : Component("HealthCheckManager"), pimpl(make_unique<Impl>()) {}
HealthCheckManager::~HealthCheckManager() {}

void HealthCheckManager::init() { pimpl->init(); }
