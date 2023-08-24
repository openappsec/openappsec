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

    HealthCheckValue(HealthCheckStatus raw_status, const map<string, HealthCheckStatusReply> &descriptions)
            :
        status(raw_status)
    {
        for (const auto &single_stat : descriptions) {
            if (single_stat.second.getStatus() == HealthCheckStatus::HEALTHY) {
                dbgTrace(D_HEALTH_CHECK_MANAGER) << "Ignoring healthy status reply. Comp name: " << single_stat.first;
                continue;
            }

            for (const auto &status : single_stat.second.getExtendedStatus()) {
                errors.push_back(HealthCheckError(single_stat.first + " " + status.first, status.second));
            }
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
    HealthCheckPatch(HealthCheckStatus raw_status, const map<string, HealthCheckStatusReply> &descriptions)
    {
        health_check = HealthCheckValue(raw_status, descriptions);
    }

    C2S_LABEL_PARAM(HealthCheckValue, health_check, "healthCheck");
};

class HealthCheckManager::Impl
        :
    Singleton::Provide<I_Health_Check_Manager>::From<HealthCheckManager>
{
public:
    void
    init()
    {
        auto rest = Singleton::Consume<I_RestApi>::by<HealthCheckManager>();
        rest->addRestCall<HealthCheckOnDemand>(RestAction::SHOW, "health-check-on-demand");

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
        getRegisteredComponentsHealthStatus();
        cereal::JSONOutputArchive ar(oputput_file);
        ar(cereal::make_nvp("allComponentsHealthCheckReplies", all_comps_health_status));
    }

private:
    bool
    sendHealthCheckPatch()
    {
        dbgFlow(D_HEALTH_CHECK_MANAGER);

        HealthCheckPatch patch_to_send(general_health_aggregated_status, all_comps_health_status);
        auto messaging = Singleton::Consume<I_Messaging>::by<HealthCheckManager>();
        return messaging->sendNoReplyObject(patch_to_send, I_Messaging::Method::PATCH, "/agents");
    }

    void
    getRegisteredComponentsHealthStatus()
    {
        vector<HealthCheckStatusReply> health_check_event_reply = HealthCheckStatusEvent().query();
        all_comps_health_status.clear();
        for (const auto &reply : health_check_event_reply) {
            if (reply.getStatus() != HealthCheckStatus::IGNORED) {
                all_comps_health_status.emplace(reply.getCompName(), reply);
            }
        }
    }

    void
    calcGeneralHealthAggregatedStatus()
    {
        general_health_aggregated_status = HealthCheckStatus::HEALTHY;

        for (const auto &reply : all_comps_health_status) {
            HealthCheckStatus status = reply.second.getStatus();

            dbgTrace(D_HEALTH_CHECK_MANAGER)
                << "Current aggregated status is: "
                << HealthCheckStatusReply::convertHealthCheckStatusToStr(
                        general_health_aggregated_status
                    )
                << ". Got health status: "
                << HealthCheckStatusReply::convertHealthCheckStatusToStr(status)
                << "for component: "
                << reply.first;

            switch (status) {
                case HealthCheckStatus::UNHEALTHY : {
                    general_health_aggregated_status = HealthCheckStatus::UNHEALTHY;
                    return;
                }
                case HealthCheckStatus::DEGRADED : {
                    general_health_aggregated_status = HealthCheckStatus::DEGRADED;
                    break;
                }
                case HealthCheckStatus::IGNORED : break;
                case HealthCheckStatus::HEALTHY : break;
            }
        }
    }

    void
    executeHealthCheck()
    {
        dbgFlow(D_HEALTH_CHECK_MANAGER) << "Collecting health status from all registered components.";

        getRegisteredComponentsHealthStatus();
        calcGeneralHealthAggregatedStatus();

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

    HealthCheckStatus general_health_aggregated_status;
    map<string, HealthCheckStatusReply> all_comps_health_status;
    bool should_patch_report;
};

HealthCheckManager::HealthCheckManager() : Component("HealthCheckManager"), pimpl(make_unique<Impl>()) {}
HealthCheckManager::~HealthCheckManager() {}

void HealthCheckManager::init() { pimpl->init(); }
