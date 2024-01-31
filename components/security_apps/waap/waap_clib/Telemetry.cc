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

#include "telemetry.h"
#include "waap.h"
#include "report/report.h"
#include "log_generator.h"
#include "generic_rulebase/triggers_config.h"
#include "config.h"
#include "maybe_res.h"
#include "LogGenWrapper.h"
#include <memory>

USE_DEBUG_FLAG(D_WAAP);

using namespace std;

const static string default_host = "open-appsec-tuning-svc";

void
WaapTelemetryBase::sendLog(const LogRest &metric_client_rest) const
{
    OrchestrationMode mode = Singleton::Consume<I_AgentDetails>::by<GenericMetric>()->getOrchestrationMode();

    GenericMetric::sendLog(metric_client_rest);

    if (mode == OrchestrationMode::ONLINE) {
        return;
    }
    auto svc_host = getConfigurationWithDefault(default_host, "Logging", "K8sSvc Log host");
    string fog_metric_uri = getConfigurationWithDefault<string>("/api/v1/agents/events", "metric", "fogMetricUri");
    MessageMetadata req_md(svc_host, 80);
    req_md.insertHeader(
        "X-Tenant-Id",
        Singleton::Consume<I_AgentDetails>::by<GenericMetric>()->getTenantId()
    );
    Singleton::Consume<I_Messaging>::by<GenericMetric>()->sendSyncMessageWithoutResponse(
        HTTPMethod::POST,
        fog_metric_uri,
        metric_client_rest,
        MessageCategory::METRIC,
        req_md
    );
}

void
WaapTelemetrics::initMetrics()
{
    requests.report(0);
    sources.report(0);
    threat_info.report(0);
    threat_low.report(0);
    threat_medium.report(0);
    threat_high.report(0);
    api_blocked.report(0);
    bot_blocked.report(0);
    waf_blocked.report(0);
    force_and_block_exceptions.report(0);
}
void
WaapTelemetrics::updateMetrics(const string &asset_id, const DecisionTelemetryData &data)
{
    initMetrics();
    requests.report(1);
    if (sources_seen.find(data.source) == sources_seen.end()) {
        if (sources.getCounter() == 0) sources_seen.clear();
        sources_seen.insert(data.source);
        sources.report(1);
    }

    if (data.blockType == WAF_BLOCK || data.blockType == NOT_BLOCKING)
    {
        switch (data.threat)
        {
            case NO_THREAT: {
                break;
            }
            case THREAT_INFO: {
                threat_info.report(1);
                break;
            }
            case LOW_THREAT: {
                threat_low.report(1);
                break;
            }
            case MEDIUM_THREAT: {
                threat_medium.report(1);
                break;
            }
            case HIGH_THREAT: {
                threat_high.report(1);
                break;
            }
            default: {
                dbgWarning(D_WAAP) << "Unexpected Enum value: " << data.threat;
                break;
            }
        }
    }

    switch (data.blockType)
    {
        case API_BLOCK: {
            api_blocked.report(1);
            break;
        }
        case BOT_BLOCK: {
            bot_blocked.report(1);
            break;
        }
        case WAF_BLOCK: {
            waf_blocked.report(1);
            break;
        }
        case FORCE_BLOCK:
        case FORCE_EXCEPTION: {
            force_and_block_exceptions.report(1);
            break;
        }
        case NOT_BLOCKING: {
            break;
        }
        default: {
            dbgWarning(D_WAAP) << "Unexpected Enum value: " << data.blockType;
            break;
        }
    }
}

void
WaapTrafficTelemetrics::initMetrics()
{
    post_requests.report(0);
    get_requests.report(0);
    put_requests.report(0);
    patch_requests.report(0);
    delete_requests.report(0);
    other_requests.report(0);

    response_2xx.report(0);
    response_4xx.report(0);
    response_5xx.report(0);
}

void
WaapTrafficTelemetrics::updateMetrics(const string &asset_id, const DecisionTelemetryData &data)
{
    initMetrics();
    switch (data.method)
    {
        case POST:
            post_requests.report(1);
            break;
        case GET:
            get_requests.report(1);
            break;
        case PUT:
            put_requests.report(1);
            break;
        case PATCH:
            patch_requests.report(1);
            break;
        case DELETE:
            delete_requests.report(1);
            break;
        default:
            other_requests.report(1);
            break;
    }

    if (data.responseCode >= 500) {
        response_5xx.report(1);;
    } else if (data.responseCode >= 400) {
        response_4xx.report(1);
    } else if (data.responseCode >= 200 && data.responseCode < 300) {
        response_2xx.report(1);
    }
}

void
WaapAttackTypesMetrics::initMetrics()
{
    sql_inj.report(0);
    vulnerability_scan.report(0);
    path_traversal.report(0);
    ldap_inj.report(0);
    evasion_techs.report(0);
    remote_code_exec.report(0);
    xml_extern_entity.report(0);
    cross_site_scripting.report(0);
    general.report(0);
}

void
WaapAttackTypesMetrics::updateMetrics(const string &asset_id, const DecisionTelemetryData &data)
{
    if (data.blockType == FORCE_EXCEPTION) {
        dbgInfo(D_WAAP) << "Data block type is FORCE_EXCEPTION, no update needed";
        return;
    }

    if (!data.attackTypes.empty()) initMetrics();

    for (const auto &attackType : data.attackTypes) {
        if (attackType == "SQL Injection") sql_inj.report(1);
        if (attackType == "Vulnerability Scanning") vulnerability_scan.report(1);
        if (attackType == "Path Traversal") path_traversal.report(1);
        if (attackType == "LDAP Injection") ldap_inj.report(1);
        if (attackType == "Evasion Techniques") evasion_techs.report(1);
        if (attackType == "Remote Code Execution") remote_code_exec.report(1);
        if (attackType == "XML External Entity") xml_extern_entity.report(1);
        if (attackType == "Cross Site Scripting") cross_site_scripting.report(1);
        if (attackType == "General") general.report(1);
    }
}

void
WaapMetricWrapper::upon(const WaapTelemetryEvent &event)
{
    const string &asset_id = event.getAssetId();
    const DecisionTelemetryData &data = event.getData();

    dbgTrace(D_WAAP)
        << "Log the decision for telemetry. Asset ID: "
        << asset_id
        << ", Practice ID: "
        << data.practiceId
        << ", Source: "
        << data.source
        << ", Block type: "
        << data.blockType
        << ", Threat level: "
        << data.threat;

    initializeTelemetryData<WaapTelemetrics>(asset_id, data, "WAAP telemetry", telemetries);
    initializeTelemetryData<WaapAttackTypesMetrics>(
        asset_id, data,
        "WAAP attack type telemetry",
        attack_types_telemetries
    );
    initializeTelemetryData<WaapTrafficTelemetrics>(asset_id, data, "WAAP traffic telemetry", traffic_telemetries);

    telemetries[asset_id]->updateMetrics(asset_id, data);
    attack_types_telemetries[asset_id]->updateMetrics(asset_id, data);
    traffic_telemetries[asset_id]->updateMetrics(asset_id, data);

    auto agent_mode = Singleton::Consume<I_AgentDetails>::by<WaapMetricWrapper>()->getOrchestrationMode();
    string tenant_id = Singleton::Consume<I_AgentDetails>::by<WaapMetricWrapper>()->getTenantId();
    if (agent_mode == OrchestrationMode::HYBRID || tenant_id.rfind("org_", 0) == 0) {
        if (!metrics.count(asset_id)) {
            metrics.emplace(asset_id, make_shared<WaapTelemetrics>());
            metrics[asset_id]->init(
                "Waap Metrics",
                ReportIS::AudienceTeam::WAAP,
                ReportIS::IssuingEngine::AGENT_CORE,
                chrono::minutes(LOGGING_INTERVAL_IN_MINUTES),
                true,
                ReportIS::Audience::INTERNAL
            );
            metrics[asset_id]->registerListener();
        }
        if (!attack_types.count(asset_id)) {
            attack_types.emplace(asset_id, make_shared<WaapAttackTypesMetrics>());
            attack_types[asset_id]->init(
                "WAAP Attack Type Metrics",
                ReportIS::AudienceTeam::WAAP,
                ReportIS::IssuingEngine::AGENT_CORE,
                chrono::minutes(LOGGING_INTERVAL_IN_MINUTES),
                true,
                ReportIS::Audience::INTERNAL
            );
            attack_types[asset_id]->registerListener();
        }

        metrics[asset_id]->updateMetrics(asset_id, data);
        attack_types[asset_id]->updateMetrics(asset_id, data);
    }
}

void
AssetsMetric::upon(const AssetCountEvent &event)
{
    int assets_count = event.getAssetCount();

    switch (event.getAssetType()) {
        case AssetType::API: {
            api_assets.report(assets_count);
            break;
        }
        case AssetType::WEB: {
            web_assets.report(assets_count);
            break;
        }
        case AssetType::ALL: {
            all_assets.report(assets_count);
            break;
        }
        default: {
            dbgWarning(D_WAAP) << "Invalid Asset Type was reported";
        }
    }
}
