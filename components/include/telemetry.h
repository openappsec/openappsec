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
#ifndef __TELEMETRY_H__
#define __TELEMETRY_H__

#include <thread>
#include <time.h>
#include <chrono>
#include "i_mainloop.h"
#include "i_waap_telemetry.h"
#include "i_agent_details.h"
#include "i_logging.h"
#include "logging_comp.h"
#include <map>
#include <set>
#include <unordered_set>
#include "waap.h"
#include "generic_metric.h"

#define LOGGING_INTERVAL_IN_MINUTES 10
USE_DEBUG_FLAG(D_WAAP);
enum class AssetType { API, WEB, ALL, COUNT };

class WaapTelemetryEvent : public Event<WaapTelemetryEvent>
{
public:
    WaapTelemetryEvent(const std::string &_asset_id, const DecisionTelemetryData &_data)
        :
    asset_id(_asset_id),
    data(_data)
    {}

    const DecisionTelemetryData & getData() const { return data; }
    const std::string & getAssetId() const { return asset_id; }

private:
    std::string asset_id;
    DecisionTelemetryData data;
};

class WaapTelemetryBase : public GenericMetric
{
protected:
    virtual void sendLog(const LogRest &metric_client_rest) const override;
};

class WaapTelemetrics : public WaapTelemetryBase
{
public:
    void updateMetrics(const std::string &asset_id, const DecisionTelemetryData &data);
    void initMetrics();

private:
    MetricCalculations::Counter requests{this, "reservedNgenA"};
    MetricCalculations::Counter sources{this, "reservedNgenB"};
    MetricCalculations::Counter force_and_block_exceptions{this, "reservedNgenC"};
    MetricCalculations::Counter waf_blocked{this, "reservedNgenD"};
    MetricCalculations::Counter api_blocked{this, "reservedNgenE"};
    MetricCalculations::Counter bot_blocked{this, "reservedNgenF"};
    MetricCalculations::Counter threat_info{this, "reservedNgenG"};
    MetricCalculations::Counter threat_low{this, "reservedNgenH"};
    MetricCalculations::Counter threat_medium{this, "reservedNgenI"};
    MetricCalculations::Counter threat_high{this, "reservedNgenJ"};
    std::unordered_set<std::string> sources_seen;
};

class WaapTrafficTelemetrics : public WaapTelemetryBase
{
public:
    void updateMetrics(const std::string &asset_id, const DecisionTelemetryData &data);
    void initMetrics();

private:
    MetricCalculations::Counter post_requests{this, "reservedNgenA"};
    MetricCalculations::Counter get_requests{this, "reservedNgenB"};
    MetricCalculations::Counter put_requests{this, "reservedNgenC"};
    MetricCalculations::Counter patch_requests{this, "reservedNgenD"};
    MetricCalculations::Counter delete_requests{this, "reservedNgenE"};
    MetricCalculations::Counter other_requests{this, "reservedNgenF"};
    MetricCalculations::Counter response_2xx{this, "reservedNgenG"};
    MetricCalculations::Counter response_4xx{this, "reservedNgenH"};
    MetricCalculations::Counter response_5xx{this, "reservedNgenI"};
    MetricCalculations::Average<uint64_t> average_latency{this, "reservedNgenJ"};
};

class WaapAttackTypesMetrics : public WaapTelemetryBase
{
public:
    void updateMetrics(const std::string &asset_id, const DecisionTelemetryData &data);
    void initMetrics();

private:
    MetricCalculations::Counter sql_inj{this, "reservedNgenA"};
    MetricCalculations::Counter vulnerability_scan{this, "reservedNgenB"};
    MetricCalculations::Counter path_traversal{this, "reservedNgenC"};
    MetricCalculations::Counter ldap_inj{this, "reservedNgenD"};
    MetricCalculations::Counter evasion_techs{this, "reservedNgenE"};
    MetricCalculations::Counter remote_code_exec{this, "reservedNgenF"};
    MetricCalculations::Counter xml_extern_entity{this, "reservedNgenG"};
    MetricCalculations::Counter cross_site_scripting{this, "reservedNgenH"};
    MetricCalculations::Counter general{this, "reservedNgenI"};
};

class WaapMetricWrapper : public Listener<WaapTelemetryEvent>, Singleton::Consume<I_AgentDetails>
{
public:
    void upon(const WaapTelemetryEvent &event) override;

private:
    std::map<std::string, std::shared_ptr<WaapTelemetrics>> metrics;
    std::map<std::string, std::shared_ptr<WaapTelemetrics>> telemetries;
    std::map<std::string, std::shared_ptr<WaapTrafficTelemetrics>> traffic_telemetries;
    std::map<std::string, std::shared_ptr<WaapAttackTypesMetrics>> attack_types;
    std::map<std::string, std::shared_ptr<WaapAttackTypesMetrics>> attack_types_telemetries;

    template <typename T>
    void initializeTelemetryData(
        const std::string& asset_id,
        const DecisionTelemetryData& data,
        const std::string& telemetryName,
        std::map<std::string, std::shared_ptr<T>>& telemetryMap
    ) {
        if (!telemetryMap.count(asset_id)) {
            dbgTrace(D_WAAP) << "creating telemetry data for asset: " << data.assetName;
            telemetryMap.emplace(asset_id, std::make_shared<T>());
            telemetryMap[asset_id]->init(
                telemetryName,
                ReportIS::AudienceTeam::WAAP,
                ReportIS::IssuingEngine::AGENT_CORE,
                std::chrono::minutes(LOGGING_INTERVAL_IN_MINUTES),
                true,
                ReportIS::Audience::SECURITY,
                false,
                asset_id
            );

            telemetryMap[asset_id]->template registerContext<std::string>(
                "pracitceType",
                std::string("Threat Prevention"),
                EnvKeyAttr::LogSection::SOURCE
            );
            telemetryMap[asset_id]->template registerContext<std::string>(
                "practiceSubType",
                std::string("Web Application"),
                EnvKeyAttr::LogSection::SOURCE
            );
            telemetryMap[asset_id]->registerListener();
        }
        dbgTrace(D_WAAP) << "updating telemetry data for asset: " << data.assetName;

        telemetryMap[asset_id]->template registerContext<std::string>(
            "assetId",
            asset_id,
            EnvKeyAttr::LogSection::SOURCE
        );
        telemetryMap[asset_id]->template registerContext<std::string>(
            "assetName",
            data.assetName,
            EnvKeyAttr::LogSection::SOURCE
        );
        telemetryMap[asset_id]->template registerContext<std::string>(
            "practiceId",
            data.practiceId,
            EnvKeyAttr::LogSection::SOURCE
        );
        telemetryMap[asset_id]->template registerContext<std::string>(
            "practiceName",
            data.practiceName,
            EnvKeyAttr::LogSection::SOURCE
        );
    }
};

class AssetCountEvent : public Event<AssetCountEvent>
{
public:
    AssetCountEvent(AssetType type, const int &asset_count) : asset_type(type), assets_count(asset_count) {};
    const AssetType & getAssetType() const { return asset_type; }
    const int & getAssetCount() const { return assets_count; }
private:
    AssetType asset_type;
    int assets_count;
};

class AssetsMetric : public GenericMetric, Listener<AssetCountEvent>
{
public:
    void upon(const AssetCountEvent &event) override;
private:
    MetricCalculations::LastReportedValue<int> api_assets{this, "numberOfProtectedApiAssetsSample"};
    MetricCalculations::LastReportedValue<int> web_assets{this, "numberOfProtectedWebAppAssetsSample"};
    MetricCalculations::LastReportedValue<int> all_assets{this, "numberOfProtectedAssetsSample"};
};

#endif // __TELEMETRY_H__
