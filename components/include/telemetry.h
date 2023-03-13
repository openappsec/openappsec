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
    std::map<std::string, std::shared_ptr<WaapAttackTypesMetrics>> attack_types;
    std::map<std::string, std::shared_ptr<WaapAttackTypesMetrics>> attack_types_telemetries;
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
