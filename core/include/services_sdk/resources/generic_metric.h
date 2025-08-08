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

#ifndef __GENERIC_METRIC_H__
#define __GENERIC_METRIC_H__

#include <chrono>
#include <vector>
#include <map>

#include "metric/metric_metadata.h"
#include "metric/metric_calc.h"
#include "metric/all_metric_event.h"
#include "i_mainloop.h"
#include "i_time_get.h"
#include "i_agent_details.h"
#include "i_encryptor.h"
#include "i_instance_awareness.h"
#include "i_environment.h"
#include "i_messaging.h"
#include "i_rest_api.h"
#include "report/report_enums.h"
#include "flags.h"

namespace MetricCalculations
{
    class Counter;
    template <typename T> class Max;
    template <typename T> class Min;
    template <typename T> class Average;
    template <typename T> class LastReportedValue;
    template <typename T, uint N> class TopValues;
    template <typename PrintableKey, typename Metric> class MetricMap;
} // MetricCalculations

MetricMetadata::DotName operator"" _dot(const char *, std::size_t);
MetricMetadata::Units operator"" _unit(const char *, std::size_t);
MetricMetadata::Description operator"" _desc(const char *, std::size_t);

class LogRest;

class GenericMetric
        :
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_TimeGet>,
    Singleton::Consume<I_AgentDetails>,
    Singleton::Consume<I_InstanceAwareness>,
    Singleton::Consume<I_Environment>,
    Singleton::Consume<I_Messaging>,
    Singleton::Consume<I_RestApi>,
    Singleton::Consume<I_Encryptor>,
    public Listener<AllMetricEvent>,
    public Listener<MetricScrapeEvent>
{
public:
    enum class Stream { FOG, DEBUG, AIOPS, COUNT };

    void
    init(
        const std::string &_metric_name,
        const ReportIS::AudienceTeam &_team,
        const ReportIS::IssuingEngine &_issuing_engine,
        std::chrono::seconds _report_interval,
        bool _reset,
        ReportIS::Audience _audience = ReportIS::Audience::INTERNAL,
        bool _force_buffering = false,
        const std::string &_asset_id = ""
    );

    template <typename Value>
    void
    registerContext(
        const std::string &key,
        const Value &val,
        EnvKeyAttr::LogSection log_enreachment = EnvKeyAttr::LogSection::NONE)
    {
        ctx.registerValue<Value>(key, val, log_enreachment);
    }

    static void preload();

    static void init();
    static void fini() {}

    static std::string getName() { return "GenericMetric"; }

    std::string generateReport() const;
    void resetMetrics();
    void upon(const AllMetricEvent &) override;
    std::string respond(const AllMetricEvent &event) override;
    std::vector<PrometheusData> respond(const MetricScrapeEvent &event) override;
    std::string getListenerName() const override;

    std::string getMetricName() const;
    std::chrono::seconds getReportInterval() const;

    void turnOnStream(Stream stream) { active_streams.setFlag(stream); }
    void turnOffStream(Stream stream) { active_streams.unsetFlag(stream); }

protected:
    virtual void sendLog(const LogRest &metric_client_rest) const;

private:
    class MetricsRest;

    friend class MetricCalc;
    void addCalc(MetricCalc *calc);

    std::vector<PrometheusData> getPromMetricsData(const std::vector<MetricCalc*> *allowed_calcs = nullptr);

    void handleMetricStreamSending();
    void generateLog();
    void generateDebug();
    void generateAiopsLog();

    I_MainLoop *i_mainloop;
    I_TimeGet *i_time;
    std::string metric_name;
    ReportIS::AudienceTeam team;
    ReportIS::IssuingEngine issuing_engine;
    ReportIS::Audience audience;
    std::chrono::seconds report_interval;
    std::vector<MetricCalc *> calcs;
    std::vector<MetricCalc *> prometheus_calcs;
    Flags<Stream> active_streams;
    bool reset;
    bool force_buffering = false;
    Context ctx;
    std::string asset_id;
};

#include "metric/counter.h"
#include "metric/no_reset_counter.h"
#include "metric/max.h"
#include "metric/min.h"
#include "metric/average.h"
#include "metric/top_values.h"
#include "metric/last_reported_value.h"
#include "metric/metric_map.h"

#endif // __GENERIC_METRIC_H__
