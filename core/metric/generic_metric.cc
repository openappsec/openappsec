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

#include "generic_metric.h"

#include "i_rest_api.h"
#include "debug.h"
#include "report/log_rest.h"
#include "config.h"

#include <fstream>
#include <sstream>

using namespace std;
using namespace ReportIS;

USE_DEBUG_FLAG(D_METRICS);

MetricCalc::MetricCalc(GenericMetric *metric, const string &title) : calc_title(title)
{
    // Only top level metric should add themselves to the metric. Nested metrics will be served by their parent.
    if (metric != nullptr) metric->addCalc(this);
}

static const string metric_file = "/tmp/metrics_output.txt";

class GenericMetric::MetricsRest : public ServerRest
{
public:
    void
    doCall() override
    {
        string output_path = getConfigurationWithDefault(metric_file, "metric", "metricsOutputTmpFile");
        fstream metric_output_file;
        metric_output_file.open(output_path, ofstream::out | ofstream::trunc);
        auto res = AllMetricEvent().query();
        for (const auto &metric : res) {
            metric_output_file << metric << endl;
        }
        metric_output_file.close();
    }
};

void
GenericMetric::init()
{
    auto rest = Singleton::Consume<I_RestApi>::by<GenericMetric>();
    rest->addRestCall<MetricsRest>(RestAction::SHOW, "metrics");
}

void
GenericMetric::init(
    const string &_metric_name,
    const ReportIS::AudienceTeam &_team,
    const ReportIS::IssuingEngine &_issuing_engine,
    chrono::seconds _report_interval,
    bool _reset,
    Audience _audience
)
{
    i_mainloop = Singleton::Consume<I_MainLoop>::by<GenericMetric>();
    i_time = Singleton::Consume<I_TimeGet>::by<GenericMetric>();
    metric_name = _metric_name;
    report_interval = _report_interval;
    reset = _reset;
    team = _team;
    issuing_engine = _issuing_engine;
    audience = _audience;

    i_mainloop->addRecurringRoutine(
        I_MainLoop::RoutineType::System,
        report_interval,
        [this] ()
        {
            ctx.activate();
            handleMetricStreamSending();
            ctx.deactivate();
        },
        "Metric Fog stream messaging for " + _metric_name
    );
}

void
GenericMetric::handleMetricStreamSending()
{
    auto metric_debug = getConfigurationWithDefault<bool>(true, "metric", "debugMetricSendEnable");
    auto report_str = generateReport(false);
    if (!report_str.empty() && metric_debug) {
        dbgTrace(D_METRICS) << report_str;
    }

    auto metric_fog = getConfigurationWithDefault<bool>(true, "metric", "fogMetricSendEnable");
    if (!report_str.empty() && metric_fog) {
        generateLog();
    }

    if (reset) {
        for(auto &calc : calcs) {
            calc->reset();
        }
    }
}

string
GenericMetric::getMetricName() const
{
    return metric_name;
}

chrono::seconds
GenericMetric::getReportInterval() const
{
    return report_interval;
}

string
GenericMetric::generateReport(bool with_reset)
{
    stringstream ss;
    bool any_reported_calc = false;

    {
        cereal::JSONOutputArchive ar(ss);
        ar(cereal::make_nvp("Metric", metric_name));
        ar(cereal::make_nvp("Reporting interval", report_interval.count()));
        for(auto &calc : calcs) {
            if (calc->wasOnceReported()) {
                calc->save(ar);
                if (with_reset) calc->reset();
                any_reported_calc = true;
            }
        }
    }
    return any_reported_calc ? ss.str() : "";
}

void
GenericMetric::addCalc(MetricCalc *calc)
{
    calcs.push_back(calc);
}

void
GenericMetric::upon(const AllMetricEvent &event)
{
    auto report_str = generateReport(event.getReset());
    if (!report_str.empty()) {
        dbgTrace(D_METRICS) << report_str;
    }
}

string
GenericMetric::respond(const AllMetricEvent &event)
{
    return generateReport(event.getReset());
}

string GenericMetric::getListenerName() const { return metric_name; }

void
GenericMetric::generateLog()
{
    set<ReportIS::Tags> tags;
    Report metric_to_fog(
        metric_name,
        Singleton::Consume<I_TimeGet>::by<GenericMetric>()->getWalltime(),
        Type::PERIODIC,
        Level::LOG,
        LogLevel::INFO,
        audience,
        team,
        Severity::INFO,
        Priority::LOW,
        report_interval,
        LogField("agentId", Singleton::Consume<I_AgentDetails>::by<GenericMetric>()->getAgentId()),
        tags,
        Tags::INFORMATIONAL,
        issuing_engine
    );

    for (auto &calc : calcs) {
        if (calc->wasOnceReported()) metric_to_fog << calc->getLogField();
    }

    if (Singleton::exists<I_Environment>()) {
        auto env = Singleton::Consume<I_Environment>::by<GenericMetric>();

        for (auto &string_by_key : env->getAllStrings(EnvKeyAttr::LogSection::SOURCE)) {
            metric_to_fog.addToOrigin(LogField(string_by_key.first, string_by_key.second));
        }

        for (auto &uint64_by_key : env->getAllUints(EnvKeyAttr::LogSection::SOURCE)) {
            metric_to_fog.addToOrigin(LogField(uint64_by_key.first, uint64_by_key.second));
        }

        for (auto &bool_by_key : env->getAllBools(EnvKeyAttr::LogSection::SOURCE)) {
            metric_to_fog.addToOrigin(LogField(bool_by_key.first, bool_by_key.second));
        }

        for (auto &string_by_key : env->getAllStrings(EnvKeyAttr::LogSection::DATA)) {
            metric_to_fog << LogField(string_by_key.first, string_by_key.second);
        }

        for (auto &uint64_by_key : env->getAllUints(EnvKeyAttr::LogSection::DATA)) {
            metric_to_fog << LogField(uint64_by_key.first, uint64_by_key.second);
        }

        for (auto &bool_by_key : env->getAllBools(EnvKeyAttr::LogSection::DATA)) {
            metric_to_fog << LogField(bool_by_key.first, bool_by_key.second);
        }
    }

    LogRest metric_client_rest(metric_to_fog);

    sendLog(metric_client_rest);
}

void
GenericMetric::sendLog(const LogRest &metric_client_rest) const
{
    string fog_metric_uri = getConfigurationWithDefault<string>("/api/v1/agents/events", "metric", "fogMetricUri");
    Singleton::Consume<I_Messaging>::by<GenericMetric>()->sendObjectWithPersistence(
        metric_client_rest,
        I_Messaging::Method::POST,
        fog_metric_uri,
        "",
        true,
        MessageTypeTag::METRIC
    );
}

void
GenericMetric::preload()
{
    registerExpectedConfiguration<bool>("metric", "fogMetricSendEnable");
    registerExpectedConfiguration<bool>("metric", "debugMetricSendEnable");
    registerExpectedConfiguration<bool>("metric", "fogMetricUri");
    registerExpectedConfiguration<string>("metric", "metricsOutputTmpFile");
}
