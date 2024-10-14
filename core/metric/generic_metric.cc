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
#include "report_messaging.h"

#include <fstream>
#include <sstream>

using namespace std;
using namespace ReportIS;

USE_DEBUG_FLAG(D_METRICS);

MetricMetadata::DotName operator"" _dot(const char *str, size_t) { return MetricMetadata::DotName{str}; }
MetricMetadata::Units operator"" _unit(const char *str, size_t) { return MetricMetadata::Units{str}; }
MetricMetadata::Description operator"" _desc(const char *str, size_t) { return MetricMetadata::Description{str}; }

// LCOV_EXCL_START Reason: Tested in unit test (testAIOPSMapMetric), but not detected by coverage
static ostream & operator<<(ostream &os, const AiopsMetricList &metrics) { return os << metrics.toString(); }
// LCOV_EXCL_STOP

vector<AiopsMetricData>
MetricCalc::getAiopsMetrics() const
{
    float value = getValue();
    if (isnan(value)) return {};

    string name = getMetricDotName() != "" ? getMetricDotName() : getMetricName();
    string units = getMetircUnits();
    string description = getMetircDescription();
    string type = getMetricType() == MetricType::GAUGE ? "gauge" : "counter";
    
    return { AiopsMetricData(name, type, units, description, getBasicLabels(), value) };
}

string
MetricCalc::getMetadata(const string &key) const
{
    auto value = metadata.find(key);
    return value != metadata.end() ? value->second : "";
}

void
MetricCalc::setMetadata(const string &key, const string &value)
{
    if (value.empty()) {
        metadata.erase(key);
    } else {
        metadata[key] = value;
    }
}

void
MetricCalc::addMetric(GenericMetric *metric)
{
    // Only top level metric should add themselves to the metric. Nested metrics will be served by their parent.
    if (metric != nullptr) metric->addCalc(this);
}

vector<PrometheusData>
MetricCalc::getPrometheusMetrics() const
{
    float value = getValue();
    if (isnan(value)) return {};

    PrometheusData res;

    res.name = getMetricDotName() != "" ? getMetricDotName() : getMetricName();
    res.type = getMetricType() == MetricType::GAUGE ? "gauge" : "counter";
    res.desc = getMetircDescription();

    stringstream labels;
    const auto &label_pairs = getBasicLabels();
    bool first = true;
    for (auto &pair : label_pairs) {
        if (!first) labels << ',';
        labels << pair.first << "=\"" << pair.second << '"';
        first = false;
    }
    res.label = labels.str();

    stringstream value_str;
    value_str << value;
    res.value = value_str.str();

    return {res};
}

map<string, string>
MetricCalc::getBasicLabels() const
{
    map<string, string> res;

    auto i_instance = Singleton::Consume<I_InstanceAwareness>::by<GenericMetric>();
    auto id = i_instance->getUniqueID();
    if (id.ok()) res["id"] = *id;

    auto details = Singleton::Consume<I_AgentDetails>::by<GenericMetric>();
    res["agent"] = details->getAgentId();

    auto env = Singleton::Consume<I_Environment>::by<GenericMetric>();
    auto executable = env->get<string>("Base Executable Name");
    if (executable.ok()) res["process"] = *executable;

    return res;
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
    Audience _audience,
    bool _force_buffering
)
{
    turnOnStream(Stream::FOG);
    turnOnStream(Stream::DEBUG);

    i_mainloop = Singleton::Consume<I_MainLoop>::by<GenericMetric>();
    i_time = Singleton::Consume<I_TimeGet>::by<GenericMetric>();
    metric_name = _metric_name;
    report_interval = _report_interval;
    reset = _reset;
    team = _team;
    issuing_engine = _issuing_engine;
    audience = _audience;
    force_buffering = _force_buffering;

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
    if (active_streams.isSet(Stream::DEBUG)) generateDebug();
    if (active_streams.isSet(Stream::PROMETHEUS)) generatePrometheus();
    if (active_streams.isSet(Stream::FOG)) generateLog();
    if (active_streams.isSet(Stream::AIOPS)) generateAiopsLog();

    if (reset) resetMetrics();
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
GenericMetric::generateReport() const
{
    stringstream ss;
    {
        cereal::JSONOutputArchive ar(ss);
        ar(cereal::make_nvp("Metric", metric_name));
        ar(cereal::make_nvp("Reporting interval", report_interval.count()));
        for(auto &calc : calcs) {
            calc->save(ar);
        }
    }
    return ss.str();
}

void
GenericMetric::resetMetrics()
{
    for(auto &calc : calcs) {
        calc->reset();
    }
}

void
GenericMetric::addCalc(MetricCalc *calc)
{
    calcs.push_back(calc);
}

void
GenericMetric::upon(const AllMetricEvent &event)
{
    dbgTrace(D_METRICS) << generateReport();
    if (event.getReset()) resetMetrics();
}

string
GenericMetric::respond(const AllMetricEvent &event)
{
    auto res = generateReport();
    if (event.getReset()) resetMetrics();
    return res;
}

string GenericMetric::getListenerName() const { return metric_name; }

void
GenericMetric::generateLog()
{
    if (!getConfigurationWithDefault<bool>(true, "metric", "fogMetricSendEnable")) return;

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
        metric_to_fog << calc->getLogField();
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

class PrometheusRest : public ClientRest
{
    class Metric : public ClientRest
    {
    public:
        Metric(const string &n, const string &t, const string &d, const string &l, const string &v)
                :
            name(n),
            type(t),
            description(d),
            labels(l),
            value(v)
        {}

    private:
        C2S_PARAM(string, name);
        C2S_PARAM(string, type);
        C2S_PARAM(string, description);
        C2S_PARAM(string, labels);
        C2S_PARAM(string, value);
    };

public:
    PrometheusRest() : metrics(vector<Metric>()) {}

    void
    addMetric(const vector<PrometheusData> &vec)
    {
        auto &metric_vec = metrics.get();
        metric_vec.reserve(vec.size());
        for (auto &metric : vec) {
            metric_vec.emplace_back(metric.name, metric.type, metric.desc, "{" + metric.label + "}", metric.value);
        }
    }

private:
    C2S_PARAM(vector<Metric>, metrics);
};

void
GenericMetric::generatePrometheus()
{
    if (!getProfileAgentSettingWithDefault(false, "prometheus")) return;

    vector<PrometheusData> all_metrics;
    for (auto &calc : calcs) {
        const auto &cal_metrics = calc->getPrometheusMetrics();
        all_metrics.insert(all_metrics.end(), cal_metrics.begin(), cal_metrics.end());
    }

    PrometheusRest rest;
    rest.addMetric(all_metrics);

    MessageMetadata new_config_req_md("127.0.0.1", 7465);
    new_config_req_md.setConnectioFlag(MessageConnectionConfig::ONE_TIME_CONN);
    new_config_req_md.setConnectioFlag(MessageConnectionConfig::UNSECURE_CONN);
    Singleton::Consume<I_Messaging>::by<GenericMetric>()->sendSyncMessage(
        HTTPMethod::POST,
        "/set-prometheus-data",
        rest,
        MessageCategory::GENERIC,
        new_config_req_md
    );
}

void
GenericMetric::generateAiopsLog()
{
    if (!getConfigurationWithDefault<bool>(true, "metric", "aiopsMetricSendEnable")) return;

    AiopsMetricList aiops_metrics;

    for (auto &calc : calcs) {
        aiops_metrics.addMetrics(calc->getAiopsMetrics());
    }

    set<ReportIS::Tags> tags;
    Report metric_to_fog(
        "AIOPS Metric Data",
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

    metric_to_fog << LogField("eventObject", aiops_metrics);
    
    LogRest metric_client_rest(metric_to_fog);
    sendLog(metric_client_rest);
}

void
GenericMetric::generateDebug()
{
    if (!getConfigurationWithDefault<bool>(true, "metric", "debugMetricSendEnable")) return;
    dbgTrace(D_METRICS) << generateReport();
}

void
GenericMetric::sendLog(const LogRest &metric_client_rest) const
{
    string fog_metric_uri = getConfigurationWithDefault<string>("/api/v1/agents/events", "metric", "fogMetricUri");
    Singleton::Consume<I_Messaging>::by<GenericMetric>()->sendAsyncMessage(
        HTTPMethod::POST,
        fog_metric_uri,
        metric_client_rest,
        MessageCategory::METRIC,
        MessageMetadata(),
        force_buffering
    );
}

void
GenericMetric::preload()
{
    registerExpectedConfiguration<bool>("metric", "fogMetricSendEnable");
    registerExpectedConfiguration<bool>("metric", "debugMetricSendEnable");
    registerExpectedConfiguration<bool>("metric", "aiopsMetricSendEnable");
    registerExpectedConfiguration<bool>("metric", "fogMetricUri");
    registerExpectedConfiguration<string>("metric", "metricsOutputTmpFile");
}
