#include "prometheus_comp.h"

#include <string>
#include <map>
#include <vector>
#include <cereal/archives/json.hpp>
#include <cereal/types/map.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/types/string.hpp>
#include <iostream>
#include <fstream>

#include "common.h"
#include "report/base_field.h"
#include "report/report_enums.h"
#include "log_generator.h"
#include "debug.h"
#include "rest.h"
#include "customized_cereal_map.h"
#include "i_messaging.h"
#include "prometheus_metric_names.h"

USE_DEBUG_FLAG(D_PROMETHEUS);

using namespace std;
using namespace ReportIS;

struct ServiceData
{
    template <typename Archive>
    void
    serialize(Archive &ar)
    {
        ar(cereal::make_nvp("Service port", service_port));
    }

    int service_port;
};

class PrometheusMetricData
{
public:
    PrometheusMetricData(const string &n, const string &u, const string &t, const string &d)
            :
        name(n),
        unique_name(u),
        type(t),
        description(d)
    {}

    void
    addElement(const string &labels, const string &value)
    {
        metric_labels_to_values[labels] = value;
    }

    ostream &
    print(ostream &os)
    {
        if (metric_labels_to_values.empty()) return os;

        string representative_name = "";
        if (!name.empty()) {
            string metric_name;
            if (!unique_name.empty()) metric_name = convertMetricName(unique_name);
            if (metric_name.empty()) metric_name = convertMetricName(name);
            !metric_name.empty() ? representative_name = metric_name : representative_name = name;
        }

        if (!description.empty()) os << "# HELP " << representative_name << ' ' << description << '\n';
        if (!name.empty()) os << "# TYPE " << representative_name << ' ' << type << '\n';
        for (auto &entry : metric_labels_to_values) {
            os << representative_name << entry.first << ' ' << entry.second << '\n';
        }
        os << '\n';
        metric_labels_to_values.clear();

        return os;
    }

private:

    string name;
    string unique_name;
    string type;
    string description;
    map<string, string> metric_labels_to_values;
};

static ostream & operator<<(ostream &os, PrometheusMetricData &metric) { return metric.print(os); }

class PrometheusComp::Impl
{
public:
    void
    init()
    {
        Singleton::Consume<I_RestApi>::by<PrometheusComp>()->addGetCall(
            "metrics",
            [&] () { return getFormatedPrometheusMetrics(); }
        );
    }

    void
    addMetrics(const vector<PrometheusData> &metrics)
    {
        for(auto &metric : metrics) {
            auto &metric_object = getDataObject(
                metric.name,
                metric.unique_name,
                metric.type,
                metric.description
            );
            metric_object.addElement(metric.label,  metric.value);
        }
    }

private:
    PrometheusMetricData &
    getDataObject(const string &name, const string &unique_name, const string &type, const string &description)
    {
        auto elem = prometheus_metrics.find(unique_name);
        if (elem == prometheus_metrics.end()) {
            elem = prometheus_metrics.emplace(
                unique_name,
                PrometheusMetricData(name, unique_name, type, description)
            ).first;
        }

        return elem->second;
    }

    map<string, ServiceData>
    getServiceDetails()
    {
        map<string, ServiceData> registeredServices;
        auto registered_services_file = getConfigurationWithDefault<string>(
            getFilesystemPathConfig() + "/conf/orchestrations_registered_services.json",
            "orchestration",
            "Orchestration registered services"
        );
        ifstream file(registered_services_file);
        if (!file.is_open()) {
            dbgWarning(D_PROMETHEUS) << "Failed to open file: " << registered_services_file;
            return registeredServices;
        }
        stringstream buffer;
        buffer << file.rdbuf();
        try {
            cereal::JSONInputArchive archive(buffer);
            archive(cereal::make_nvp("Registered Services", registeredServices));
        } catch (const exception& e) {
            dbgWarning(D_PROMETHEUS) << "Error parsing Registered Services JSON file: " << e.what();
        }

        return registeredServices;
    }

    void
    getServicesMetrics()
    {
        dbgTrace(D_PROMETHEUS) << "Get all registered services metrics";
        map<string, ServiceData> service_names_to_ports = getServiceDetails();
        for (const auto &service : service_names_to_ports) {
            I_Messaging *messaging = Singleton::Consume<I_Messaging>::by<PrometheusComp>();
            MessageMetadata servie_metric_req_md("127.0.0.1", service.second.service_port);
            servie_metric_req_md.setConnectioFlag(MessageConnectionConfig::ONE_TIME_CONN);
            servie_metric_req_md.setConnectioFlag(MessageConnectionConfig::UNSECURE_CONN);
            auto res = messaging->sendSyncMessage(
                HTTPMethod::GET,
                "/service-metrics",
                string(""),
                MessageCategory::GENERIC,
                servie_metric_req_md
            );
            if (!res.ok()) {
                dbgWarning(D_PROMETHEUS) << "Failed to get service metrics. Service: " << service.first;
                continue;
            }
            stringstream buffer;
            buffer << res.unpack().getBody();
            cereal::JSONInputArchive archive(buffer);
            vector<PrometheusData> metrics;
            archive(cereal::make_nvp("metrics", metrics));
            addMetrics(metrics);
        }
    }

    string
    getFormatedPrometheusMetrics()
    {
        MetricScrapeEvent().notify();
        getServicesMetrics();
        stringstream result;
        for (auto &metric : prometheus_metrics) {
            result << metric.second;
        }
        dbgTrace(D_PROMETHEUS) << "Prometheus metrics: " << result.str();
        return result.str();
    }

    map<string, PrometheusMetricData> prometheus_metrics;
};

PrometheusComp::PrometheusComp() : Component("Prometheus"), pimpl(make_unique<Impl>()) {}

PrometheusComp::~PrometheusComp() {}

void
PrometheusComp::init()
{
    pimpl->init();
}
