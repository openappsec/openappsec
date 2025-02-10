#include "metric/metric_scraper.h"

using namespace std;

USE_DEBUG_FLAG(D_METRICS);

class MetricScraper::Impl
{
public:
    void
    init()
    {
        Singleton::Consume<I_RestApi>::by<MetricScraper>()->addGetCall(
            "service-metrics",
            [&] () { return getAllPrometheusMetrics(); }
        );
    }

    string
    getAllPrometheusMetrics()
    {
        auto all_metrics_events_res = MetricScrapeEvent().query();
        for (auto metric_vec : all_metrics_events_res) {
            for (PrometheusData metric : metric_vec) {
                metric.label = "{" + metric.label + "}";
                all_metrics.emplace_back(metric);
            }
        }
        stringstream ss;
        {
            cereal::JSONOutputArchive archive(ss);
            archive(cereal::make_nvp("metrics", all_metrics));
        }
        all_metrics.clear();
        return ss.str();
    }

private:
    vector<PrometheusData> all_metrics;
};

MetricScraper::MetricScraper() : Component("MetricScraper"), pimpl(make_unique<MetricScraper::Impl>()) {}

MetricScraper::~MetricScraper() {}

void
MetricScraper::init()
{
    pimpl->init();
}
