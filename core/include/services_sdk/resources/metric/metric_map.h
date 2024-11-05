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

#ifndef __METRIC_MAP_H__
#define __METRIC_MAP_H__

#ifndef __GENERIC_METRIC_H__
#error metric/metric_map.h should not be included directly
#endif // __GENERIC_METRIC_H_

#include <map>
#include <sstream>

namespace MetricCalculations
{

template <typename PrintableKey, typename Metric>
class MetricMap : public MetricCalc
{
    class InnerMap
    {
    public:
        void
        save(cereal::JSONOutputArchive &ar) const
        {
            for (auto &metric : inner_map) {
                metric.second.save(ar);
            }
        }

        std::pair<typename std::map<std::string, Metric>::iterator, bool>
        emplace(const std::string &key, Metric &&metric)
        {
            return inner_map.emplace(key, std::move(metric));
        }

        void clear() { inner_map.clear(); }

        MetricType
        getMetricType() const
        {
            auto first = begin();
            if (first == end()) return MetricType::GAUGE;
            return first->second.getMetricType();
        }

        std::vector<PrometheusData>
        getPrometheusMetrics(const std::string &label, const std::string &name) const
        {
            std::vector<PrometheusData> res;

            for (auto &metric : inner_map) {
                auto sub_res =  metric.second.getPrometheusMetrics();
                for (auto &sub_metric : sub_res) {
                    sub_metric.label += "," + label + "=\"" + metric.first + "\"";
                    sub_metric.name = name;
                }
                res.insert(res.end(), sub_res.begin(), sub_res.end());
            }

            return res;
        }

        std::vector<AiopsMetricData>
        getAiopsMetrics(const std::string &label) const
        {
            std::vector<AiopsMetricData> aiops_metrics;
            for (auto &metric : inner_map) {
                auto metric_data = metric.second.getAiopsMetrics();
                for (auto &sub_metric : metric_data) {
                    sub_metric.addMetricAttribute(label,  metric.first);
                }
                aiops_metrics.insert(aiops_metrics.end(), metric_data.begin(), metric_data.end());
            }
            return aiops_metrics;
        }

        typename std::map<std::string, Metric>::const_iterator begin() const { return inner_map.begin(); }
        typename std::map<std::string, Metric>::const_iterator end() const { return inner_map.end(); }

    private:
        std::map<std::string, Metric> inner_map;
    };

public:
    template <typename ... Args>
    MetricMap(
        const Metric &sub_metric,
        GenericMetric *metric,
        const std::string &l,
        const std::string &title,
        const Args & ... args
    )
            :
        MetricCalc(metric, title, args ...),
        base_metric(sub_metric),
        label(l)
    {
    }

    void
    reset() override
    {
        if (getMetricType() == MetricType::GAUGE) metric_map.clear();
    }

// LCOV_EXCL_START Reason: Covered by printPromeathusMultiMap unit-test, but misdetected by the coverage
    float
    getValue() const override
    {
        return std::nanf("");
    }
// LCOV_EXCL_STOP

    void
    save(cereal::JSONOutputArchive &ar) const override
    {
        ar(cereal::make_nvp(getMetricName(), metric_map));
    }

    MetricType getMetricType() const override { return metric_map.getMetricType(); }

    template <typename ... Values>
    void
    report(const PrintableKey &key, const Values & ... new_values)
    {
        std::stringstream string_key;
        string_key << key;
        auto new_metric = base_metric;
        new_metric.setMetricName(string_key.str());
        auto metric = metric_map.emplace(string_key.str(), std::move(new_metric)).first;
        metric->second.report(new_values...);
    }

    LogField
    getLogField() const override
    {
        LogField field(getMetricName());

        for (auto &metric : metric_map) {
            field.addFields(metric.second.getLogField());
        }

        return field;
    }

    std::vector<PrometheusData>
    getPrometheusMetrics() const override
    {
        return metric_map.getPrometheusMetrics(label, getMetricName());
    }

    std::vector<AiopsMetricData>
    getAiopsMetrics() const
    {
        return metric_map.getAiopsMetrics(label);
    }

private:
    InnerMap metric_map;
    Metric base_metric;
    std::string label;
};

} // namespace MetricCalculations

#endif // __METRIC_MAP_H__
