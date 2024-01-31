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

        typename std::map<std::string, Metric>::const_iterator begin() const { return inner_map.begin(); }
        typename std::map<std::string, Metric>::const_iterator end() const { return inner_map.end(); }

    private:
        std::map<std::string, Metric> inner_map;
    };

public:
    MetricMap(GenericMetric *metric, const std::string &title) : MetricCalc(metric, title) {}

    void
    reset() override
    {
        was_once_reported = false;
        metric_map.clear();
    }

    void
    save(cereal::JSONOutputArchive &ar) const override
    {
        ar(cereal::make_nvp(calc_title, metric_map));
    }


    template <typename ... Values>
    void
    report(const PrintableKey &key, const Values & ... new_values)
    {
        was_once_reported = true;
        std::stringstream string_key;
        string_key << key;
        auto metric = metric_map.emplace(string_key.str(), Metric(nullptr, string_key.str())).first;
        metric->second.report(new_values...);
    }

    LogField
    getLogField() const override
    {
        LogField field(calc_title);

        for (auto &metric : metric_map) {
            field.addFields(metric.second.getLogField());
        }

        return field;
    }

private:
    InnerMap metric_map;
};

} // namespace MetricCalculations

#endif // __METRIC_MAP_H__
