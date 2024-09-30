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

#ifndef __METRIC_CALC_H__
#define __METRIC_CALC_H__

#ifndef __GENERIC_METRIC_H__
#error metric/metric_calc.h should not be included directly
#endif // __GENERIC_METRIC_H_

#include <cereal/archives/json.hpp>

#include "report/report.h"

class GenericMetric;

enum class MetricType { GAUGE, COUNTER };

class MetricCalc
{
public:
    template<typename ... Args>
    MetricCalc(GenericMetric *metric, const std::string &calc_title, const Args & ... args)
    {
        setMetadata("BaseName", calc_title);
        addMetric(metric);
        parseMetadata(args ...);
    }

    virtual void reset() = 0;
    virtual void save(cereal::JSONOutputArchive &) const = 0;
    virtual LogField getLogField() const = 0;

    std::string getMetricName() const { return getMetadata("BaseName"); }
    std::string getMetricDotName() const { return getMetadata("DotName"); }
    std::string getMetircUnits() const { return getMetadata("Units"); }
    std::string getMetircDescription() const { return getMetadata("Description"); }
    std::string getMetadata(const std::string &metadata) const;
    virtual MetricType getMetricType() const { return MetricType::GAUGE; }

    void setMetricDotName(const std::string &name) { setMetadata("DotName", name); }
    void setMetircUnits(const std::string &units) { setMetadata("Units", units); }
    void setMetircDescription(const std::string &description) { setMetadata("Description", description); }
    void setMetadata(const std::string &metadata, const std::string &value);

protected:
    void addMetric(GenericMetric *metric);

    template <typename Metadata, typename ... OtherMetadata>
    void
    parseMetadata(const Metadata &metadata, const OtherMetadata & ... other_metadata)
    {
        parseMetadata(metadata);
        parseMetadata(other_metadata ...);
    }

    void parseMetadata(const MetricMetadata::DotName &name) { setMetricDotName(name.val); }
    void parseMetadata(const MetricMetadata::Units &units) { setMetircUnits(units.val); }
    void parseMetadata(const MetricMetadata::Description &description) { setMetircDescription(description.val); }
    void parseMetadata() {}

private:
    std::map<std::string, std::string> metadata;
};

#endif // __METRIC_CALC_H__
