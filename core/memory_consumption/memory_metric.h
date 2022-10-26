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

#ifndef __MEMORY_METRIC_H__
#define __MEMORY_METRIC_H__

#include "log_generator.h"
#include "generic_metric.h"
#include "event.h"

enum class memory_type_metric {
    VM_PROC_MAX,
    VM_PROC_MIN,
    VM_PROC_AVERAGE,
    RSS_PROC_MAX,
    RSS_PROC_MIN,
    RSS_PROC_AVERAGE,
    GENERAL_TOTAL_MAX,
    GENERAL_TOTAL_MIN,
    GENERAL_TOTAL_AVERAGE
};

static const std::string virtual_process_memory_key = "virtual_process_memory";
static const std::string rss_process_key = "rss_process";
static const std::string general_total_memory_key = "general_total_memory";

USE_DEBUG_FLAG(D_MONITORING);

class MemoryConsumptionEvent : public Event<MemoryConsumptionEvent>
{
public:
    void
    setMemoryValues(std::map<std::string, double> new_values)
    {
        virtual_process_memory_max = new_values[virtual_process_memory_key];
        virtual_process_memory_min = new_values[virtual_process_memory_key];
        virtual_process_memory_average = new_values[virtual_process_memory_key];

        rss_process_max = new_values[rss_process_key];
        rss_process_min = new_values[rss_process_key];
        rss_process_average = new_values[rss_process_key];

        general_total_memory_max = new_values[general_total_memory_key];
        general_total_memory_min = new_values[general_total_memory_key];
        general_total_memory_average = new_values[general_total_memory_key];
    }

    double
    getMemoryValue(const memory_type_metric memory_type) const
    {
        switch (memory_type) {
            case memory_type_metric::VM_PROC_MAX:
                return virtual_process_memory_max;
            case memory_type_metric::VM_PROC_MIN:
                return virtual_process_memory_min;
            case memory_type_metric::VM_PROC_AVERAGE:
                return virtual_process_memory_average;
            case memory_type_metric::RSS_PROC_MAX:
                return rss_process_max;
            case memory_type_metric::RSS_PROC_MIN:
                return rss_process_min;
            case memory_type_metric::RSS_PROC_AVERAGE:
                return rss_process_average;
            case memory_type_metric::GENERAL_TOTAL_MAX:
                return general_total_memory_max;
            case memory_type_metric::GENERAL_TOTAL_MIN:
                return general_total_memory_min;
            case memory_type_metric::GENERAL_TOTAL_AVERAGE:
                return general_total_memory_average;
            default:
                dbgWarning(D_MONITORING) << "Unsupported memory metric type.";
                return 0;
        }
    }

private:
    double virtual_process_memory_max = 0;
    double virtual_process_memory_min = 0;
    double virtual_process_memory_average = 0;
    double rss_process_max = 0;
    double rss_process_min = 0;
    double rss_process_average = 0;
    double general_total_memory_max = 0;
    double general_total_memory_min = 0;
    double general_total_memory_average = 0;
};

class MemoryMetric
        :
    public GenericMetric,
    public Listener<MemoryConsumptionEvent>
{
public:
    void upon(const MemoryConsumptionEvent &event) override;

private:
    MetricCalculations::Max<double> virtual_process_memory_max{this, "serviceVirtualMemorySizeMaxSample", 0};
    MetricCalculations::Min<double> virtual_process_memory_min{this, "serviceVirtualMemorySizeMinSample"};
    MetricCalculations::Average<double> virtual_process_memory_average{this, "serviceVirtualMemorySizeAvgSample"};

    MetricCalculations::Max<double> rss_process_max{this, "serviceRssMemorySizeMaxSample", 0};
    MetricCalculations::Min<double> rss_process_min{this, "serviceRssMemorySizeMinSample"};
    MetricCalculations::Average<double> rss_process_average{this, "serviceRssMemorySizeAvgSample"};

    MetricCalculations::Max<double> general_total_memory_max{this, "generalTotalMemorySizeMaxSample", 0};
    MetricCalculations::Min<double> general_total_memory_min{this, "generalTotalMemorySizeMinSample"};
    MetricCalculations::Average<double> general_total_memory_average{this, "generalTotalMemorySizeAvgSample"};
};

#endif // __MEMORY_METRIC_H__
