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

#ifndef __HYBRID_MODE_TELEMETRY_H__
#define __HYBRID_MODE_TELEMETRY_H__

#include "generic_metric.h"

class HybridModeMetricEvent : public Event<HybridModeMetricEvent>
{
public:
    HybridModeMetricEvent() {}
};

class HybridModeMetric : public GenericMetric, public Listener<HybridModeMetricEvent>
{
public:
    void upon(const HybridModeMetricEvent &event) override;

private:
    MetricCalculations::LastReportedValue<int> wd_process_restart{this, "watchdogProcessStartupEventsSum"};
};

#endif // __HYBRID_MODE_TELEMETRY_H__
