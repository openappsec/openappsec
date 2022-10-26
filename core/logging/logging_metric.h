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

#ifndef __LOGGING_METRIC_H__
#define __LOGGING_METRIC_H__

#include "generic_metric.h"

class LogEventQueueSize : public Event<LogEventQueueSize>
{
public:
    LogEventQueueSize(uint64_t _size) : size(_size) {}

    uint64_t getSize() const { return size; }

private:
    uint64_t size;
};

class LogEventLogsSent : public Event<LogEventLogsSent>
{
public:
    LogEventLogsSent(bool is_single, uint64_t no_logs = 1) : logs(no_logs),  bulks(is_single ? 0 : 1)  {}

    uint64_t getLogsNumber() const { return logs; }
    uint64_t getBulksNumber() const { return bulks; }

private:
    uint64_t logs;
    uint64_t bulks;
};

class LogMetric
        :
    public GenericMetric,
    public Listener<LogEventQueueSize>,
    public Listener<LogEventLogsSent>
{
public:
    void
    upon(const LogEventQueueSize &event) override
    {
        max_queue_size.report(event.getSize());
        avg_queue_size.report(double(event.getSize()));
        current_queue_size.report(event.getSize());
    }

    void
    upon(const LogEventLogsSent &event) override
    {
        sent_logs.report(event.getLogsNumber());
        sent_logs_bulks.report(event.getBulksNumber());
    }

private:
    MetricCalculations::Max<uint64_t> max_queue_size{this, "logQueueMaxSizeSample", 0};
    MetricCalculations::Average<double> avg_queue_size{this, "logQueueAvgSizeSample"};
    MetricCalculations::LastReportedValue<uint64_t> current_queue_size{this, "logQueueCurrentSizeSample"};
    MetricCalculations::Counter sent_logs{this, "sentLogsSum"};
    MetricCalculations::Counter sent_logs_bulks{this, "sentLogsBulksSum"};
};

#endif // __LOGGING_METRIC_H__
