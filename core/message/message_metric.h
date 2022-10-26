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

#ifndef __MESSAGE_METRIC_H__
#define __MESSAGE_METRIC_H__

#include "generic_metric.h"

class MessageQueueEvent : public Event<MessageQueueEvent>
{
public:
    void
    setMessageQueueSize(uint64_t _queue_size)
    {
        queue_size = _queue_size;
    }

    uint64_t
    getMessageQueueSize() const
    {
        return queue_size;
    }

private:
    uint64_t queue_size;
};

class MessageQueueMetric
        :
    public GenericMetric,
    public Listener<MessageQueueEvent>
{
public:
    void
    upon(const MessageQueueEvent &event) override
    {
        max_queue_size.report(event.getMessageQueueSize());
        avg_queue_size.report(double(event.getMessageQueueSize()));
        current_queue_size.report(event.getMessageQueueSize());
    }

private:
    MetricCalculations::Max<uint64_t> max_queue_size{this, "messageQueueMaxSizeSample", 0};
    MetricCalculations::Average<double> avg_queue_size{this, "messageQueueAvgSizeSample"};
    MetricCalculations::LastReportedValue<uint64_t> current_queue_size{this, "messageQueueCurrentSizeSample"};
};

#endif // __MESSAGE_METRIC_H__
