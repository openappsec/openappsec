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

#ifndef __COUNTER_H__
#define __COUNTER_H__

#ifndef __GENERIC_METRIC_H__
#error metric/counter.h should not be included directly
#endif // __GENERIC_METRIC_H_

namespace MetricCalculations
{

class Counter : public MetricCalc
{
public:
    Counter(GenericMetric *metric, const std::string &title) : MetricCalc(metric, title), counter(0) {}

    void
    reset() override
    {
        was_once_reported = false;
        counter = 0;
    }

    uint64_t
    getCounter() const
    {
        return counter;
    }

    void
    save(cereal::JSONOutputArchive &ar) const override
    {
        ar(cereal::make_nvp(calc_title, getCounter()));
    }

    void
    report(const uint64_t &new_value)
    {
        was_once_reported = true;
        counter += new_value;
    }

    LogField
    getLogField() const override
    {
        return LogField(calc_title, static_cast<uint64_t>(getCounter()));
    }

private:
    uint64_t counter;
};

} // namespace MetricCalculations

#endif // __COUNTER_H__
