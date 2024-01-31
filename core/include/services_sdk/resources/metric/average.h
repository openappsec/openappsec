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

#ifndef __AVERAGE_H__
#define __AVERAGE_H__

#ifndef __GENERIC_METRIC_H__
#error metric/average.h should not be included directly
#endif // __GENERIC_METRIC_H__

namespace MetricCalculations
{

template <typename T>
class Average : public MetricCalc
{
public:
    Average(GenericMetric *metric, const std::string &title) : MetricCalc(metric, title), sum(0), count(0) {}

    void
    report(const T &new_value)
    {
        was_once_reported = true;
        sum += new_value;
        count++;
    }

    void
    reset() override
    {
        was_once_reported = false;
        sum = 0;
        count = 0;
    }

    double
    getAverage() const
    {
        return (was_once_reported) ? double(sum)/count : 0;
    }

    void
    save(cereal::JSONOutputArchive &ar) const override
    {
        ar(cereal::make_nvp(calc_title, getAverage()));
    }

    LogField
    getLogField() const override
    {
        return LogField(calc_title, static_cast<uint64_t>(getAverage()));
    }

private:
    T sum;
    uint count;
};

} // namespace MetricCalculations
#endif // __AVERAGE_H__
