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

#ifndef __MIN_H__
#define __MIN_H__

#ifndef __GENERIC_METRIC_H__
#error metric/min.h should not be included directly
#endif // __GENERIC_METRIC_H_

namespace MetricCalculations
{

template <typename T>
class Min : public MetricCalc
{
public:
    Min(GenericMetric *metric, const std::string &title) : Min(metric, title, 0) {}

    template<typename ... Args>
    Min(GenericMetric *metric, const std::string &title, T max_val, const Args & ... args)
            :
        MetricCalc(metric, title, args ...),
        min(max_val),
        reset_value(max_val)
    {
    }

    void
    report(const T &new_value)
    {
        if (new_value < min || first) min = new_value;
        first = false;
    }

    void
    reset() override
    {
        min = reset_value;
        first = true;
    }

    T
    getMin() const
    {
        return min;
    }

    float
    getValue() const override
    {
        return static_cast<float>(min);
    }

    void
    save(cereal::JSONOutputArchive &ar) const override
    {
        ar(cereal::make_nvp(getMetricName(), min));
    }

    LogField
    getLogField() const override
    {
        return LogField(getMetricName(), static_cast<uint64_t>(getMin()));
    }

private:
    T min;
    T reset_value;
    bool first = true;
};

} // namespace MetricCalculations

#endif // __MIN_H__
