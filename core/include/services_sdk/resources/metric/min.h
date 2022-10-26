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
    Min(GenericMetric *metric, const std::string &title) : Min(metric, title, std::numeric_limits<T>::max()) {}
    Min(GenericMetric *metric, const std::string &title, T max_val) : MetricCalc(metric, title), min(max_val) {}

    void
    report(const T &new_value)
    {
        was_once_reported = true;
        if (new_value < min) min = new_value;
    }

    void
    reset() override
    {
        was_once_reported = false;
        min = std::numeric_limits<T>::max();
    }

    T
    getMin() const
    {
        return min;
    }

    void
    save(cereal::JSONOutputArchive &ar) const override
    {
        ar(cereal::make_nvp(calc_title, min));
    }

    LogField
    getLogField() const override
    {
        return LogField(calc_title, static_cast<uint64_t>(getMin()));
    }

private:
    T min;
};

} // namespace MetricCalculations

#endif // __MIN_H__
