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

#ifndef __TOP_VALUES_H__
#define __TOP_VALUES_H__

#ifndef __GENERIC_METRIC_H__
#error metric/top_values.h should not be included directly
#endif // __GENERIC_METRIC_H__

#include <vector>
#include <algorithm>

namespace MetricCalculations
{

template <typename T, uint N>
class TopValues : public MetricCalc
{
public:
    TopValues(GenericMetric *metric, const std::string &title) : MetricCalc(metric, title) { values.reserve(N); }

    void
    report(const T &new_value)
    {
        was_once_reported = true;
        if (values.size() < N) {
            values.push_back(new_value);
            return;
        }

        std::sort(values.begin(), values.end());
        for (T &old_value : values) {
            if (old_value < new_value) {
                old_value = new_value;
                return;
            }
        }
    }

    void
    reset() override
    {
        was_once_reported = false;
        values.clear();
    }

    std::vector<T>
    getTopValues() const
    {
        auto res = values;
        std::sort(res.begin(), res.end());
        return res;
    }

    void
    save(cereal::JSONOutputArchive &ar) const override
    {
        ar(cereal::make_nvp(calc_title, getTopValues()));
    }

    LogField
    getLogField() const override
    {
        return LogField(calc_title, getTopValues());
    }

private:
    std::vector<T> values;
};

} // namespace MetricCalculations

#endif // __TOP_VALUES_H__
