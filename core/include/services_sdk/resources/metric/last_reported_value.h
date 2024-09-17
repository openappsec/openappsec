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

#ifndef __LAST_REPORTED_VALUE_H__
#define __LAST_REPORTED_VALUE_H__

#ifndef __GENERIC_METRIC_H__
#error metric/last_reported_value.h should not be included directly
#endif // __GENERIC_METRIC_H_

namespace MetricCalculations
{

template <typename T>
class LastReportedValue : public MetricCalc
{
public:
    template <typename ... Args>
    LastReportedValue(GenericMetric *metric, const std::string &title, const Args & ... args)
            :
        MetricCalc(metric, title, args ...)
    {
    }

    void
    reset() override
    {
        last_reported = T();
    }

    T
    getLastReportedValue() const
    {
        return last_reported;
    }

    void
    save(cereal::JSONOutputArchive &ar) const override
    {
        ar(cereal::make_nvp(getMetricName(), getLastReportedValue()));
    }

    void
    report(const T &new_value)
    {
        last_reported = new_value;
    }

    LogField
    getLogField() const override
    {
        return LogField(getMetricName(), static_cast<uint64_t>(getLastReportedValue()));
    }

private:
    T last_reported{};
};

} // namespace MetricCalculations

#endif // __LAST_REPORTED_VALUE_H__
