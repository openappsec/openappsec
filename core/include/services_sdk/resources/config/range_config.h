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

#ifndef __RANGE_CONFIG_H__
#define __RANGE_CONFIG_H___

#ifndef __CONFIG_H__
#error "range_config.h should not be included directly"
#endif // __CONFIG_H__

namespace Config
{

template <typename ConfigurationType>
class ConfigRange
{
    using PerContextValue = std::vector<std::pair<std::shared_ptr<EnvironmentEvaluator<bool>>, TypeWrapper>>;
    using Iterator = PerContextValue::const_iterator;

    class ConfigurationIter
    {
    public:
        ConfigurationIter(const Iterator &begin, const Iterator &end) : curr(begin), end_iter(end)
        {
            if (!isLegitimatePosition()) ++(*this);
        }

        void
        operator++()
        {
            while (curr != end_iter) {
                ++curr;
                if (isLegitimatePosition()) break;
            }
        }

        const ConfigurationType & operator*() const { return curr->second.getValue<ConfigurationType>().unpack(); }
        bool operator!=(const ConfigurationIter &other) { return curr != other.curr; }
        bool operator==(const ConfigurationIter &other) { return curr == other.curr; }

    private:
        bool
        isLegitimatePosition() const
        {
            if (curr == end_iter) return true;
            if (!checkContext()) return false;
            return curr->second.getValue<ConfigurationType>().ok();
        }

        bool
        checkContext() const
        {
            auto &checker = curr->first;
            if (checker == nullptr) return true;
            auto res = checker->evalVariable();
            return res.ok() && *res;
        }

        Iterator curr, end_iter;
    };

public:
    ConfigRange() {}
    ConfigRange(const PerContextValue &_values) :  values(_values) {}

    ConfigurationIter begin() const { return ConfigurationIter(values.begin(), values.end()); }
    ConfigurationIter end() const { return ConfigurationIter(values.end(), values.end()); }

private:
    PerContextValue values;
};

} // namespace Config

#endif // __RANGE_CONFIG_H__
