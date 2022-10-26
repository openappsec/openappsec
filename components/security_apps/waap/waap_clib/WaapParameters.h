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

#pragma once
#include <string>
#include <unordered_map>
#include <cereal/archives/json.hpp>
#include <cereal/types/unordered_map.hpp>


namespace Waap {
    namespace Parameters {
        typedef std::string Parameter;
        typedef std::string Value;
        typedef std::unordered_map<Parameter, Value> ParamMap;

        class WaapParameters
        {
        public:
            template <typename _A>
            WaapParameters(_A& ar)
            {
                ar(cereal::make_nvp("waapParameters", m_paramMap));
            }

            bool operator==(const WaapParameters &other) const;

            ParamMap getParamsMap() const;
            Value getParamVal(Parameter key, Value defaultVal);
        private:
            ParamMap m_paramMap;
        };

    }
}
