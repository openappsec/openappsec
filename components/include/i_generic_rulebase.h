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

#ifndef __I_GENERIC_RULEBASE_H__
#define __I_GENERIC_RULEBASE_H__

#include <vector>

#include "generic_rulebase/parameters_config.h"
#include "generic_rulebase/zone.h"
#include "config.h"

class I_GenericRulebase
{
public:
    virtual Maybe<Zone, Config::Errors> getLocalZone() const = 0;
    virtual Maybe<Zone, Config::Errors> getOtherZone() const = 0;

    using ParameterKeyValues = std::unordered_map<std::string, std::set<std::string>>;
    virtual std::set<ParameterBehavior> getBehavior(const ParameterKeyValues &key_value_pairs) const = 0;

protected:
    ~I_GenericRulebase() {}
};

#endif // __I_GENERIC_RULEBASE_H__
