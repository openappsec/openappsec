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

#ifndef __INTELLIGENCE_FILTER_H__
#define __INTELLIGENCE_FILTER_H__

#include "rest.h"
#include "common.h"
#include "intelligence_is/intelligence_types.h"

class IntelligenceFilter
{
public:
    IntelligenceFilter(
        const std::string &key,
        const std::string &value,
        Intelligence_IS::AttributeKeyType type= Intelligence_IS::AttributeKeyType::NONE
    );

    void addFilter(
        const std::string &key,
        const std::string &value,
        Intelligence_IS::AttributeKeyType type= Intelligence_IS::AttributeKeyType::NONE
    );

    std::string getQuery(bool is_encoded = true) const;
    const std::set<std::pair<std::string, std::string>> & getFilters() const;

    void addRequestedAttr(
        const std::string &attr,
        Intelligence_IS::AttributeKeyType type = Intelligence_IS::AttributeKeyType::NONE
    );

    const std::set<std::string> & getRequestedAttr() const;
    std::string getRequestedAttrStr() const;

private:
    std::string
    createAttrString(
        const std::string &value,
        bool use_quotes,
        Intelligence_IS::AttributeKeyType type = Intelligence_IS::AttributeKeyType::NONE
    ) const;

    std::set<std::pair<std::string, std::string>> query;
    std::set<std::string> requested_attr;
};
#endif // __INTELLIGENCE_FILTER_H__
