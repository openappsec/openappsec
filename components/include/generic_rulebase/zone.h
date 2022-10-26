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

#ifndef __ZONE_H__
#define __ZONE_H__

#include <vector>
#include <string>
#include <set>
#include <arpa/inet.h>

#include "generic_rulebase_context.h"
#include "match_query.h"
#include "i_environment.h"
#include "i_intelligence_is_v2.h"
#include "asset.h"

class Zone : Singleton::Consume<I_Intelligence_IS_V2>, Singleton::Consume<I_Environment>
{
    using AttrData = std::unordered_map<std::string, std::set<std::string>>;

public:
    enum class Direction { To, From, Bidirectional };

    void load(cereal::JSONInputArchive &archive_in);

    bool contains(const Asset &asset);

    GenericConfigId getId() const { return zone_id; }
    const std::string & getName() const { return zone_name; }
    const std::vector<std::pair<Direction, GenericConfigId>> & getAdjacentZones() const { return adjacent_zones; }
    const MatchQuery & getMatchQuery() const { return match_query; }
    bool isAnyZone() const { return is_any; }

private:
    bool matchAttributes(const AttrData &data);

    GenericConfigId zone_id;
    std::string zone_name;
    std::vector<std::pair<Direction, GenericConfigId>> adjacent_zones;
    MatchQuery match_query;
    bool is_any;
};

#endif // __ZONE_H__
