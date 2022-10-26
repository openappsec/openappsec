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

#ifndef __ZONES_CONFIG_H__
#define __ZONES_CONFIG_H__

#include <vector>
#include <string>
#include <set>
#include <arpa/inet.h>

#include "generic_rulebase_context.h"
#include "match_query.h"
#include "i_generic_rulebase.h"
#include "zone.h"

class Zones
{
public:
    void load(cereal::JSONInputArchive &archive_in)
    {
        cereal::load(archive_in, zones);
    }

    const std::vector<Zone> & getZones() const { return zones; }

    std::vector<Zone> zones;
};

class ZonesConfig : Singleton::Consume<I_GenericRulebase>
{
public:
    static void preload();

    void load(cereal::JSONInputArchive &archive_in);

    const std::vector<Zone> & getZones() const { return zones; }

private:
    std::vector<Zone> zones;
};

#endif //__ZONES_CONFIG_H__
