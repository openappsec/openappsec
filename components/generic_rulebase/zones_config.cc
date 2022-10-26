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

#include "generic_rulebase/zones_config.h"

#include <string>
#include <unordered_map>

#include "generic_rulebase/generic_rulebase_utils.h"
#include "config.h"
#include "ip_utilities.h"
#include "connkey.h"
#include "i_generic_rulebase.h"

USE_DEBUG_FLAG(D_RULEBASE_CONFIG);

using namespace std;

void
ZonesConfig::load(cereal::JSONInputArchive &archive_in)
{
    dbgFlow(D_RULEBASE_CONFIG) << "Saving active zones";
    set<string> used_zones;
    cereal::load(archive_in, used_zones);

    dbgTrace(D_RULEBASE_CONFIG) << "Loading all zones";
    auto all_zones_maybe = getSetting<Zones>("rulebase", "zones");
    if (!all_zones_maybe.ok()) {
        dbgWarning(D_RULEBASE_CONFIG) << "Failed to load zones";
        return;
    }

    dbgTrace(D_RULEBASE_CONFIG) << "Creating cache of all zones by ID";
    map<GenericConfigId, Zone> all_zones;
    for (const auto &single_zone : all_zones_maybe.unpack().zones) {
        if (used_zones.count(single_zone.getId()) > 0 && single_zone.isAnyZone()) {
            dbgTrace(D_RULEBASE_CONFIG) << "Found used zone of type \"Any\": saving all zones as active zones";
            zones = all_zones_maybe.unpack().zones;
            return;
        }

        dbgWarning(D_RULEBASE_CONFIG)
            << "Adding specific zone to cache. Zone ID: "
            << single_zone.getId()
            << ", name: "
            << single_zone.getName();
        all_zones.emplace(single_zone.getId(), single_zone);
    }

    dbgTrace(D_RULEBASE_CONFIG) << "Creating list of active zones";
    map<GenericConfigId, Zone> active_zones_set;
    for (const auto &single_used_zone_id : used_zones) {
        const auto &found_zone = all_zones[single_used_zone_id];
        dbgTrace(D_RULEBASE_CONFIG)
            << "Adding zone to list of active zones. Zone ID: "
            << single_used_zone_id
            << ", zone name: "
            << found_zone.getName();
        active_zones_set.emplace(found_zone.getId(), found_zone);

        for (const auto &adjacent_zone : found_zone.getAdjacentZones()) {
            const auto &adjacent_zone_obj = all_zones[adjacent_zone.second];
            dbgTrace(D_RULEBASE_CONFIG)
                << "Adding adjacent zone to list of active zones. Zone ID: "
                << adjacent_zone_obj.getId()
                << ", zone name: "
                << adjacent_zone_obj.getName();
            active_zones_set.emplace(adjacent_zone_obj.getId(), adjacent_zone_obj);
        }
    }

    vector<GenericConfigId> implied_zones = {
        "impliedAzure",
        "impliedDNS",
        "impliedSSH",
        "impliedProxy",
        "impliedFog"
    };

    GenericConfigId any_zone_id = "";
    for (const auto &single_zone : all_zones_maybe.unpack().zones) {
        if (single_zone.isAnyZone()) any_zone_id = single_zone.getId();
    }
    for (GenericConfigId &implied_id: implied_zones) {
        if (all_zones.find(implied_id) != all_zones.end()) {
            dbgWarning(D_RULEBASE_CONFIG) << "Adding implied zone to cache. Zone ID: " << implied_id;
            active_zones_set.emplace(implied_id, all_zones[implied_id]);
            if (any_zone_id != "" && active_zones_set.count(any_zone_id) == 0) {
                active_zones_set.emplace(any_zone_id, all_zones[any_zone_id]);
            }
        }
    }

    for (const auto &single_id_zone_pair : active_zones_set) {
        zones.push_back(single_id_zone_pair.second);
    }
}

void
ZonesConfig::preload()
{
    registerExpectedSetting<Zones>("rulebase", "zones");
    registerExpectedSetting<ZonesConfig>("rulebase", "usedZones");
}
