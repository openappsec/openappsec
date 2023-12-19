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

#include "new_auto_upgrade.h"

using namespace std;

USE_DEBUG_FLAG(D_LOCAL_POLICY);

static const set<string> valid_modes = {"automatic", "manual", "scheduled"};
static const set<string> valid_days_of_week = {
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday"
};

class AppSecScheduledUpgrade
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        parseAppsecJSONKey<vector<string>>("days", days, archive_in);
        for (const string &day : days) {
            if (valid_days_of_week.count(day) == 0) {
                dbgWarning(D_LOCAL_POLICY) << "AppSec upgrade day invalid: " << day;
            }
        }
        parseAppsecJSONKey<string>("upgradeWindowStartHourUTC", upgrade_window_start_hour_UTC, archive_in, "0:00");
        parseAppsecJSONKey<uint>("upgradeWindowDuration", upgrade_window_duration, archive_in, 4);
    }

    const vector<string> &
    getDays() const
    {
        return days;
    }

    const string &
    getUpgradeWindowStartHourUTC() const
    {
        return upgrade_window_start_hour_UTC;
    }

    const uint &
    getUpgradeWindowDuration() const
    {
        return upgrade_window_duration;
    }

private:
    vector<string> days;
    string upgrade_window_start_hour_UTC = "0:00";
    uint upgrade_window_duration = 4;
};

void
AppSecAutoUpgradeSpec::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec upgrade settings spec";
    parseAppsecJSONKey<string>("appsecClassName", appsec_class_name, archive_in);
    parseAppsecJSONKey<string>("name", name, archive_in);
    parseAppsecJSONKey<string>("mode", mode, archive_in);
    if (valid_modes.count(mode) == 0) {
        dbgWarning(D_LOCAL_POLICY) << "AppSec upgrade mode invalid: " << mode;
    }
    if (mode != "scheduled") return;

    AppSecScheduledUpgrade schedule;
    parseAppsecJSONKey<AppSecScheduledUpgrade>("schedule", schedule, archive_in);
    days = schedule.getDays();
    upgrade_window_start_hour_UTC = schedule.getUpgradeWindowStartHourUTC();
    upgrade_window_duration = schedule.getUpgradeWindowDuration();
}

void
AppSecAutoUpgradeSpec::save(cereal::JSONOutputArchive& out_ar) const
{
    out_ar(cereal::make_nvp("upgradeMode", mode));
    if (mode != "scheduled") return;
    out_ar(
        cereal::make_nvp("upgradeTime", upgrade_window_start_hour_UTC),
        cereal::make_nvp("upgradeDurationHours", upgrade_window_duration),
        cereal::make_nvp("upgradeDay", days)
    );
}

void
AppSecAutoUpgradeSpec::setName(const string &_name)
{
    name = _name;
}

const string &
AppSecAutoUpgradeSpec::getName() const
{
    return name;
}

const string &
AppSecAutoUpgradeSpec::getAppSecClassName() const
{
    return appsec_class_name;
}
