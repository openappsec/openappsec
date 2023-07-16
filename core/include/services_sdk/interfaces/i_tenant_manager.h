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

#ifndef __I_TENANT_MANAGER_H__
#define __I_TENANT_MANAGER_H__

#include <string>
#include <vector>
#include <set>
#include <map>
#include <chrono>
#include <functional>

#include "tenant_profile_pair.h"

class I_TenantManager
{
public:
    virtual bool areTenantAndProfileActive(const std::string &tenant_id, const std::string &profile_id) const = 0;

    virtual std::set<std::string> fetchAllActiveTenants() const = 0;
    virtual std::set<std::string> fetchActiveTenants() const = 0;
    virtual std::set<std::string> getInstances(
        const std::string &tenant_id,
        const std::string &profile_id
    ) const = 0;
    virtual std::map<std::string, std::set<std::string>> fetchActiveTenantsAndProfiles() const = 0;
    virtual std::map<std::string, std::set<std::string>> fetchAndUpdateActiveTenantsAndProfiles(bool update) = 0;
    virtual std::set<std::string> fetchProfileIds(const std::string &tenant_id) const = 0;

    virtual void deactivateTenant(const std::string &tenant_id, const std::string &profile_id) = 0;

    virtual void addActiveTenantAndProfile(const std::string &tenant_id, const std::string &profile_id) = 0;

    virtual std::set<std::string> getProfileIdsForRegionAccount(
        const std::string &tenant_id,
        const std::string &region,
        const std::string &account_id = ""
    ) const = 0;

private:
    friend class LoadNewTenants;
    friend class LoadNewTenantsAndProfiles;
    virtual void addInstance(
        const std::string &tenant_id,
        const std::string &profile_id,
        const std::string &instace_id
    ) = 0;

protected:
    virtual ~I_TenantManager() {}
};

#endif // __I_TENANT_MANAGER_H__
