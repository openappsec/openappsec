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
#include <chrono>
#include <functional>

class I_TenantManager
{
public:
    using newTenantCB = std::function<void(const std::vector<std::string> &)>;

    virtual void uponNewTenants(const newTenantCB &cb) = 0;
    virtual bool areTenantAndProfileActive(const std::string &tenant_id, const std::string &profile_id) const = 0;

    virtual std::vector<std::string> fetchActiveTenants() const = 0;
    virtual std::vector<std::string> fetchAllActiveTenants() const = 0;
    virtual std::vector<std::string> getInstances(
        const std::string &tenant_id,
        const std::string &profile_id
    ) const = 0;
    virtual std::vector<std::string> fetchProfileIds(const std::string &tenant_id) const = 0;

    virtual void deactivateTenant(const std::string &tenant_id, const std::string &profile_id) = 0;

    virtual void addActiveTenantAndProfile(const std::string &tenant_id, const std::string &profile_id) = 0;

    virtual std::chrono::microseconds getTimeoutVal() const = 0;

    virtual std::string getProfileId(const std::string &tenant_id, const std::string &region) const = 0;

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
