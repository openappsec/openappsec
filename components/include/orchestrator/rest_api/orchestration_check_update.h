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

#ifndef __ORCHESTRATION_CHECK_UPDATE_H__
#define __ORCHESTRATION_CHECK_UPDATE_H__

#include <string>

#include "rest.h"
#include "maybe_res.h"

class CheckUpdateRequest : public ClientRest
{
public:
    class Tenants : public ClientRest
    {
    public:
        Tenants() = default;

        Tenants(const Tenants &other)
        {
            tenant_id = other.tenant_id;
            checksum = other.checksum;
            version = other.version;
        }

        Tenants(const std::string &_tenant_id, const std::string &_checksum, const std::string &_version)
                :
            tenant_id(_tenant_id),
            checksum(_checksum),
            version(_version)
        {
        }

        bool
        operator==(const Tenants &other) const
        {
            return
                tenant_id.get() == other.tenant_id.get() &&
                checksum.get() == other.checksum.get() &&
                version.get() == other.version.get();
        }

        const std::string & getTenantID() const { return tenant_id.get(); }
        const std::string & getChecksum() const { return checksum.get();  }
        const std::string & getVersion() const  { return version.get();   }

    private:
        BOTH_LABEL_PARAM(std::string, tenant_id, "tenantId");
        BOTH_LABEL_PARAM(std::string, checksum,  "checksum");
        BOTH_LABEL_PARAM(std::string, version, "version");
    };

    CheckUpdateRequest(
        const std::string &_manifest,
        const std::string &_policy,
        const std::string &_settings,
        const std::string &_data,
        const std::string &_checksum_type,
        const std::string &_policy_version)
            :
        manifest(_manifest),
        policy(_policy),
        settings(_settings),
        data(_data),
        checksum_type(_checksum_type),
        policy_version(_policy_version)
    {
        out_virtual_policy.setActive(true);
        out_virtual_settings.setActive(true);
    }

    Maybe<std::string>
    getManifest() const
    {
        if (manifest.get().empty()) return genError("No manifest");
        return manifest.get();
    }

    Maybe<std::string>
    getPolicy() const
    {
        if (policy.get().empty()) return genError("No policy");
        return policy.get();
    }

    Maybe<std::string>
    getSettings() const
    {
        if (settings.get().empty()) return genError("No settings");
        return settings.get();
    }

    Maybe<std::string>
    getData() const
    {
        if (data.get().empty()) return genError("No data");
        return data.get();
    }

    Maybe<std::vector<Tenants>>
    getVirtualPolicy() const
    {
        if (!in_virtual_policy.isActive()) return genError("no virtual policy is found");
        return in_virtual_policy.get().getTenants();
    }

    Maybe<std::vector<Tenants>>
    getVirtualSettings() const
    {
        if (!in_virtual_settings.isActive()) return genError("no virtual settings are found");
        return in_virtual_settings.get().getTenants();
    }

    template <typename ...Args>
    void
    addTenantPolicy(Args ...args)
    {
        if (!out_virtual_policy.isActive()) out_virtual_policy.setActive(true);
        out_virtual_policy.get().addTenant(std::forward<Args>(args)...);
    }

    template <typename ...Args>
    void
    addTenantSettings(Args ...args)
    {
        if (!out_virtual_settings.isActive()) out_virtual_settings.setActive(true);
        out_virtual_settings.get().addTenant(std::forward<Args>(args)...);
    }

    void setGreedyMode() { check_all_tenants = true; }

private:
    class VirtualConfig : public ClientRest
    {
    public:
        VirtualConfig()
        {
            tenants.setActive(true);
        }

        template <typename ...Args>
        void
        addTenant(Args ...args)
        {
            if (!tenants.isActive()) tenants.setActive(true);
            tenants.get().emplace_back(std::forward<Args>(args)...);
        }

        const std::vector<Tenants> & getTenants() const { return tenants.get(); }

    private:
        BOTH_LABEL_PARAM(std::vector<Tenants>, tenants, "tenants");
    };

    BOTH_LABEL_PARAM(std::string, manifest, "manifest");
    BOTH_LABEL_PARAM(std::string, policy,   "policy");
    BOTH_LABEL_PARAM(std::string, settings, "settings");
    BOTH_LABEL_OPTIONAL_PARAM(std::string, data, "data");

    C2S_LABEL_OPTIONAL_PARAM(VirtualConfig, out_virtual_settings,  "virtualSettings");
    C2S_LABEL_OPTIONAL_PARAM(VirtualConfig, out_virtual_policy,    "virtualPolicy");
    BOTH_LABEL_OPTIONAL_PARAM(bool, check_all_tenants,             "checkForAllTenants");

    C2S_LABEL_PARAM(std::string, checksum_type,  "checksum-type");
    C2S_LABEL_PARAM(std::string, policy_version, "policyVersion");

    S2C_LABEL_OPTIONAL_PARAM(VirtualConfig, in_virtual_policy,    "virtualPolicy");
    S2C_LABEL_OPTIONAL_PARAM(VirtualConfig, in_virtual_settings,  "virtualSettings");
};

#endif // __ORCHESTRATION_CHECK_UPDATE_H__
