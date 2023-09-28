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
#include "debug.h"
#include "maybe_res.h"

USE_DEBUG_FLAG(D_ORCHESTRATOR);

class TenantError : public ClientRest
{
public:
    TenantError() = default;

    bool
    operator==(const TenantError &other) const
    {
        return
            messageId.get() == other.messageId.get() &&
            message.get() == other.message.get() &&
            referenceId.get() == other.referenceId.get() &&
            severity.get() == other.severity.get();
    }

    const std::string & getMessageID() const { return messageId.get(); }
    const std::string & getMessage() const { return message.get(); }
// LCOV_EXCL_START Reason: Will be covered in INXT-33277
    const std::string & getReferenceID() const { return referenceId.get(); }
// LCOV_EXCL_STOP
    const std::string & getSeverity() const { return severity.get(); }

private:
    BOTH_LABEL_PARAM(std::string, messageId, "messageId");
    BOTH_LABEL_PARAM(std::string, message,  "message");
    BOTH_LABEL_PARAM(std::string, referenceId, "referenceId");
    BOTH_LABEL_PARAM(std::string, severity, "severity");
};

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
            profile_id = other.profile_id;
            checksum = other.checksum;
            version = other.version;
            error = other.error;
        }

        Tenants(
            const std::string &_tenant_id,
            const std::string &_profile_id,
            const std::string &_checksum,
            const std::string &_version)
                :
            tenant_id(_tenant_id),
            profile_id(_profile_id),
            checksum(_checksum),
            version(_version)
        {
        }

        bool
        operator==(const Tenants &other) const
        {
            return
                tenant_id.get() == other.tenant_id.get() &&
                profile_id.get() == other.profile_id.get() &&
                checksum.get() == other.checksum.get() &&
                version.get() == other.version.get() &&
                error.get() == other.error.get();
        }

        const std::string & getTenantID() const { return tenant_id.get(); }
        const std::string & getProfileID() const { return profile_id.get(); }
        const std::string & getChecksum() const { return checksum.get(); }
        const std::string & getVersion() const { return version.get(); }
        const TenantError & getError() const { return error.get(); }

    private:
        BOTH_LABEL_OPTIONAL_PARAM(std::string, tenant_id, "tenantId");
        BOTH_LABEL_OPTIONAL_PARAM(std::string, profile_id, "profileId");
        BOTH_LABEL_OPTIONAL_PARAM(std::string, checksum,  "checksum");
        BOTH_LABEL_OPTIONAL_PARAM(std::string, version, "version");
        BOTH_LABEL_OPTIONAL_PARAM(TenantError, error, "error");
    };

    class UpgradeSchedule : public ClientRest
    {
    public:
        UpgradeSchedule() = default;

        UpgradeSchedule(const UpgradeSchedule &other)
        {
            mode = other.mode;
            time = other.time;
            duration_hours = other.duration_hours;
            days = other.days;
        }

        UpgradeSchedule &
        operator=(const UpgradeSchedule &other)
        {
            if (this != &other) {
                mode = other.mode;
                time = other.time;
                duration_hours = other.duration_hours;
                days = other.days;
            }
            return *this;
        }

        void init(const std::string &_upgrade_mode) { mode = _upgrade_mode; }

        void
        init(
            const std::string &_upgrade_mode,
            const std::string &_upgrade_time,
            const uint &_upgrade_duration_hours)
        {
            init(_upgrade_mode);
            time = _upgrade_time;
            duration_hours = _upgrade_duration_hours;
        }

        void
        init(
            const std::string &_upgrade_mode,
            const std::string &_upgrade_time,
            const uint &_upgrade_duration_hours,
            const std::vector<std::string> &_upgrade_days)
        {
            init(_upgrade_mode, _upgrade_time, _upgrade_duration_hours);
            days = _upgrade_days;
        }

    private:
        C2S_LABEL_PARAM(std::string, mode, "upgradeMode");
        C2S_LABEL_OPTIONAL_PARAM(std::string, time, "upgradeTime");
        C2S_LABEL_OPTIONAL_PARAM(uint, duration_hours, "upgradeDurationHours");
        C2S_LABEL_OPTIONAL_PARAM(std::vector<std::string>, days, "upgradeDay");
    };

    class LocalConfigurationSettings : public ClientRest
    {
    public:
        LocalConfigurationSettings() = default;

        void
        setUpgradeSchedule(const UpgradeSchedule &schedule)
        {
            upgrade_schedule.setActive(true);
            upgrade_schedule.get() = schedule;
        }

    private:
        C2S_LABEL_OPTIONAL_PARAM(UpgradeSchedule, upgrade_schedule, "upgradeSchedule");
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

    void
    setUpgradeFields(const std::string &_upgrade_mode)
    {
        UpgradeSchedule upgrade_schedule;
        upgrade_schedule.init(_upgrade_mode);
        local_configuration_settings.setActive(true);
        local_configuration_settings.get().setUpgradeSchedule(upgrade_schedule);
    }

    void
    setUpgradeFields(
        const std::string &_upgrade_mode,
        const std::string &_upgrade_time,
        const uint &_upgrade_duration_hours,
        const std::vector<std::string> &_upgrade_days)
    {
        UpgradeSchedule upgrade_schedule;
        if (!_upgrade_days.empty()) {
            upgrade_schedule.init(_upgrade_mode, _upgrade_time, _upgrade_duration_hours, _upgrade_days);
        } else {
            upgrade_schedule.init(_upgrade_mode, _upgrade_time, _upgrade_duration_hours);
        }
        local_configuration_settings.setActive(true);
        local_configuration_settings.get().setUpgradeSchedule(upgrade_schedule);
    }

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

        const std::vector<Tenants>
        getTenants() const
        {
            std::vector<Tenants> tenants_to_return;
            for (const auto &tenant : tenants.get()) {
                if (tenant.getError().getMessage().empty()) {
                    tenants_to_return.push_back(tenant);
                    continue;
                }

                dbgError(D_ORCHESTRATOR)
                    << "Error getting the tenant information. Tenant ID: "
                    << tenant.getTenantID()
                    << ", Error message: "
                    << tenant.getError().getMessage()
                    << ", Reference ID: "
                    << tenant.getError().getReferenceID();
            }
            return tenants_to_return;
        }

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

    C2S_LABEL_OPTIONAL_PARAM(LocalConfigurationSettings, local_configuration_settings, "localConfigurationSettings");

    S2C_LABEL_OPTIONAL_PARAM(VirtualConfig, in_virtual_policy,    "virtualPolicy");
    S2C_LABEL_OPTIONAL_PARAM(VirtualConfig, in_virtual_settings,  "virtualSettings");
};

#endif // __ORCHESTRATION_CHECK_UPDATE_H__
