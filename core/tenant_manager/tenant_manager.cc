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

#include "tenant_manager.h"

#include <string>
#include <vector>
#include <chrono>
#include <map>

#include "cache.h"
#include "config.h"
#include "tenant_profile_pair.h"
#include "hash_combine.h"

using namespace std;
using ProfilesPerTenantMap = map<string, set<string>>;

USE_DEBUG_FLAG(D_TENANT_MANAGER);

class AccountRegionPair
{
public:
    void
    load(cereal::JSONInputArchive &ar)
    {
        ar(
            cereal::make_nvp("accountId", accountID),
            cereal::make_nvp("regionName", regionName)
        );
    }

    bool
    operator<(const AccountRegionPair &other) const {
        return accountID < other.getAccountID() && regionName < other.getRegion();
    }

    const string & getAccountID() const { return accountID; }
    const string & getRegion() const { return regionName; }

private:
    string accountID;
    string regionName;
};

class AccountRegionSet
{
public:
    void
    load(cereal::JSONInputArchive &ar)
    {
        cereal::load(ar, account_region_map);
    }

    const set<AccountRegionPair> & getAccoutRegionPairs() const { return account_region_map; }

private:
    set<AccountRegionPair> account_region_map;
};

class TenantManager::Impl
        :
    Singleton::Provide<I_TenantManager>::From<TenantManager>
{
public:
    void init();
    void fini();

    bool areTenantAndProfileActive(const string &tenant_id, const string &profile_id) const override;

    ProfilesPerTenantMap fetchActiveTenantsAndProfiles() const override;
    ProfilesPerTenantMap fetchAndUpdateActiveTenantsAndProfiles(bool update) override;
    set<string> fetchAllActiveTenants() const override;
    set<string> fetchActiveTenants() const override;
    set<string> getInstances(const string &tenant_id, const string &profile_id) const override;
    set<string> fetchProfileIds(const string &tenant_id) const override;

    void addActiveTenantAndProfile(const string &tenant_id, const string &profile_id) override;

    void deactivateTenant(const string &tenant_id, const string &profile_id) override;

    set<string> getProfileIdsForRegionAccount(
        const string &tenant_id,
        const string &region,
        const string &account
    ) const override;

    void
    addInstance(const string &tenant_id, const string &profile_id, const string &instace_id) override
    {
        auto tenant_profile_pair = TenantProfilePair(tenant_id, profile_id);
        auto tenant_cache = mapper.find(tenant_profile_pair);
        if (tenant_cache == mapper.end()) {
            tenant_cache = mapper.insert(make_pair(tenant_profile_pair, TemporaryCache<string, void>())).first;
        }

        tenant_cache->second.createEntry(instace_id);
    }

private:
    set<string> getAllTenants() const;
    set<string> fetchAllProfileIds(const string &tenant_id) const;
    set<string> getProfileIds(const string &tenant_id) const;

    TemporaryCache<TenantProfilePair, void> active_tenants;
    map<TenantProfilePair, TemporaryCache<string, void>> mapper;

    I_Messaging *i_messaging = nullptr;
    TenantManagerType type;
    ::Flags<MessageConnConfig> conn_flags;
};

class LoadNewTenants : public ServerRest
{
public:
    void
    doCall() override
    {
        auto i_tenant_manager = Singleton::Consume<I_TenantManager>::from<TenantManager>();
        i_tenant_manager->addActiveTenantAndProfile(tenant_id.get(), profile_id.get());
        i_tenant_manager->addInstance(tenant_id.get(), profile_id.get(), instance_id.get());
    }

private:
    C2S_LABEL_PARAM(string, tenant_id,   "tenantId");
    C2S_LABEL_PARAM(string, profile_id,  "profileId");
    C2S_LABEL_PARAM(string, instance_id, "instanceId");
};

class SendNewTenants : public ClientRest
{
public:
    SendNewTenants(const string &_tenant_id, const string &_profile_id)
            :
        tenant_id(_tenant_id),
        profile_id(_profile_id)
    {
        auto _instance_id = Singleton::Consume<I_InstanceAwareness>::by<TenantManager>()->getUniqueID();
        instance_id = _instance_id.ok() ? *_instance_id : "default";
    }

private:
    C2S_LABEL_PARAM(string, tenant_id,   "tenantId");
    C2S_LABEL_PARAM(string, profile_id,  "profileId");
    C2S_LABEL_PARAM(string, instance_id, "instanceId");
};

class FetchActiveTenants : public ServerRest
{
public:
    void
    doCall() override
    {
        active_tenants = Singleton::Consume<I_TenantManager>::from<TenantManager>()->fetchAllActiveTenants();
    }

    S2C_PARAM(set<string>, active_tenants);
};

class GetActiveTenants : public ClientRest
{
public:
    GetActiveTenants() : active_tenants() {};

    Maybe<string> genJson() const { return string("{}"); };

    S2C_PARAM(set<string>, active_tenants);
};

class FetchProfileIds : public ServerRest
{
public:
    void
    doCall() override
    {
        profile_ids = Singleton::Consume<I_TenantManager>::from<TenantManager>()->fetchProfileIds(tenant_id);
    }

    S2C_PARAM(set<string>, profile_ids);
    C2S_PARAM(string, tenant_id);
};

class GetProfileIds : public ClientRest
{
public:
    GetProfileIds(const string &_tenant_id) : profile_ids(), tenant_id(_tenant_id) {};

    S2C_PARAM(set<string>, profile_ids);
    C2S_PARAM(string, tenant_id);
};

void
TenantManager::Impl::init()
{
    auto is_orchestrator = Singleton::Consume<I_Environment>::by<TenantManager>()->get<bool>("Is Orchestrator");
    type = (is_orchestrator.ok() && *is_orchestrator) ? TenantManagerType::SERVER : TenantManagerType::CLIENT;

    conn_flags.setFlag(MessageConnConfig::ONE_TIME_CONN);
    i_messaging = Singleton::Consume<I_Messaging>::by<TenantManager>();

    if (type == TenantManagerType::SERVER) {
        auto rest = Singleton::Consume<I_RestApi>::by<TenantManager>();
        rest->addRestCall<LoadNewTenants>(RestAction::SET, "tenant-id");
        rest->addRestCall<FetchActiveTenants>(RestAction::SHOW, "active-tenants");
        rest->addRestCall<FetchProfileIds>(RestAction::SHOW, "profile-ids");
    }
}

void
TenantManager::Impl::fini()
{
    i_messaging = nullptr;
}

set<string>
TenantManager::Impl::getAllTenants() const
{
    dbgFlow(D_TENANT_MANAGER) << "Tenant Manager is a client. Requesting the active tenants";

    GetActiveTenants active_tenant;

    auto res = i_messaging->sendObject(
        active_tenant,
        I_Messaging::Method::POST,
        "127.0.0.1",
        7777,
        conn_flags,
        "/show-active-tenants"
    );

    if (!res) {
        i_messaging->sendObject(
            active_tenant,
            I_Messaging::Method::POST,
            "127.0.0.1",
            7778,
            conn_flags,
            "/show-active-tenants"
        );
    }

    return active_tenant.active_tenants.get();
}

set<string>
TenantManager::Impl::getProfileIds(const string &_tenant_id) const
{
    dbgFlow(D_TENANT_MANAGER) << "Tenant Manager is a client. Requesting the active profiles";

    GetProfileIds tenant_id(_tenant_id);

    auto res = i_messaging->sendObject(
        tenant_id,
        I_Messaging::Method::POST,
        "127.0.0.1",
        7777,
        conn_flags,
        "/show-profile-ids"
    );

    if (!res) {
        i_messaging->sendObject(
            tenant_id,
            I_Messaging::Method::POST,
            "127.0.0.1",
            7778,
            conn_flags,
            "/show-profile-ids"
        );
    }

    return tenant_id.profile_ids.get();
}


set<string>
TenantManager::Impl::getProfileIdsForRegionAccount(
    const string &tenant_id,
    const string &region,
    const string &account_id = "") const
{
    if (region.empty()) {
        dbgWarning(D_TENANT_MANAGER) << "Can't find the profile ID. Region is empty";
        return set<string>();
    }

    set<string> profile_ids = fetchProfileIds(tenant_id);

    dbgTrace(D_TENANT_MANAGER) << "Fetched " << profile_ids.size() << " profiles";

    auto i_env = Singleton::Consume<I_Environment>::by<TenantManager>();
    auto unset_tenant_on_exit = make_scope_exit([&]() { i_env->unsetActiveTenantAndProfile(); });

    set<string> profiles_to_return;
    for (const string &profile_id : profile_ids) {
        string account_dbg = account_id.empty() ? "" : (" in the account " + account_id);
        dbgDebug(D_TENANT_MANAGER)
            << "Checking if the profile ID: "
            << profile_id
            << " corresponds to the tenant ID:  "
            << tenant_id
            << " and the region "
            << region
            << account_dbg;

        i_env->setActiveTenantAndProfile(tenant_id, profile_id);

        auto maybe_account_region_set = getSetting<AccountRegionSet>("accountRegionSet");
        if (maybe_account_region_set.ok()) {
            auto account_region_set = maybe_account_region_set.unpack().getAccoutRegionPairs();
            if (account_region_set.empty()) {
                dbgTrace(D_TENANT_MANAGER) << "Old profile with new hook. Resolving to profile ID: " << profile_id;
                profiles_to_return.insert(profile_id);
                return profiles_to_return;
            }
            for (const AccountRegionPair &account : account_region_set) {
                if (region == account.getRegion() && (account_id.empty() || account_id == account.getAccountID())) {
                    dbgTrace(D_TENANT_MANAGER) << "Found a corresponding profile ID: " << profile_id;
                    profiles_to_return.insert(profile_id);
                }
            }
        } else {
            auto maybe_region = getSetting<string>("region");
            if (maybe_region.ok() && region == maybe_region.unpack()) {
                dbgDebug(D_TENANT_MANAGER) << "The region corresponds to profile ID " << profile_id;
                profiles_to_return.insert(profile_id);
                return profiles_to_return;
            } else {
                if (maybe_region.ok()) {
                    dbgTrace(D_TENANT_MANAGER)
                        << "The region does not corresponds to profile ID "
                        << profile_id
                        << " region "
                        << *maybe_region;
                } else {
                    dbgDebug(D_TENANT_MANAGER) << "Failed to match profile ID by accountRegionSet or region";
                }
            }
        }
    }

    if (!profiles_to_return.empty()) {
        dbgDebug(D_TENANT_MANAGER) << "Found " << profiles_to_return.size() << " profiles that correspond";
        return profiles_to_return;
    }

    dbgWarning(D_TENANT_MANAGER) << "Found no corresponding profile ID";
    return set<string>();
}

bool
TenantManager::Impl::areTenantAndProfileActive(const string &tenant_id, const string &profile_id) const
{
    return active_tenants.doesKeyExists(TenantProfilePair(tenant_id, profile_id));
}

void
TenantManager::Impl::addActiveTenantAndProfile(const string &tenant_id, const string &profile_id)
{
    if (tenant_id.empty() || profile_id.empty()) {
        dbgWarning(D_TENANT_MANAGER) << "Tenant ID and Profile ID should not be empty.";
        return;
    }
    auto tenant_profile = TenantProfilePair(tenant_id, profile_id);
    dbgTrace(D_TENANT_MANAGER)
        << "Adding an active tenant and profile. Tenant ID: "
        << tenant_id
        << ", Profile ID: "
        << profile_id;
    active_tenants.createEntry(tenant_profile);
}

void
TenantManager::Impl::deactivateTenant(const string &tenant_id, const string &profile_id)
{
    dbgTrace(D_TENANT_MANAGER)
        << "Deactivate tenant and profile. Tenant ID: "
        << tenant_id
        << ", Profile ID: "
        << profile_id;
    active_tenants.deleteEntry(TenantProfilePair(tenant_id, profile_id));
}

ProfilesPerTenantMap
TenantManager::Impl::fetchAndUpdateActiveTenantsAndProfiles(bool update)
{
    if (!update) return fetchActiveTenantsAndProfiles();

    active_tenants.clear();
    ProfilesPerTenantMap update_active_tenants = fetchActiveTenantsAndProfiles();
    for (const auto &tenant_profile_set : update_active_tenants) {
        auto tenant_id = tenant_profile_set.first;
        for (const auto &profile_id : tenant_profile_set.second) {
            active_tenants.createEntry(TenantProfilePair(tenant_id, profile_id));
        }
    }
    return update_active_tenants;
}

ProfilesPerTenantMap
TenantManager::Impl::fetchActiveTenantsAndProfiles() const
{
    dbgFlow(D_TENANT_MANAGER) << "Fetching active teants and profiles map";
    ProfilesPerTenantMap active_tenants_and_profiles;
    set<string> tenants = fetchAllActiveTenants();
    for (const string &tenant : tenants) {
        active_tenants_and_profiles[tenant] = fetchProfileIds(tenant);
    }

    return active_tenants_and_profiles;
}

set<string>
TenantManager::Impl::fetchAllActiveTenants() const
{
    dbgFlow(D_TENANT_MANAGER) << "Fetching all active tenants";
    return (type == TenantManagerType::CLIENT) ? getAllTenants() : fetchActiveTenants();
}

set<string>
TenantManager::Impl::fetchActiveTenants() const
{
    dbgFlow(D_TENANT_MANAGER) << "Tenant Manager is a server. Fetching active tenants";
    set<string> tenants;
    for (const auto &iter : active_tenants) {
        dbgDebug(D_TENANT_MANAGER) << "Found a tenant to return. Tenant ID: " << iter.first.getTenantId();
        tenants.insert(iter.first.getTenantId());
    }

    return tenants;
}

set<string>
TenantManager::Impl::getInstances(const string &tenant_id, const string &profile_id) const
{
    set<string> instances;
    auto tenant_profile_pair = TenantProfilePair(tenant_id, profile_id);
    auto tenant_instance_cache = mapper.find(tenant_profile_pair);

    if (tenant_instance_cache == mapper.end()) return instances;

    for (auto iter = begin(tenant_instance_cache->second); iter != end(tenant_instance_cache->second); iter++) {
        instances.insert(iter->first);
    }
    return instances;
}

set<string>
TenantManager::Impl::fetchAllProfileIds(const string &tenant_id) const
{
    set<string> tenant_profile_ids;

    for (auto iter = begin(active_tenants); iter != end(active_tenants); iter++) {
        if (iter->first.getTenantId() == tenant_id) {
            dbgTrace(D_TENANT_MANAGER) << "Returning a fetched profile ID: " << iter->first.getProfileId();
            tenant_profile_ids.insert(iter->first.getProfileId());
        }
    }
    return tenant_profile_ids;
}

set<string>
TenantManager::Impl::fetchProfileIds(const string &tenant_id) const
{
    dbgFlow(D_TENANT_MANAGER) << "Fetching all profile IDs for tenant " << tenant_id;
    return (type == TenantManagerType::CLIENT) ? getProfileIds(tenant_id) : fetchAllProfileIds(tenant_id);
}

TenantManager::TenantManager()
        :
    Component("TenantManager"),
    pimpl(make_unique<Impl>())
{
}

TenantManager::~TenantManager() {}

void
TenantManager::init()
{
    pimpl->init();
}

void
TenantManager::fini()
{
    pimpl->fini();
}

void
TenantManager::preload()
{
    registerExpectedConfiguration<string>("Tenant Manager", "Tenant manager type");
    registerExpectedSetting<AccountRegionSet>("accountRegionSet");
    registerExpectedSetting<string>("region");
}
