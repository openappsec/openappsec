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

USE_DEBUG_FLAG(D_TENANT_MANAGER);

class TenantManager::Impl
        :
    Singleton::Provide<I_TenantManager>::From<TenantManager>
{
public:
    void init();
    void fini();

    void uponNewTenants(const newTenantCB &cb) override;
    bool areTenantAndProfileActive(const string &tenant_id, const string &profile_id) const override;

    vector<string> fetchAllActiveTenants() const override;
    vector<string> fetchActiveTenants() const override;
    vector<string> getInstances(const string &tenant_id, const string &profile_id) const override;
    vector<string> fetchProfileIds(const string &tenant_id) const override;

    void addActiveTenantAndProfile(const string &tenant_id, const string &profile_id) override;

    void deactivateTenant(const string &tenant_id, const string &profile_id) override;

    chrono::microseconds getTimeoutVal() const override;

    void
    addInstance(const string &tenant_id, const string &profile_id, const string &instace_id)
    {
        auto tenant_profile_pair = TenantProfilePair(tenant_id, profile_id);
        auto tenant_cache = mapper.find(tenant_profile_pair);
        if (tenant_cache == mapper.end()) {
            tenant_cache = mapper.insert(make_pair(tenant_profile_pair, TemporaryCache<string, void>())).first;
            tenant_cache->second.startExpiration(
                getTimeoutVal(),
                Singleton::Consume<I_MainLoop>::by<TenantManager>(),
                Singleton::Consume<I_TimeGet>::by<TenantManager>()
            );
        }

        tenant_cache->second.createEntry(instace_id);
    }

private:
    void runUponNewTenants(const vector<string> &new_tenants);
    void sendTenantAndProfile(const string &tenant_id, const string &profile_id);
    vector<string> getAllTenants() const;
    vector<string> fetchAllProfileIds(const string &tenant_id) const;
    vector<string> getProfileIds(const string &profile_id) const;
    bool sendWithCustomPort(const string &tenant_id, const string &profile_id, const uint16_t port);

    TemporaryCache<TenantProfilePair, void> active_tenants;
    map<TenantProfilePair, TemporaryCache<string, void>> mapper;
    vector<I_TenantManager::newTenantCB> upon_cb;

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

    S2C_PARAM(std::vector<std::string>, active_tenants);
};

class GetActiveTenants : public ClientRest
{
public:
    GetActiveTenants() : active_tenants() {};

    Maybe<string> genJson() const { return string("{}"); };

    S2C_PARAM(vector<string>, active_tenants);
};

class FetchProfileIds : public ServerRest
{
public:
    void
    doCall() override
    {
        profile_ids = Singleton::Consume<I_TenantManager>::from<TenantManager>()->fetchProfileIds(tenant_id);
    }

    S2C_PARAM(vector<string>, profile_ids);
    C2S_PARAM(string, tenant_id);
};

class GetProfileIds : public ClientRest
{
public:
    GetProfileIds(const string &_tenant_id) : profile_ids(), tenant_id(_tenant_id) {};

    S2C_PARAM(vector<string>, profile_ids);
    C2S_PARAM(string, tenant_id);
};

void
TenantManager::Impl::init()
{
    auto is_orchestrator = Singleton::Consume<I_Environment>::by<TenantManager>()->get<bool>("Is Orchestrator");
    type = (is_orchestrator.ok() && *is_orchestrator) ? TenantManagerType::SERVER : TenantManagerType::CLIENT;

    conn_flags.setFlag(MessageConnConfig::ONE_TIME_CONN);
    i_messaging = Singleton::Consume<I_Messaging>::by<TenantManager>();

    auto cache_timeout = getTimeoutVal();

    active_tenants.startExpiration(
        cache_timeout,
        Singleton::Consume<I_MainLoop>::by<TenantManager>(),
        Singleton::Consume<I_TimeGet>::by<TenantManager>()
    );

    if (type == TenantManagerType::SERVER) {
        auto rest = Singleton::Consume<I_RestApi>::by<TenantManager>();
        rest->addRestCall<LoadNewTenants>(RestAction::SET, "tenant-id");
        rest->addRestCall<FetchActiveTenants>(RestAction::SHOW, "active-tenants");
        rest->addRestCall<FetchActiveTenants>(RestAction::SHOW, "profile-ids");
    }

    if (type == TenantManagerType::CLIENT) {
        auto interval = chrono::seconds(
            getProfileAgentSettingWithDefault<uint32_t>(600, "agentConfig.tenantReportIntervalSeconds")
        );
        interval = chrono::seconds(
            getConfigurationWithDefault(interval.count(), "Tenant Manager", "Report interval")
        );

        Singleton::Consume<I_MainLoop>::by<TenantManager>()->addRecurringRoutine(
            I_MainLoop::RoutineType::System,
            interval,
            [this] ()
            {
                auto tenants_ids = fetchActiveTenants();
                for (auto tenant_id : tenants_ids) {
                    auto profile_ids = fetchAllProfileIds(tenant_id);
                    for (auto profile_id : profile_ids) {
                        sendTenantAndProfile(tenant_id, profile_id);
                    }
                }
            },
            "Tenant manager client reporter"
        );
    }
}

void
TenantManager::Impl::fini()
{
    active_tenants.endExpiration();
    i_messaging = nullptr;
}

bool
TenantManager::Impl::sendWithCustomPort(const string &tenant_id, const string &profile_id, const uint16_t port)
{
    if (i_messaging == nullptr) {
        i_messaging = Singleton::Consume<I_Messaging>::by<TenantManager>();
    }

    SendNewTenants new_tenant_and_profile(tenant_id, profile_id);

    return i_messaging->sendNoReplyObject(
        new_tenant_and_profile,
        I_Messaging::Method::POST,
        "127.0.0.1",
        port,
        conn_flags,
        "/set-tenant-id"
    );
}

void
TenantManager::Impl::runUponNewTenants(const vector<string> &new_tenants)
{
    for (auto &cb: upon_cb) {
        Singleton::Consume<I_MainLoop>::by<TenantManager>()->addOneTimeRoutine(
            I_MainLoop::RoutineType::System,
            [this, cb, new_tenants] () { cb(new_tenants); },
            "New tenant event handler"
        );
    }
}

void
TenantManager::Impl::sendTenantAndProfile(const string &tenant_id, const string &profile_id)
{
    auto res = sendWithCustomPort(
        tenant_id,
        profile_id,
        getConfigurationWithDefault<uint16_t>(
            7777,
            "Tenant Manager",
            "Orchestrator's primary port"
        )
    );

    if (!res) {
        sendWithCustomPort(
            tenant_id,
            profile_id,
            getConfigurationWithDefault<uint16_t>(
                7778,
                "Tenant Manager",
                "Orchestrator's secondary port"
            )
        );
    }
}

vector<string>
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

vector<string>
TenantManager::Impl::getProfileIds(const string &tenant_id) const
{
    dbgFlow(D_TENANT_MANAGER) << "Tenant Manager is a client. Requesting the active tenants";

    GetProfileIds profile_id(tenant_id);

    auto res = i_messaging->sendObject(
        profile_id,
        I_Messaging::Method::POST,
        "127.0.0.1",
        7777,
        conn_flags,
        "/show-profile-ids"
    );

    if (!res) {
        i_messaging->sendObject(
            profile_id,
            I_Messaging::Method::POST,
            "127.0.0.1",
            7778,
            conn_flags,
            "/show-profile-ids"
        );
    }

    return profile_id.profile_ids.get();
}

void
TenantManager::Impl::uponNewTenants(const newTenantCB &cb)
{
    upon_cb.push_back(cb);
}

bool
TenantManager::Impl::areTenantAndProfileActive(const string &tenant_id, const string &profile_id) const
{
    return active_tenants.doesKeyExists(TenantProfilePair(tenant_id, profile_id));
}

void
TenantManager::Impl::addActiveTenantAndProfile(const string &tenant_id, const string &profile_id)
{
    auto tenant_profile = TenantProfilePair(tenant_id, profile_id);
    active_tenants.createEntry(tenant_profile);
    if (type == TenantManagerType::CLIENT) {
        sendTenantAndProfile(tenant_id, profile_id);
    } else {
        runUponNewTenants({tenant_id});
    }
}

void
TenantManager::Impl::deactivateTenant(const string &tenant_id, const string &profile_id)
{
    active_tenants.deleteEntry(TenantProfilePair(tenant_id, profile_id));
}

vector<string>
TenantManager::Impl::fetchAllActiveTenants() const
{
    dbgFlow(D_TENANT_MANAGER) << "Fetching all active tenants";
    return (type == TenantManagerType::CLIENT) ? getAllTenants() : fetchActiveTenants();
}

vector<string>
TenantManager::Impl::fetchActiveTenants() const
{
    dbgFlow(D_TENANT_MANAGER) << "Tenant Manager is a server. Fetching active tenants";
    vector<string> tenants;
    tenants.reserve(active_tenants.size());
    for (auto iter = begin(active_tenants); iter != end(active_tenants); iter++) {
        dbgDebug(D_TENANT_MANAGER) << "Found a tenant to return. Tenant ID: " << iter->first.getTenantId();
        tenants.push_back(iter->first.getTenantId());
    }

    return tenants;
}

vector<string>
TenantManager::Impl::getInstances(const string &tenant_id, const string &profile_id) const
{
    vector<string> instances;
    auto tenant_profile_pair = TenantProfilePair(tenant_id, profile_id);
    auto tenant_instance_cache = mapper.find(tenant_profile_pair);

    if (tenant_instance_cache == mapper.end()) return instances;

    instances.reserve(tenant_instance_cache->second.size());
    for (auto iter = begin(tenant_instance_cache->second); iter != end(tenant_instance_cache->second); iter++) {
        instances.push_back(iter->first);
    }
    return instances;
}

vector<string>
TenantManager::Impl::fetchAllProfileIds(const string &tenant_id) const
{
    vector<string> tenant_profile_ids;

    for (auto iter = begin(active_tenants); iter != end(active_tenants); iter++) {
        if (iter->first.getTenantId() == tenant_id) {
            tenant_profile_ids.push_back(iter->first.getPfofileId());
        }
    }
    return tenant_profile_ids;
}

vector<string>
TenantManager::Impl::fetchProfileIds(const string &tenant_id) const
{
    dbgFlow(D_TENANT_MANAGER) << "Fetching all profile ids for tenant " << tenant_id;
    return (type == TenantManagerType::CLIENT) ? getProfileIds(tenant_id) : fetchAllProfileIds(tenant_id);
}

chrono::microseconds
TenantManager::Impl::getTimeoutVal() const
{
    auto cache_timeout = chrono::seconds(
        getProfileAgentSettingWithDefault<uint32_t>(900, "Orchestration.TenantTimeoutSeconds")
    );
    cache_timeout = chrono::seconds(
        getConfigurationWithDefault(cache_timeout.count(), "Tenant Manager", "Tenant timeout")
    );

    return chrono::duration_cast<chrono::microseconds>(cache_timeout);
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
    registerExpectedConfiguration<uint32_t>("Tenant Manager", "Tenant timeout");
    registerExpectedConfiguration<string>("Tenant Manager", "Tenant manager type");
}
