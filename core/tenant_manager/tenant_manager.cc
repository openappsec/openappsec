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

using namespace std;

class TenantManager::Impl
        :
    Singleton::Provide<I_TenantManager>::From<TenantManager>
{
public:
    void init();
    void fini();

    void uponNewTenants(const newTenantCB &cb) override;
    bool isTenantActive(const string &tenant_id) const override;

    vector<string> fetchActiveTenants() const override;
    vector<string> getInstances(const string &tenant_id) const override;

    void addActiveTenant(const string &tenant_id) override;
    void addActiveTenants(const vector<string> &tenants_id) override;

    void deactivateTenant(const string &tenant_id) override;
    void deactivateTenants(const vector<string> &tenants_id) override;

    chrono::microseconds getTimeoutVal() const override;

    void
    addInstance(const string &tenant_id, const string &instace_id)
    {
        auto tenant_cache = mapper.find(tenant_id);
        if (tenant_cache == mapper.end()) {
            tenant_cache = mapper.insert(make_pair(tenant_id, TemporaryCache<string, void>())).first;
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
    void sendTenant(const vector<string> &tenant_id);
    bool sendWithCustomPort(const vector<string>  &tenant_id, const uint16_t port);

    TemporaryCache<string, void> active_tenants;
    map<string, TemporaryCache<string, void>> mapper;
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
        i_tenant_manager->addActiveTenants(tenant_ids.get());
        for (const auto &tenant_id: tenant_ids.get()) {
            i_tenant_manager->addInstance(tenant_id, instance_id.get());
        }
    }

private:
    C2S_LABEL_PARAM(vector<string>, tenant_ids,  "tenantIds");
    C2S_LABEL_PARAM(string,         instance_id, "instanceId");
};

class SendNewTenants : public ClientRest
{
public:
    SendNewTenants(const vector<string> &_tenant_ids)
            :
        tenant_ids(_tenant_ids)
    {
        auto _instance_id = Singleton::Consume<I_InstanceAwareness>::by<TenantManager>()->getUniqueID();
        instance_id = _instance_id.ok() ? *_instance_id : "default";
    }

private:
    C2S_LABEL_PARAM(vector<string>, tenant_ids,  "tenantIds");
    C2S_LABEL_PARAM(string,         instance_id, "instanceId");
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
                auto tenants_id = fetchActiveTenants();
                sendTenant(tenants_id);
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
TenantManager::Impl::sendWithCustomPort(const vector<string> &tenants_id, const uint16_t port)
{
    if (i_messaging == nullptr) {
        i_messaging = Singleton::Consume<I_Messaging>::by<TenantManager>();
    }

    SendNewTenants new_tenants(tenants_id);

    return i_messaging->sendNoReplyObject(
        new_tenants,
        I_Messaging::Method::POST,
        "127.0.0.1",
        port,
        conn_flags,
        "set-tenant-id"
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
TenantManager::Impl::sendTenant(const vector<string> &tenants_id)
{
    auto res = sendWithCustomPort(
        tenants_id,
        getConfigurationWithDefault<uint16_t>(
            7777,
            "Tenant Manager",
            "Orchestrator's primary port"
        )
    );

    if (!res) {
        sendWithCustomPort(
            tenants_id,
            getConfigurationWithDefault<uint16_t>(
                7778,
                "Tenant Manager",
                "Orchestrator's secondary port"
            )
        );
    }
}

void
TenantManager::Impl::uponNewTenants(const newTenantCB &cb)
{
    upon_cb.push_back(cb);
}

bool
TenantManager::Impl::isTenantActive(const string &tenant_id) const
{
    return active_tenants.doesKeyExists(tenant_id);
}

void
TenantManager::Impl::addActiveTenant(const string &tenant_id)
{
    active_tenants.createEntry(tenant_id);
    if (type == TenantManagerType::CLIENT) {
        sendTenant({tenant_id});
    } else {
        runUponNewTenants({tenant_id});
    }
}

void
TenantManager::Impl::addActiveTenants(const vector<string> &tenants_id)
{
    for (const auto &tenant_id: tenants_id) active_tenants.createEntry(tenant_id);
    if (type == TenantManagerType::CLIENT) {
        sendTenant(tenants_id);
    } else {
        runUponNewTenants(tenants_id);
    }
}

void
TenantManager::Impl::deactivateTenant(const string &tenant_id)
{
    active_tenants.deleteEntry(tenant_id);
}

void
TenantManager::Impl::deactivateTenants(const vector<string> &tenants_id)
{
    for (const auto &tenant_id: tenants_id) deactivateTenant(tenant_id);
}

vector<string>
TenantManager::Impl::fetchActiveTenants() const
{
    vector<string> tenants;
    tenants.reserve(active_tenants.size());
    for (auto iter = begin(active_tenants); iter != end(active_tenants); iter++) {
        tenants.push_back(iter->first);
    }
    return tenants;
}

vector<string>
TenantManager::Impl::getInstances(const string &tenant_id) const
{
    vector<string> tenants;

    auto tenant_instance_cache = mapper.find(tenant_id);
    if (tenant_instance_cache == mapper.end()) return tenants;

    tenants.reserve(tenant_instance_cache->second.size());
    for (auto iter = begin(tenant_instance_cache->second); iter != end(tenant_instance_cache->second); iter++) {
        tenants.push_back(iter->first);
    }
    return tenants;
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
