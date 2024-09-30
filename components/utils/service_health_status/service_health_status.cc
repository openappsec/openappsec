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

#include "service_health_status.h"

#include <fstream>
#include <string>

#include "debug.h"
#include "rest.h"
#include "customized_cereal_map.h"
#include "service_health_update_event.h"

using namespace std;

USE_DEBUG_FLAG(D_SERVICE_HEALTH_STATUS);

class I_ServiceHealthStatusImpl
{
public:
    virtual const map<string, string> & getErrors() const = 0;

protected:
    virtual ~I_ServiceHealthStatusImpl() {}
};

class ServiceHealthStatus::Impl
        :
    public Singleton::Provide<I_ServiceHealthStatusImpl>::SelfInterface,
    public Listener<ServiceHealthUpdateEvent>
{
public:
    void init();
    const map<string, string> & getErrors() const override { return errors_map; }
    void upon(const ServiceHealthUpdateEvent &event) override;

private:
    map<string, string> errors_map;
};

class ServiceHealthStatusRest
        :
    public ServerRest,
    Singleton::Consume<I_ServiceHealthStatusImpl>
{
    using ErrorsMap = map<string, string>;

public:
    void
    doCall()
    {
        errors = Singleton::Consume<I_ServiceHealthStatusImpl>::by<ServiceHealthStatusRest>()->getErrors();
        healthy = errors.get().empty();
        dbgTrace(D_SERVICE_HEALTH_STATUS)
            << "Heath status requested. "
            << (healthy ? "Service is healthy." : "Service is not healthy.");
    }

private:
    S2C_PARAM(bool, healthy);
    S2C_PARAM(ErrorsMap, errors);
};

void
ServiceHealthStatus::Impl::init()
{
    if (!Singleton::exists<I_RestApi>()) return;
    Singleton::Consume<I_RestApi>::by<ServiceHealthStatus>()->addRestCall<ServiceHealthStatusRest>(
        RestAction::SHOW,
        "health"
    );
    registerListener();
}

void
ServiceHealthStatus::Impl::upon(const ServiceHealthUpdateEvent &event)
{
    dbgTrace(D_SERVICE_HEALTH_STATUS)
        << "Service health update event. Error: "
        << event.getComponent()
        << " - "
        << event.getError();

    if (event.isHealthyUpdate()) {
        errors_map.clear();
    } else {
        errors_map[event.getComponent()] = event.getError();
    }
}

ServiceHealthStatus::ServiceHealthStatus() : Component("ServiceHealthStatus"), pimpl(make_unique<Impl>()) {}
ServiceHealthStatus::~ServiceHealthStatus() {}

void ServiceHealthStatus::init() { pimpl->init(); }
