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

#include <iostream>
#include <memory>
#include "waap.h"
#include "telemetry.h"
#include "waap_clib/DeepAnalyzer.h"
#include "waap_component_impl.h"
#include "debug.h"
#include "waap_clib/WaapConfigApplication.h"
#include "waap_clib/WaapConfigApi.h"

USE_DEBUG_FLAG(D_WAAP);
USE_DEBUG_FLAG(D_WAAP_API);

WaapComponent::WaapComponent() : Component("WaapComponent"), pimpl(std::make_unique<WaapComponent::Impl>())
{
    dbgTrace(D_WAAP) << "WaapComponent::WaapComponent()";
}

WaapComponent::~WaapComponent()
{
    dbgTrace(D_WAAP) << "WaapComponent::~WaapComponent()";
}

void
WaapComponent::init()
{
    pimpl->init();
}

void
WaapComponent::fini()
{
    pimpl->fini();
}

void
WaapComponent::preload()
{
    // TODO:: call stuff like registerExpectedCofiguration here..
    registerExpectedConfiguration<WaapConfigApplication>("WAAP", "WebApplicationSecurity");
    registerExpectedConfiguration<WaapConfigAPI>("WAAP", "WebAPISecurity");
    registerExpectedConfiguration<std::string>("WAAP", "Sigs file path");
    registerExpectedConfigFile("waap", Config::ConfigFileType::Policy);
    registerConfigLoadCb(
        [this]()
        {
            WaapConfigApplication::notifyAssetsCount();
            WaapConfigAPI::notifyAssetsCount();
        }
    );
    registerConfigPrepareCb(
        [this]()
        {
            WaapConfigApplication::clearAssetsCount();
            WaapConfigAPI::clearAssetsCount();
        }
    );
    dbgTrace(D_WAAP) << "WaapComponent::preload() exit";
}
