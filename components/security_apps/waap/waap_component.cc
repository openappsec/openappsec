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
#include "WaapDataVersion.h"
#include "waap_clib/DeepAnalyzer.h"
#include "waap_component_impl.h"
#include "debug.h"
#include "waap_clib/WaapConfigApplication.h"
#include "waap_clib/WaapConfigApi.h"
#include "log_generator.h"

USE_DEBUG_FLAG(D_WAAP);
USE_DEBUG_FLAG(D_WAAP_API);
USE_DEBUG_FLAG(D_WAAP_DATA_LOAD);

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
    // registerExpectedConfiguration<WaapConfigApplication>("WAAP", "WebApplicationSecurity");
    // registerExpectedConfiguration<WaapConfigAPI>("WAAP", "WebAPISecurity");

    registerExpectedConfigurationWithCache<WaapConfigApplication>(
        "assetId", "WAAP", "WebApplicationSecurity");
    registerExpectedConfigurationWithCache<WaapConfigAPI>("assetId", "WAAP", "WebAPISecurity");
    registerExpectedConfiguration<std::string>("waap data", "cloud folder");
    registerExpectedConfiguration<std::string>("WAAP", "Sigs file path");
    registerExpectedConfigFile("waap", Config::ConfigFileType::Policy);
    registerExpectedConfigFile("waap", Config::ConfigFileType::RawData);
    registerExpectedSetting<bool>("features", "learningLeader");
    registerConfigLoadCb(
        [this]()
        {
            WaapConfigApplication::notifyAssetsCount();
            WaapConfigAPI::notifyAssetsCount();
            reloadWaapDataOnConfigChange();
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

void
WaapComponent::reloadWaapDataOnConfigChange()
{
    std::string cloudWaapDataFileName = getConfigurationWithDefault<std::string>(
        WAAP_DATA_CLOUD_PATH, "waap data", "cloud folder"
    );
    if (!NGEN::Filesystem::exists(cloudWaapDataFileName)) {
        dbgWarning(D_WAAP_DATA_LOAD)
            << "cloud waap.data file does not exist at '"
            << cloudWaapDataFileName
            << "'";
        return;
    }
    auto* mgr = Singleton::Consume<I_WaapAssetStatesManager>::by<WaapComponent>();
    if (!mgr) {
        dbgWarning(D_WAAP_DATA_LOAD) << "WaapAssetStatesManager is unavailable, skipping reload";
        return;
    }
    if (!mgr->getWaapAssetStateGlobal()) {
        dbgDebug(D_WAAP_DATA_LOAD) << "global WAAP asset state not initialized, skipping reload";
        return;
    }

    int newBuild = WaapDataVersion(cloudWaapDataFileName).getBuildNumber();
    dbgTrace(D_WAAP_DATA_LOAD) << "newBuild=" << newBuild
        << ", lastBuild=" << mgr->getLastBuildNumber();

    // build_number == 0 means the field is absent in the data file
    // (WaapDataVersion defaults to 0 when the field is missing).
    // Skip reload no meaningful version information available.
    if (newBuild <= 0) {
        dbgWarning(D_WAAP_DATA_LOAD)
            << "build_number is: "
            << newBuild
            << "(absent from data file), skipping reload";

        LogGen buildInvalidLog(
            "WAAP cloud engine reload skipped - invalid build number in data file",
            ReportIS::Audience::SECURITY,
            ReportIS::Severity::HIGH,
            ReportIS::Priority::HIGH,
            ReportIS::Tags::WAF
        );
        buildInvalidLog << LogField("waapEngineVersion", newBuild);
        buildInvalidLog << LogField("waapDataFilePath", cloudWaapDataFileName);
        buildInvalidLog << LogField("failureReason", std::string("build_number is absent or invalid in data file"));
        buildInvalidLog << LogField("reloadStatus", std::string("failure"));
        buildInvalidLog.addToOrigin(LogField("eventTopic", std::string("WAAP Engine Reload")));
        return;
    }
    if (newBuild == mgr->getLastBuildNumber()) {
        dbgDebug(D_WAAP_DATA_LOAD) << "build_number=" << newBuild
            << " unchanged, skipping reload";
        return;
    }

    int oldBuild = mgr->getLastBuildNumber();
    dbgTrace(D_WAAP_DATA_LOAD) << "reloading from path='" << cloudWaapDataFileName << "'";

    if (!mgr->reloadBasicWaapSigs(cloudWaapDataFileName)) {
        dbgWarning(D_WAAP_DATA_LOAD) << "reload failed for build_number=" << newBuild
            << ", path='" << cloudWaapDataFileName << "', keeping old signatures";

        LogGen reloadFailLog(
            "WAAP cloud engine reload failed - keeping old signatures",
            ReportIS::Audience::SECURITY,
            ReportIS::Severity::CRITICAL,
            ReportIS::Priority::URGENT,
            ReportIS::Tags::WAF
        );
        reloadFailLog << LogField("waapEngineVersion", newBuild);
        reloadFailLog << LogField("previousWaapEngineVersion", oldBuild);
        reloadFailLog << LogField("waapDataFilePath", cloudWaapDataFileName);
        reloadFailLog << LogField("failureReason", std::string("Signature reload returned failure"));
        reloadFailLog << LogField("reloadStatus", std::string("failure"));
        reloadFailLog.addToOrigin(LogField("eventTopic", std::string("WAAP Engine Reload")));
        return;
    }

    dbgInfo(D_WAAP_DATA_LOAD) << "WAAP data reloaded successfully, build_number=" << newBuild;

    LogGen reloadSuccessLog(
        "WAAP cloud engine reloaded successfully",
        ReportIS::Audience::SECURITY,
        ReportIS::Severity::INFO,
        ReportIS::Priority::LOW,
        ReportIS::Tags::WAF
    );
    reloadSuccessLog << LogField("waapEngineVersion", newBuild);
    reloadSuccessLog << LogField("previousWaapEngineVersion", oldBuild);
    reloadSuccessLog << LogField("waapDataFilePath", cloudWaapDataFileName);
    reloadSuccessLog << LogField("reloadStatus", std::string("success"));
    reloadSuccessLog.addToOrigin(LogField("eventTopic", std::string("WAAP Engine Reload")));
}
