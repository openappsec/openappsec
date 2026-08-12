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

#include "WaapAssetStatesManager.h"
#include "WaapDataVersion.h"
#include "WaapDefines.h"
#include "WaapAssetState.h"
#include "i_waapConfig.h"
#include "config.h"
#include "agent_core_utilities.h"

USE_DEBUG_FLAG(D_WAAP);
USE_DEBUG_FLAG(D_WAAP_DATA_LOAD);

WaapAssetStatesManager::WaapAssetStatesManager() : pimpl(std::make_unique<WaapAssetStatesManager::Impl>())
{
}

WaapAssetStatesManager::~WaapAssetStatesManager()
{
}

void WaapAssetStatesManager::preload()
{
    registerExpectedConfiguration<std::string>("waap data", "base folder");
    registerExpectedConfiguration<std::string>("waap data", "cloud folder");
}

bool WaapAssetStatesManager::initBasicWaapSigs(const std::string& waapDataFileName)
{
    return pimpl->initBasicWaapSigs(waapDataFileName);
}

bool WaapAssetStatesManager::reloadBasicWaapSigs(const std::string& waapDataFileName)
{
    return pimpl->reloadBasicWaapSigs(waapDataFileName);
}

int WaapAssetStatesManager::getLastBuildNumber() const
{
    return pimpl->getLastBuildNumber();
}

std::shared_ptr<WaapAssetState> WaapAssetStatesManager::getWaapAssetStateGlobal()
{
    return pimpl->getWaapAssetStateGlobal();
}

std::shared_ptr<WaapAssetState> WaapAssetStatesManager::getWaapAssetStateById(const std::string& assetId)
{
    return pimpl->getWaapAssetStateById(assetId);
}

void WaapAssetStatesManager::setAssetDirectoryPath(const std::string &assetDirectoryPath)
{
    return pimpl->setAssetDirectoryPath(assetDirectoryPath);
}

WaapAssetStatesManager::Impl::Impl() :
    m_signatures(nullptr),
    m_hyperscanEngine(nullptr),
    m_basicWaapSigs(nullptr),
    m_AssetBasedWaapSigs(),
    m_assetDirectoryPath(BACKUP_DIRECTORY_PATH)
{
}

WaapAssetStatesManager::Impl::~Impl()
{
}

bool WaapAssetStatesManager::Impl::loadSignaturesFromFile(const std::string& waapDataFileName){
    if (m_signatures && !m_signatures->fail() && m_hyperscanEngine && m_basicWaapSigs)
    {
        // already initialized successfully.
        return true;
    }
    try {
        m_signatures = std::make_shared<Signatures>(waapDataFileName);
        
        // Initialize Hyperscan engine
        m_hyperscanEngine = std::make_shared<WaapHyperscanEngine>();
        if (!Signatures::shouldUseHyperscan()) {
            dbgTrace(D_WAAP_DATA_LOAD) << "Hyperscan disabled by configuration, will use PCRE2";
        } else if (!m_hyperscanEngine->initialize(m_signatures)) {
            dbgTrace(D_WAAP_DATA_LOAD) << "Hyperscan initialization failed, will use PCRE2";
        } else {
            m_signatures->setHyperscanInitialized(true);
            dbgTrace(D_WAAP_DATA_LOAD) << "Hyperscan initialized successfully";
        }

        m_basicWaapSigs = std::make_shared<WaapAssetState>(
            m_signatures,
            waapDataFileName,
            m_hyperscanEngine,
            SIGS_APPLY_CLEAN_CACHE_CAPACITY,
            SIGS_APPLY_SUSPICIOUS_CACHE_CAPACITY,
            SIGS_SAMPLE_TYPE_CACHE_CAPACITY,
            "");
    }
    catch (std::runtime_error & e) {
        // TODO:: properly handle component initialization failure
        dbgTrace(D_WAAP_DATA_LOAD) <<
            "WaapAssetStatesManager::initBasicWaapSigs(): " << e.what() << ". Failed to read data file '" <<
            waapDataFileName << "'";
        m_basicWaapSigs.reset();
        return false;
    }

    return m_signatures && !m_signatures->fail() && m_hyperscanEngine && m_basicWaapSigs;
}

bool WaapAssetStatesManager::Impl::initBasicWaapSigs(const std::string& waapDataFileName)
{
    std::string cloudWaapDataFileName = getConfigurationWithDefault<std::string>(
        WAAP_DATA_CLOUD_PATH, "waap data", "cloud folder"
    );

    dbgInfo(D_WAAP_DATA_LOAD)
        << "cloud waap.data path resolved to '"
        << cloudWaapDataFileName
        << "', local fallback path: '"
        << waapDataFileName
        << "'";

    if (!NGEN::Filesystem::exists(cloudWaapDataFileName)) {
        dbgWarning(D_WAAP_DATA_LOAD)
            << "cloud waap.data file does not exist at '"
            << cloudWaapDataFileName
            << "', falling back to local path '"
            << waapDataFileName
            << "'";
        return loadSignaturesFromFile(waapDataFileName);
    }

    this->m_lastBuildNumber = WaapDataVersion(cloudWaapDataFileName).getBuildNumber();
    if (this->m_lastBuildNumber == -1) {
        dbgWarning(D_WAAP_DATA_LOAD)
            << "cloud waap.data exists at '"
            << cloudWaapDataFileName
            << "' but failed to read build number (file may be corrupted or has invalid format)"
            << ", falling back to local path '"
            << waapDataFileName
            << "'";
        return loadSignaturesFromFile(waapDataFileName);
    }

    dbgInfo(D_WAAP_DATA_LOAD)
        << "cloud waap.data found at '"
        << cloudWaapDataFileName
        << "', build_number="
        << this->m_lastBuildNumber
        << ", attempting to load signatures";

    if (loadSignaturesFromFile(cloudWaapDataFileName)) {
        dbgInfo(D_WAAP_DATA_LOAD)
            << "successfully loaded cloud waap.data, build_number="
            << this->m_lastBuildNumber;
        return true;
    }

    dbgWarning(D_WAAP_DATA_LOAD)
        << "cloud waap.data at '"
        << cloudWaapDataFileName
        << "' (build_number="
        << this->m_lastBuildNumber
        << ") existed and had valid build number but loadSignaturesFromFile failed"
        << ", falling back to local path '"
        << waapDataFileName
        << "'";
    return loadSignaturesFromFile(waapDataFileName);
}

bool WaapAssetStatesManager::Impl::reloadBasicWaapSigs(const std::string& waapDataFileName)
{
    try {
        auto temp_signatures = std::make_shared<Signatures>(waapDataFileName);
        if (!temp_signatures || temp_signatures->fail()) {
            dbgWarning(D_WAAP_DATA_LOAD) << "failed to load signatures from '" << waapDataFileName << "'";
            return false;
        }

        auto temp_hyperscanEngine = std::make_shared<WaapHyperscanEngine>();
        if (!Signatures::shouldUseHyperscan()) {
            dbgTrace(D_WAAP_DATA_LOAD) << "Hyperscan disabled, will use PCRE2";
        } else if (!temp_hyperscanEngine->initialize(temp_signatures)) {
            dbgTrace(D_WAAP_DATA_LOAD) << "Hyperscan initialization failed, will use PCRE2";
        } else {
            temp_signatures->setHyperscanInitialized(true);
        }

        auto temp_basicWaapSigs = std::make_shared<WaapAssetState>(
            temp_signatures,
            waapDataFileName,
            temp_hyperscanEngine,
            SIGS_APPLY_CLEAN_CACHE_CAPACITY,
            SIGS_APPLY_SUSPICIOUS_CACHE_CAPACITY,
            SIGS_SAMPLE_TYPE_CACHE_CAPACITY,
            "");

        m_signatures      = temp_signatures;
        m_hyperscanEngine = temp_hyperscanEngine;
        m_basicWaapSigs   = temp_basicWaapSigs;
        m_AssetBasedWaapSigs.clear();
        m_lastBuildNumber = WaapDataVersion(waapDataFileName).getBuildNumber();

        dbgInfo(D_WAAP_DATA_LOAD) << "reload succeeded for '" << waapDataFileName << "'";
        return true;
    } catch (const std::exception& e) {
        dbgWarning(D_WAAP_DATA_LOAD) <<
            "exception: " << e.what() << ". Old signatures preserved.";
        return false;
    }
}

std::shared_ptr<WaapAssetState> WaapAssetStatesManager::Impl::getWaapAssetStateGlobal()
{
    return m_basicWaapSigs;
}

std::shared_ptr<WaapAssetState> WaapAssetStatesManager::Impl::getWaapAssetStateById(const std::string& assetId)
{
    if (assetId.size() > 0)
    {
        std::string sigsKey = assetId;
        std::string instanceId = "";
        if (Singleton::exists<I_InstanceAwareness>())
        {
            I_InstanceAwareness* instance = Singleton::Consume<I_InstanceAwareness>::by<WaapComponent>();
            Maybe<std::string> uniqueId = instance->getUniqueID();
            if (uniqueId.ok())
            {
                instanceId = uniqueId.unpack();
                sigsKey += "/" + instanceId;
            }
        }
        std::unordered_map<std::string, std::shared_ptr<WaapAssetState>>::iterator it;
        it = m_AssetBasedWaapSigs.find(sigsKey);

        if (it != m_AssetBasedWaapSigs.end())
        {
            return it->second;
        }

        if (m_basicWaapSigs == NULL) {
            dbgWarning(D_WAAP) <<
                "WaapAssetStatesManager::Impl::getWaapAssetStateById(): ERROR: m_basicWaapSigs == NULL!";
            return std::shared_ptr<WaapAssetState>(nullptr);
        }

        std::shared_ptr<WaapAssetState> newWaapSigs = CreateWaapSigsForAsset(m_basicWaapSigs, assetId, instanceId);

        if (newWaapSigs)
        {
            m_AssetBasedWaapSigs[sigsKey] = newWaapSigs;
        }

        return newWaapSigs;
    }

    return std::shared_ptr<WaapAssetState>(nullptr);
}

void WaapAssetStatesManager::Impl::setAssetDirectoryPath(const std::string &assetDirectoryPath)
{
    m_assetDirectoryPath = assetDirectoryPath;
}

int WaapAssetStatesManager::Impl::getLastBuildNumber() const
{
    return m_lastBuildNumber;
}

std::shared_ptr<WaapAssetState>
WaapAssetStatesManager::Impl::CreateWaapSigsForAsset(const std::shared_ptr<WaapAssetState>& pWaapAssetState,
    const std::string& assetId,
    const std::string& instanceId)
{
    std::string assetPath =
        getConfigurationWithDefault<std::string>(m_assetDirectoryPath, "waap data", "base folder")
        + assetId;
    if (instanceId != "")
    {
        assetPath += "/" + instanceId;
    }
    if (!NGEN::Filesystem::exists(assetPath))
    {
        if (!NGEN::Filesystem::makeDirRecursive(assetPath))
        {
            dbgWarning(D_WAAP)
                << "WaapAssetStatesManager::CreateWaapSigsForAsset() can't create asset folder. "
                << "Directory: "
                << assetPath;
            return std::shared_ptr<WaapAssetState>(nullptr);
        }
    }

    dbgTrace(D_WAAP) << "WaapAssetStatesManager::CreateWaapSigsForAsset() assetPath is: " << assetPath;

    if (pWaapAssetState == NULL) {
        dbgWarning(D_WAAP) <<
            "WaapAssetStatesManager::CreateWaapSigsForAsset(): failed to create a WaapAssetState object";
        return std::shared_ptr<WaapAssetState>(nullptr);

    }

    std::string basePath = pWaapAssetState->getWaapDataFileName();
    size_t lastSlash = basePath.find_last_of('/');
    std::string assetScoresPath = assetPath +
        ((lastSlash == std::string::npos) ? basePath : basePath.substr(lastSlash));
    dbgTrace(D_WAAP) << "WaapAssetStatesManager::CreateWaapSigsForAsset() assetScoresPath is: " << assetScoresPath;
    return std::make_shared<WaapAssetState>(pWaapAssetState, assetScoresPath, assetId);
}
