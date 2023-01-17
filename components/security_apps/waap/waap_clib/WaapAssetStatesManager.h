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

#pragma once

#include "singleton.h"
#include "Signatures.h"
#include <string>
#include <memory>
#include <unordered_map>

//forward decleration.
class WaapAssetState;

class I_WaapAssetStatesManager {
public:
    virtual bool initBasicWaapSigs(const std::string& waapDataFileName) = 0;
    virtual std::shared_ptr<WaapAssetState> getWaapAssetStateGlobal() = 0;
    virtual std::shared_ptr<WaapAssetState> getWaapAssetStateById(const std::string& assetId) = 0;
    virtual void setAssetDirectoryPath(const std::string &assetDirectoryPath) = 0;
};

class WaapAssetStatesManager : Singleton::Provide<I_WaapAssetStatesManager> {
public:
    WaapAssetStatesManager();
    virtual ~WaapAssetStatesManager();

    void preload();
    virtual bool initBasicWaapSigs(const std::string& waapDataFileName);
    virtual std::shared_ptr<WaapAssetState> getWaapAssetStateGlobal();
    virtual std::shared_ptr<WaapAssetState> getWaapAssetStateById(const std::string& assetId);

    virtual void setAssetDirectoryPath(const std::string &assetDirectoryPath);

    class Impl;
protected:
    std::unique_ptr<Impl> pimpl;
};

class WaapAssetStatesManager::Impl : Singleton::Provide<I_WaapAssetStatesManager>::From<WaapAssetStatesManager>
{
public:
    Impl();
    virtual ~Impl();

    virtual bool initBasicWaapSigs(const std::string& waapDataFileName);
    virtual std::shared_ptr<WaapAssetState> getWaapAssetStateGlobal();
    virtual std::shared_ptr<WaapAssetState> getWaapAssetStateById(const std::string& assetId);
    virtual void setAssetDirectoryPath(const std::string &assetDirectoryPath);

private:
    std::shared_ptr<WaapAssetState>
        CreateWaapSigsForAsset(const std::shared_ptr<WaapAssetState>& pWaapAssetState,
            const std::string& assetId,
            const std::string& instanceId);

    std::shared_ptr<Signatures> m_signatures;
    std::shared_ptr<WaapAssetState> m_basicWaapSigs;
    std::unordered_map<std::string, std::shared_ptr<WaapAssetState>> m_AssetBasedWaapSigs;
    std::string m_assetDirectoryPath;
};
