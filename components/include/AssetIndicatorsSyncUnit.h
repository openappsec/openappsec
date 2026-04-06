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

#include <chrono>
#include <memory>
#include <string>
#include "UnifiedIndicatorsContainer.h"
#include "i_serialize.h"
#include "unified_learning_comp.h"

// Per-asset sync unit that manages indicators for a single asset
// Each instance:
// - Maintains its own UnifiedIndicatorsContainer
// - Handles serialization/deserialization to asset-specific backup file
// - Posts data independently to remote service
// - Inherits sync lifecycle management from SerializeToLocalAndRemoteSyncBaseT
class AssetIndicatorsSyncUnit : public SerializeToLocalAndRemoteSyncBaseT<UnifiedLearningComponent>
{
public:
    AssetIndicatorsSyncUnit(
        const std::string &asset_id,
        std::chrono::minutes sync_interval,
        std::chrono::seconds wait_for_sync,
        const std::string &remotePath = ""
    );

    ~AssetIndicatorsSyncUnit() = default;

    // Add an entry to this asset's indicators container
    void addEntry(const UnifiedIndicatorsContainer::Entry &entry);

    // Handle policy changes notification
    void handleNewPolicy();

    // Get statistics for monitoring
    size_t getIndicatorCount() const;
    size_t getKeyCount() const;

private:
    // Friend class for unit testing
    friend class AssetIndicatorsSyncUnitTest;

    // I_Serializable interface implementation
    void serialize(std::ostream &stream) override;
    void deserialize(std::istream &stream) override;

    // I_RemoteSyncSerialize interface implementation
    bool postData() override;
    void pullData(const std::vector<std::string> &files) override;
    void processData() override;
    void postProcessedData() override;
    void pullProcessedData(const std::vector<std::string> &files) override;
    void updateState(const std::vector<std::string> &files) override;

private:
    std::string m_asset_id;
    std::shared_ptr<UnifiedIndicatorsContainer> indicators_container;
};
