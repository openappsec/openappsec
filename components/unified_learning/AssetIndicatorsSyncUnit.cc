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

#include "AssetIndicatorsSyncUnit.h"
#include <cereal/archives/json.hpp>
#include <chrono>
#include "buffered_compressed_stream.h"
#include "debug.h"

USE_DEBUG_FLAG(D_UNIFIED_LEARNING);

AssetIndicatorsSyncUnit::AssetIndicatorsSyncUnit(
    const std::string &asset_id,
    std::chrono::minutes sync_interval,
    std::chrono::seconds wait_for_sync,
    const std::string &remotePath
) :
    SerializeToLocalAndRemoteSyncBaseT<UnifiedLearningComponent>(
        sync_interval,
        wait_for_sync,
        "/tmp/unified_learning_backup_" + asset_id + ".data",
        remotePath,
        asset_id,
        "AssetIndicatorsSyncUnit"
    ),
    m_asset_id(asset_id),
    indicators_container(std::make_shared<UnifiedIndicatorsContainer>())
{
    dbgTrace(D_UNIFIED_LEARNING)
        << "Created AssetIndicatorsSyncUnit for asset: "
        << asset_id;
}

void
AssetIndicatorsSyncUnit::addEntry(const UnifiedIndicatorsContainer::Entry &entry)
{
    indicators_container->addEntry(entry);

    dbgTrace(D_UNIFIED_LEARNING)
        << "Added entry to asset "
        << m_asset_id
        << ", Key: "
        << entry.key
        << ", Source: "
        << entry.sourceId
        << ", indicators: "
        << entry.indicators.size()
        << ", types: "
        << entry.types.size();
}

void
AssetIndicatorsSyncUnit::handleNewPolicy()
{
    dbgTrace(D_UNIFIED_LEARNING)
        << "Asset sync unit received policy change notification: "
        << m_asset_id;

    int interval_minutes = getProfileAgentSettingWithDefault<int>(
        120,
        "agent.learning.learningSyncInterval"
    );

    std::chrono::minutes new_interval(interval_minutes);
    if (getIntervalDuration() != new_interval) {
        dbgTrace(D_UNIFIED_LEARNING)
        << "Learning sync interval changed for asset "
        << m_asset_id
        << " from "
        << std::chrono::duration_cast<std::chrono::minutes>(getIntervalDuration())
        << " to "
        << new_interval.count()
        << " minutes";

        setInterval(new_interval);
    }
}

size_t
AssetIndicatorsSyncUnit::getIndicatorCount() const
{
    return indicators_container->getIndicatorCount();
}

size_t
AssetIndicatorsSyncUnit::getKeyCount() const
{
    return indicators_container->getKeyCount();
}

// I_Serializable implementation
void
AssetIndicatorsSyncUnit::serialize(std::ostream &stream)
{
    BufferedCompressedOutputStream compressed_out(stream);
    {
        cereal::JSONOutputArchive archive(compressed_out);
        indicators_container->serialize(archive);
    }
    compressed_out.close();
    
    dbgTrace(D_UNIFIED_LEARNING)
        << "Serialized indicators for asset: "
        << m_asset_id;
}

void
AssetIndicatorsSyncUnit::deserialize(std::istream &stream)
{
    try {
        BufferedCompressedInputStream decompressed_stream(stream);
        indicators_container->deserialize(decompressed_stream);
        dbgTrace(D_UNIFIED_LEARNING)
            << "Deserialized indicators for asset: "
            << m_asset_id;
    } catch (const std::exception &e) {
        dbgWarning(D_UNIFIED_LEARNING)
            << "Failed to deserialize asset "
            << m_asset_id
            << ": "
            << e.what();
    }
}

// I_RemoteSyncSerialize implementation
bool
AssetIndicatorsSyncUnit::postData()
{
    dbgTrace(D_UNIFIED_LEARNING)
        << "Posting indicators for asset: "
        << m_asset_id;

    if (indicators_container->getKeyCount() == 0) {
        dbgTrace(D_UNIFIED_LEARNING)
            << "No indicators to post for asset: "
            << m_asset_id;
        m_dataWasSent = false;
        return true;
    }

    UnifiedIndicatorsLogPost logPost(indicators_container);
    std::string postUrl = getPostDataUrl();

    dbgTrace(D_UNIFIED_LEARNING)
        << "Posting "
        << indicators_container->getIndicatorCount()
        << " indicators for asset "
        << m_asset_id
        << " to: "
        << postUrl;

    bool ok = sendNoReplyObjectWithRetry(logPost, HTTPMethod::PUT, postUrl);

    if (!ok) {
        dbgError(D_UNIFIED_LEARNING)
            << "Failed to post indicators for asset "
            << m_asset_id
            << " to: "
            << postUrl;
            m_dataWasSent = false;
    } else {
        dbgTrace(D_UNIFIED_LEARNING)
            << "Successfully posted indicators for asset: "
            << m_asset_id;
            m_dataWasSent = true;
    }

    // Clear container after successful post
    indicators_container = std::make_shared<UnifiedIndicatorsContainer>();
    return ok;
}

void
AssetIndicatorsSyncUnit::pullData(const std::vector<std::string> &files)
{
    (void)files;
    // Not implemented for POC
}

void
AssetIndicatorsSyncUnit::processData()
{
    // Processing happens in UnifiedLearningManager
}

void
AssetIndicatorsSyncUnit::postProcessedData()
{
    // Not needed for POC
}

void
AssetIndicatorsSyncUnit::pullProcessedData(const std::vector<std::string> &files)
{
    (void)files;
    // Not needed for POC
}

void
AssetIndicatorsSyncUnit::updateState(const std::vector<std::string> &files)
{
    (void)files;
    // Not needed for POC
}
