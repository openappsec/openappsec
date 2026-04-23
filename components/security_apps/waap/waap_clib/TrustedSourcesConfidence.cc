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

#include "TrustedSourcesConfidence.h"
#include "waap.h"
#include "Waf2Util.h"

USE_DEBUG_FLAG(D_WAAP_CONFIDENCE_CALCULATOR);
#define SYNC_WAIT_TIME std::chrono::seconds(300) // 5 minutes in seconds

TrustedSourcesConfidenceCalculator::TrustedSourcesConfidenceCalculator(
    std::string path,
    const std::string &remotePath,
    const std::string &assetId)
    :
    SerializeToLocalAndRemoteSyncBase(std::chrono::minutes(120),
        SYNC_WAIT_TIME,
        path,
        (remotePath == "") ? remotePath : remotePath + "/Trust",
        assetId,
        "TrustedSourcesConfidenceCalculator"),
    m_persistent_state(),
    m_incremental_logger(std::make_shared<KeyValSourceLogger>())
{
    restore();
}

bool TrustedSourcesConfidenceCalculator::is_confident(Key key, Val value, size_t minSources) const
{
    // Check persistent state first (accumulated data from previous syncs)
    auto sourceCtrItr = m_persistent_state.find(key);
    if (sourceCtrItr != m_persistent_state.end())
    {
        auto sourceSetItr = sourceCtrItr->second.find(value);
        if (sourceSetItr != sourceCtrItr->second.end())
        {
            size_t persistent_sources = sourceSetItr->second.size();

            if (persistent_sources >= minSources) {
                dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "The number of trusted sources for " << key
                    << " : " << value << " is " << persistent_sources << " (persistent only)";
                return true;
            }

            // Also check incremental logger for recent data
            size_t incremental_sources = 0;
            if (m_incremental_logger) {
                auto incr_ctr_itr = m_incremental_logger->find(key);
                if (incr_ctr_itr != m_incremental_logger->end()) {
                    auto incr_set_itr = incr_ctr_itr->second.find(value);
                    if (incr_set_itr != incr_ctr_itr->second.end()) {
                        // Count unique sources (avoid double counting)
                        for (const auto &src : incr_set_itr->second) {
                            if (sourceSetItr->second.find(src) == sourceSetItr->second.end()) {
                                incremental_sources++;
                            }
                        }
                    }
                }
            }

            size_t total_sources = persistent_sources + incremental_sources;
            dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "The number of trusted sources for " << key
                << " : " << value << " is " << total_sources << " (persistent: " << persistent_sources
                << ", incremental: " << incremental_sources << ")";
            return total_sources >= minSources;
        }
        else
        {
            dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to find the value(" << value << ")";
        }
    }
    else
    {
        // Check if data exists only in incremental logger
        if (m_incremental_logger) {
            auto incr_ctr_itr = m_incremental_logger->find(key);
            if (incr_ctr_itr != m_incremental_logger->end()) {
                auto incr_set_itr = incr_ctr_itr->second.find(value);
                if (incr_set_itr != incr_ctr_itr->second.end()) {
                    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "The number of trusted sources for " << key
                        << " : " << value << " is " << incr_set_itr->second.size() << " (incremental only)";
                    return incr_set_itr->second.size() >= minSources;
                }
            }
        }
        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to find the key(" << key << ")";
    }
    return false;
}


class GetTrustedFile : public RestGetFile
{
public:
    GetTrustedFile()
    {
    }

    Maybe<TrustedSourcesConfidenceCalculator::KeyValSourceLogger>
        getTrustedLogs() const
    {
        if (!logger.get().empty()) return logger.get();
        return genError("failed to get file");
    }

private:
    S2C_PARAM(TrustedSourcesConfidenceCalculator::KeyValSourceLogger, logger)
};

class TrustedSourcesLogger : public RestGetFile
{
public:
    TrustedSourcesLogger(std::shared_ptr<TrustedSourcesConfidenceCalculator::KeyValSourceLogger> _logger_ptr)
        : logger_ptr(_logger_ptr)
    {
        logger = move(*logger_ptr);
    }
private:
    std::shared_ptr<TrustedSourcesConfidenceCalculator::KeyValSourceLogger> logger_ptr;
    C2S_PARAM(TrustedSourcesConfidenceCalculator::KeyValSourceLogger, logger);
};

bool TrustedSourcesConfidenceCalculator::postData()
{
    if (m_incremental_logger->empty())
    {
        dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "No data to post, skipping";
        return true; // Nothing to post
    }
    std::string url = getPostDataUrl();

    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Sending the data to: " << url;
    mergeIncrementalToPersistent();

    TrustedSourcesLogger logger(m_incremental_logger);

    // Clear and reset incremental logger for next cycle
    m_incremental_logger = std::make_shared<KeyValSourceLogger>();

    bool ok = sendNoReplyObjectWithRetry(logger,
        HTTPMethod::PUT,
        url);
    if (!ok) {
        dbgError(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to post collected data to: " << url;
    }
    return ok;
}

void TrustedSourcesConfidenceCalculator::pullData(const std::vector<std::string> &files)
{
    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Fetching the window data for trusted sources";
    std::string url = getPostDataUrl();
    std::string sentFile = url.erase(0, url.find_first_of('/') + 1);
    for (const auto &file : files) // Use const reference to avoid copying
    {
        if (file == sentFile)
        {
            continue;
        }
        GetTrustedFile getTrustFile;
        bool res = sendObjectWithRetry(getTrustFile,
            HTTPMethod::GET,
            getUri() + "/" + file);
        if (!res)
        {
            dbgError(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to get file: " << file;
            continue;
        }
        if (getTrustFile.getTrustedLogs().ok())
        {
            mergeFromRemote(getTrustFile.getTrustedLogs().unpack());
        }
    }
}

void TrustedSourcesConfidenceCalculator::processData()
{

}
void TrustedSourcesConfidenceCalculator::updateState(const std::vector<std::string> &files)
{
    pullProcessedData(files);
}

Maybe<std::string> TrustedSourcesConfidenceCalculator::getRemoteStateFilePath() const
{
    return m_remotePath + "/remote/data.data";
}

void TrustedSourcesConfidenceCalculator::pullProcessedData(const std::vector<std::string> &files) {
    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Fetching the logger object for trusted sources";
    bool pull_ok = false;
    for (const auto &file : files) { // Use const reference
        GetTrustedFile getTrustFile;
        bool res = sendObject(getTrustFile,
            HTTPMethod::GET,
            getUri() + "/" + file);
        pull_ok |= res;
        if (res && getTrustFile.getTrustedLogs().ok()) {
            mergeFromRemote(getTrustFile.getTrustedLogs().unpack());
        }
    }
    if (!pull_ok && !files.empty()) {
        dbgError(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to pull state data";
    }
}

void TrustedSourcesConfidenceCalculator::postProcessedData()
{
    std::string url = getUri() + "/" + m_remotePath + "/processed/data.data";
    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Sending the processed data to: " << url;

    // Send persistent state as processed data
    auto logger_ptr = std::make_shared<TrustedSourcesConfidenceCalculator::KeyValSourceLogger>(m_persistent_state);
    TrustedSourcesLogger logger(logger_ptr);
    sendNoReplyObjectWithRetry(logger,
        HTTPMethod::PUT,
        url);
}

TrustedSourcesConfidenceCalculator::ValuesSet TrustedSourcesConfidenceCalculator::getConfidenceValues(
    const Key &key,
    size_t minSources) const
{
    ValuesSet values;

    // Check persistent state
    auto sourceCtrItr = m_persistent_state.find(key);
    if (sourceCtrItr != m_persistent_state.end())
    {
        for (auto sourceSetItr : sourceCtrItr->second)
        {
            size_t persistent_sources = sourceSetItr.second.size();
            if (persistent_sources >= minSources)
            {
                values.insert(sourceSetItr.first);
                continue; // No need to check incremental logger if we already have enough sources
            }

            // Also check incremental logger for recent data
            size_t incremental_sources = 0;
            if (m_incremental_logger) {
                auto incr_ctr_itr = m_incremental_logger->find(key);
                if (incr_ctr_itr != m_incremental_logger->end()) {
                    auto incr_set_itr = incr_ctr_itr->second.find(sourceSetItr.first);
                    if (incr_set_itr != incr_ctr_itr->second.end()) {
                        // Count unique sources (avoid double counting)
                        for (const auto &src : incr_set_itr->second) {
                            if (sourceSetItr.second.find(src) == sourceSetItr.second.end()) {
                                incremental_sources++;
                            }
                        }
                    }
                }
            }

            if (persistent_sources + incremental_sources >= minSources)
            {
                values.insert(sourceSetItr.first);
            }
        }
    }

    // Also check values that exist only in incremental logger
    if (m_incremental_logger) {
        auto incr_ctr_itr = m_incremental_logger->find(key);
        if (incr_ctr_itr != m_incremental_logger->end()) {
            for (auto incr_set_itr : incr_ctr_itr->second) {
                // Skip if already processed in persistent state
                if (sourceCtrItr != m_persistent_state.end() &&
                    sourceCtrItr->second.find(incr_set_itr.first) != sourceCtrItr->second.end()) {
                    continue;
                }

                if (incr_set_itr.second.size() >= minSources) {
                    values.insert(incr_set_itr.first);
                }
            }
        }
    }

    if (values.empty()) {
        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to find the key(" << key << ")";
    }
    return values;
}

void TrustedSourcesConfidenceCalculator::serialize(std::ostream &stream)
{
    cereal::JSONOutputArchive archive(stream);

    archive(cereal::make_nvp("version", 3), cereal::make_nvp("persistent_state", m_persistent_state));
}

void TrustedSourcesConfidenceCalculator::deserialize(std::istream &stream)
{
    cereal::JSONInputArchive archive(stream);
    size_t version = 0;

    try
    {
        archive(cereal::make_nvp("version", version));
    }
    catch (std::runtime_error & e) {
        archive.setNextName(nullptr);
        version = 0;
        dbgDebug(D_WAAP) << "Can't load file version: " << e.what();
    }

    switch (version)
    {
    case 3:
    {
        archive(cereal::make_nvp("persistent_state", m_persistent_state));
        break;
    }
    case 2:
    {
        // Legacy: load into persistent state
        archive(cereal::make_nvp("logger", m_persistent_state));
        break;
    }
    case 1:
    {
        KeyValSourceLogger logger;
        archive(cereal::make_nvp("logger", logger));
        for (auto &log : logger)
        {
            m_persistent_state[normalize_param(log.first)] = log.second;
        }
        break;
    }
    case 0:
    {
        // Legacy: load into persistent state
        archive(cereal::make_nvp("m_logger", m_persistent_state));
        break;
    }
    default:
        dbgError(D_WAAP) << "unknown file format version: " << version;
        break;
    }
}

void TrustedSourcesConfidenceCalculator::mergeFromRemote(const KeyValSourceLogger &logs)
{
    for (auto &srcCounterItr : logs)
    {
        for (auto &sourcesItr : srcCounterItr.second)
        {
            for (auto &src : sourcesItr.second)
            {
                dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Registering the source: " << src
                    << " for the value: " << sourcesItr.first << " and the key: " << srcCounterItr.first;
                m_persistent_state[normalize_param(srcCounterItr.first)][sourcesItr.first].insert(src);
            }
        }
    }
}

void TrustedSourcesConfidenceCalculator::log(Key key, Val value, Source source)
{
    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR)
        << "Logging the value: "
        << value
        << " for the key: "
        << key
        << " from the source: "
        << source;
    (*m_incremental_logger)[key][value].insert(source);
}

void TrustedSourcesConfidenceCalculator::reset()
{
    m_persistent_state.clear();
    m_incremental_logger->clear();
}

void TrustedSourcesConfidenceCalculator::mergeIncrementalToPersistent()
{
    // Merge incremental data into persistent state (same logic as in postData but without network operations)
    for (const auto &keyEntry : *m_incremental_logger) {
        const std::string &key = keyEntry.first;
        for (const auto &valueEntry : keyEntry.second) {
            const std::string &value = valueEntry.first;
            for (const std::string &source : valueEntry.second) {
                m_persistent_state[key][value].insert(source);
            }
        }
    }

    // Clear incremental logger after merging
    m_incremental_logger->clear();
}
