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

#include "ScannersDetector.h"
#include "waap.h"
#include <boost/algorithm/string/predicate.hpp>

USE_DEBUG_FLAG(D_WAAP);
#define SYNC_WAIT_TIME std::chrono::seconds(300) // 5 minutes in seconds
#define INTERVAL std::chrono::minutes(120)
#define EQUAL_VALUES_COUNT_THRESHOLD 2
#define MAX_RETENTION 2
#define DEFAULT_MAX_SOURCES 256

ScannerDetector::ScannerDetector(const std::string &localPath, const std::string &remotePath,
        const std::string &assetId) :
    SerializeToLocalAndRemoteSyncBase(INTERVAL, SYNC_WAIT_TIME,
    localPath + "/11.data",
    (remotePath == "") ? remotePath : remotePath + "/ScannersDetector",
    assetId,
    "ScannerDetector"),
    m_current_accumulator(std::make_shared<SourceKeyValsMap>()),
    m_maxSources(getProfileAgentSettingWithDefault<uint>(-1, "scannerDetector.maxSources"))
{
    dbgTrace(D_WAAP) << "ScannerDetector constructor: m_maxSources set to " << m_maxSources;
}

bool ScannerDetector::ready()
{
    if (m_lastSync.count() == 0)
    {
        return false;
    }
    std::chrono::microseconds currentTime = Singleton::Consume<I_TimeGet>::by<WaapComponent>()->getWalltime();
    return (currentTime - m_lastSync < m_interval / 2);
}

std::vector<std::string>* ScannerDetector::getSourcesToIgnore()
{
    return &m_sources;
}

void ScannerDetector::log(
    const std::string &source,
    const std::string &key,
    Waap::Keywords::KeywordsSet &keywords)
{
    if (m_maxSources == uint(-1)) {
        m_maxSources = getProfileAgentSettingWithDefault<uint>(DEFAULT_MAX_SOURCES, "scannerDetector.maxSources");
        dbgTrace(D_WAAP) << "log: m_maxSources set to " << m_maxSources;
    }

    // Add to accumulator for processing - same as original
    (*m_current_accumulator)[source][key].insert(keywords.begin(), keywords.end());

    // Optimized O(1) cache update - just add the key directly to the source cache
    auto currentTime = Singleton::Consume<I_TimeGet>::by<WaapComponent>()->getWalltime();

    auto cache_it = m_sourceCache.find(source);
    if (cache_it != m_sourceCache.end()) {
        // Source exists, just add the key - O(1) operation
        cache_it->second.keys.insert(key);
        cache_it->second.lastUpdate = currentTime;
        cache_it->second.accessCount++;

        // Move to front of LRU - O(1) operation
        auto lru_it = m_lruMap.find(source);
        if (lru_it != m_lruMap.end()) {
            m_lruOrder.erase(lru_it->second);
            m_lruOrder.push_front(source);
            m_lruMap[source] = m_lruOrder.begin();
        }

        dbgTrace(D_WAAP) << "log: Updated existing source " << source << " with key " << key;
        return;
    }

    // New source - check if cache is full
    if (m_sourceCache.size() >= m_maxSources) {
        evictLeastImportantSource();
    }

    // Add new source - O(1) operations
    SourceInfo newSource(source, currentTime);
    newSource.keys.insert(key);
    m_sourceCache[source] = newSource;

    // Add to front of LRU list - O(1) operation
    m_lruOrder.push_front(source);
    m_lruMap[source] = m_lruOrder.begin();

    dbgTrace(D_WAAP) << "log: Added new source " << source << " with key " << key
                    << " (cache size: " << m_sourceCache.size() << ")";
}

void ScannerDetector::loadParams(std::shared_ptr<Waap::Parameters::WaapParameters> pParams)
{
    std::string interval = pParams->getParamVal("learnIndicators.intervalDuration",
        std::to_string(INTERVAL.count()));
    setInterval(std::chrono::minutes(std::stoul(interval)));
    std::string remoteSyncStr = pParams->getParamVal("remoteSync", "true");
    setRemoteSyncEnabled(!boost::iequals(remoteSyncStr, "false"));

    m_maxSources = getProfileAgentSettingWithDefault<uint>(DEFAULT_MAX_SOURCES, "scannerDetector.maxSources");
    dbgTrace(D_WAAP) << "loadParams: m_maxSources set to " << m_maxSources;
}

class SourcesMonitorPost : public RestGetFile
{
public:
    SourcesMonitorPost(ScannerDetector::SourceKeyValsMap &_monitor)
        : monitor(std::move(_monitor))
    {
    }

private:
    C2S_PARAM(ScannerDetector::SourceKeyValsMap, monitor)
};

class SourcesMonitorGet : public RestGetFile
{
public:
    SourcesMonitorGet() : monitor()
    {
    }

    Maybe<ScannerDetector::SourceKeyValsMap> getSourcesMonitor()
    {
        return monitor.get();
    }

private:
    S2C_PARAM(ScannerDetector::SourceKeyValsMap, monitor)
};


bool ScannerDetector::postData()
{
    if (m_current_accumulator->empty()) {
        dbgDebug(D_WAAP) << "No data to post, skipping";
        return true;
    }
    SourcesMonitorPost postMonitor(*m_current_accumulator);
    bool ok = sendNoReplyObjectWithRetry(postMonitor,
        HTTPMethod::PUT,
        getPostDataUrl());

    if (ok) {
        m_current_accumulator = std::make_shared<SourceKeyValsMap>();
    }

    return ok;
}

void ScannerDetector::pullData(const std::vector<std::string> &files)
{
    std::string url = getPostDataUrl();
    std::string sentFile = url.erase(0, url.find_first_of('/') + 1);
    dbgTrace(D_WAAP) << "pulling files, skipping: " << sentFile;

    for (const auto &file : files) // Use const reference
    {
        if (file == sentFile) {
            continue;
        }
        dbgTrace(D_WAAP) << "Pulling the file: " << file;
        SourcesMonitorGet getMonitor;
        bool ok = sendObjectWithRetry(getMonitor,
            HTTPMethod::GET,
            getUri() + "/" + file);

        if (!ok) {
            dbgError(D_WAAP) << "Failed to get data from: " << file;
            continue;
        }

        SourceKeyValsMap remoteMonitor = getMonitor.getSourcesMonitor().unpack();
        mergeMonitors(*m_current_accumulator, remoteMonitor);
    }
}

void ScannerDetector::postProcessedData()
{
    // Empty implementation as in original
}

void ScannerDetector::updateState(const std::vector<std::string>&)
{
    // Empty implementation as in original
}

void ScannerDetector::pullProcessedData(const std::vector<std::string> &files)
{
    (void)files;
}

void ScannerDetector::evictLeastImportantSource()
{
    if (m_lruOrder.empty()) {
        return;
    }
    // Enhanced eviction: scan last N sources in LRU and evict the one with the smallest key count
    constexpr size_t N = 10; // Number of candidates to consider
    auto it = m_lruOrder.rbegin();
    auto it_end = m_lruOrder.rend();
    size_t checked = 0;
    std::string evictCandidate;
    size_t minKeyCount = std::numeric_limits<size_t>::max();
    auto candidateIt = m_lruOrder.rbegin();
    for (; it != it_end && checked < N; ++it, ++checked) {
        const std::string &source = *it;
        auto cacheIt = m_sourceCache.find(source);
        size_t keyCount = (cacheIt != m_sourceCache.end()) ? cacheIt->second.keys.size() : 0;
        if (keyCount < minKeyCount) {
            minKeyCount = keyCount;
            evictCandidate = source;
            candidateIt = it;
        }
    }
    if (evictCandidate.empty()) {
        // fallback to classic LRU
        evictCandidate = m_lruOrder.back();
        candidateIt = m_lruOrder.rbegin();
    }
    // Remove from all data structures - O(1) operations
    m_sourceCache.erase(evictCandidate);
    m_lruMap.erase(evictCandidate);
    // Erase from m_lruOrder using base iterator
    m_lruOrder.erase(std::next(candidateIt).base());
    // Remove evicted source from current accumulator
    m_current_accumulator->erase(evictCandidate);
    dbgTrace(D_WAAP) << "evictLeastImportantSource: Evicted " << evictCandidate
                    << " (key count: " << minKeyCount << ", cache size: " << m_sourceCache.size() << ")";
}

void ScannerDetector::mergeMonitors(SourceKeyValsMap &mergeTo, const SourceKeyValsMap &mergeFrom)
{
    for (const auto &sourceEntry : mergeFrom) { // Use const reference
        const std::string &source = sourceEntry.first;
        for (const auto &keyEntry : sourceEntry.second) { // Use const reference
            const std::string &key = keyEntry.first;
            for (const auto &value : keyEntry.second) { // Use const reference
                mergeTo[source][key].insert(value);
            }
        }
    }
}

void ScannerDetector::processData()
{
    dbgTrace(D_WAAP) << "processData: Processing accumulated sources";

    // Move current data to monitor deque for analysis
    if (!m_current_accumulator->empty()) {
        m_sources_monitor.push_front(m_current_accumulator);
        m_current_accumulator = std::make_shared<SourceKeyValsMap>();
    }

    // Merge all monitors into a single monitor, but only include cached sources
    SourceKeyValsMap mergedMonitor;
    for (const auto &monitor : m_sources_monitor) {
        mergeMonitors(mergedMonitor, *monitor);
    }

    if (m_sources_monitor.size() == MAX_RETENTION) {
        m_sources_monitor.pop_back(); // Keep only the latest MAX_RETENTION cycles
    }

    // Analyze cached sources to identify scanners
    m_sources.clear();

    // Simple threshold-based scanner detection
    const uint SCANNER_KEY_THRESHOLD = 3;

    for (const auto &sourceInfo : mergedMonitor) {
        const std::string &source = sourceInfo.first;
        const auto &keys = sourceInfo.second;
        if (keys.size() >= SCANNER_KEY_THRESHOLD) {
            dbgTrace(D_WAAP) << "processData: Source " << source
                            << " flagged as scanner (keyCount=" << keys.size() << ")";
            m_sources.push_back(source);
        }
    }

    dbgTrace(D_WAAP) << "processData: Found " << m_sources.size() << " scanners out of "
                    << m_sourceCache.size() << " sources in cache";

    m_lastSync = Singleton::Consume<I_TimeGet>::by<WaapComponent>()->getWalltime();
}

void ScannerDetector::serialize(std::ostream &stream)
{
    (void)stream;
}

void ScannerDetector::deserialize(std::istream &stream)
{
    (void)stream;
}
