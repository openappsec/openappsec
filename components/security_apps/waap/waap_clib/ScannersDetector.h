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

#ifndef __OPTIMIZED_SCANNERS_DETECTOR_H__
#define __OPTIMIZED_SCANNERS_DETECTOR_H__

#include "WaapKeywords.h"
#include "i_serialize.h"
#include "i_ignoreSources.h"
#include "WaapParameters.h"
#include <chrono>
#include <unordered_map>
#include <unordered_set>
#include <list>

// TODO PHASE3: remove inheritance from SerializeToLocalAndRemoteSyncBase

class ScannerDetector : public SerializeToLocalAndRemoteSyncBase, public I_IgnoreSources
{
public:
    typedef std::map<std::string, std::map<std::string, std::set<std::string>>> SourceKeyValsMap;
    struct SourceInfo {
        std::string source;
        std::unordered_set<std::string> keys;
        std::chrono::microseconds lastUpdate;
        uint32_t accessCount;  // Track access frequency for LFU eviction
        
        // Default constructor for container requirements
        SourceInfo() : lastUpdate(std::chrono::microseconds(0)), accessCount(0) {}
        
        SourceInfo(const std::string &src, std::chrono::microseconds time)
            : source(src), lastUpdate(time), accessCount(1) {}

        uint getKeyCount() const { return keys.size(); }
        
        void updateKeys(const std::set<std::string> &newKeys) {
            keys.clear();
            keys.insert(newKeys.begin(), newKeys.end());
            lastUpdate = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now().time_since_epoch());
            accessCount++;
        }
    };
    
    ScannerDetector(
        const std::string &localPath,
        const std::string &remotePath = "",
        const std::string &assetId = "");

    virtual bool ready();
    virtual std::vector<std::string>* getSourcesToIgnore();
    void log(const std::string &source, const std::string &key, Waap::Keywords::KeywordsSet &keywords);

    void loadParams(std::shared_ptr<Waap::Parameters::WaapParameters> pParams);

    virtual bool postData();
    virtual void pullData(const std::vector<std::string> &files);
    virtual void processData();
    virtual void postProcessedData();
    virtual void pullProcessedData(const std::vector<std::string> &files);
    virtual void updateState(const std::vector<std::string> &files);

    virtual void serialize(std::ostream &stream);
    virtual void deserialize(std::istream &stream);

private:
    void evictLeastImportantSource();
    void mergeMonitors(SourceKeyValsMap &mergeTo, const SourceKeyValsMap &mergeFrom);
    
    // Optimized data structures
    std::unordered_map<std::string, SourceInfo> m_sourceCache;
    std::list<std::string> m_lruOrder;
    std::unordered_map<std::string, std::list<std::string>::iterator> m_lruMap;
    
    // Original data structures for compatibility
    std::shared_ptr<SourceKeyValsMap> m_current_accumulator;
    std::deque<std::shared_ptr<SourceKeyValsMap>> m_sources_monitor;
    SourceKeyValsMap m_sources_monitor_backup;
    std::vector<std::string> m_sources;
    std::chrono::microseconds m_lastSync;
    uint m_maxSources;
};

#endif
