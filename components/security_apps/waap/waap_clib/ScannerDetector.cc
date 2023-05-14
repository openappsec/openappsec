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
#include "i_messaging.h"
#include <boost/algorithm/string/predicate.hpp>

USE_DEBUG_FLAG(D_WAAP);
#define SYNC_WAIT_TIME std::chrono::seconds(300) // 5 minutes in seconds
#define INTERVAL std::chrono::minutes(120)
#define EQUAL_VALUES_COUNT_THRESHOLD 2
#define MAX_RETENTION 5

ScannerDetector::ScannerDetector(const std::string& localPath, const std::string& remotePath,
        const std::string &assetId) :
    SerializeToLocalAndRemoteSyncBase(INTERVAL, SYNC_WAIT_TIME,
    localPath + "/11.data",
    (remotePath == "") ? remotePath : remotePath + "/ScannersDetector",
    assetId,
    "ScannerDetector")
{
    m_sources_monitor.push_front(SourceKeyValsMap());
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

void ScannerDetector::log(const std::string& source, const std::string& key, Waap::Keywords::KeywordsSet& keywords)
{
    m_sources_monitor.front()[source][key].insert(keywords.begin(), keywords.end());
}

void ScannerDetector::loadParams(std::shared_ptr<Waap::Parameters::WaapParameters> pParams)
{
    std::string interval = pParams->getParamVal("learnIndicators.intervalDuration",
            std::to_string(INTERVAL.count()));
    setInterval(std::chrono::minutes(std::stoul(interval)));
    std::string remoteSyncStr = pParams->getParamVal("remoteSync", "true");
    setRemoteSyncEnabled(!boost::iequals(remoteSyncStr, "false"));
}

class SourcesMonitorPost : public RestGetFile
{
public:
    SourcesMonitorPost(ScannerDetector::SourceKeyValsMap& _monitor)
        : monitor(_monitor)
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
    m_sources_monitor_backup = m_sources_monitor.front();
    m_sources_monitor.push_front(SourceKeyValsMap());
    std::string url = getPostDataUrl();

    dbgTrace(D_WAAP) << "Sending the data to: " << url;

    SourcesMonitorPost currentWindow(m_sources_monitor_backup);
    bool ok = sendNoReplyObjectWithRetry(currentWindow,
        I_Messaging::Method::PUT,
        url);
    if (!ok) {
        dbgError(D_WAAP) << "Failed to post collected data to: " << url;
    }
    return ok;
}

void ScannerDetector::pullData(const std::vector<std::string>& files)
{
    std::string url = getPostDataUrl();
    std::string sentFile = url.erase(0, url.find_first_of('/') + 1);
    dbgTrace(D_WAAP) << "pulling files, skipping: " << sentFile;
    for (auto file : files)
    {
        if (file == sentFile)
        {
            continue;
        }
        dbgTrace(D_WAAP) << "Pulling the file: " << file;
        SourcesMonitorGet getMonitor;
        bool ok = sendObjectWithRetry(getMonitor,
            I_Messaging::Method::GET,
            getUri() + "/" + file);

        if (!ok) {
            dbgError(D_WAAP) << "Failed to get data from: " << file;
            continue;
        }

        SourceKeyValsMap remoteMonitor = getMonitor.getSourcesMonitor().unpack();
        for (const auto& srcData : remoteMonitor)
        {
            for (const auto& keyData : srcData.second)
            {
                m_sources_monitor_backup[srcData.first][keyData.first].insert(
                keyData.second.begin(),
                keyData.second.end());
            }
        }
        // update the sources monitor in previous "time window"
        auto temp = m_sources_monitor.front();
        m_sources_monitor.pop_front();
        m_sources_monitor.pop_front();
        m_sources_monitor.push_front(m_sources_monitor_backup);
        m_sources_monitor.push_front(temp);
    }
}

void ScannerDetector::postProcessedData()
{

}

void ScannerDetector::updateState(const std::vector<std::string>&)
{
}

void ScannerDetector::pullProcessedData(const std::vector<std::string>& files)
{
    (void)files;
}

void ScannerDetector::mergeMonitors(SourceKeyValsMap& mergeTo, SourceKeyValsMap& mergeFrom)
{
    for (const auto& srcData : mergeFrom)
    {
        for (const auto& keyData : srcData.second)
        {
            dbgTrace(D_WAAP) << "merging src: " << srcData.first << ", key: " << keyData.first <<
                ", keywords: " << Waap::Util::setToString(keyData.second);
            mergeTo[srcData.first][keyData.first].insert(keyData.second.begin(), keyData.second.end());
        }
    }
}

void ScannerDetector::processData()
{
    if (m_sources_monitor_backup.empty())
    {
        m_sources_monitor_backup = m_sources_monitor.front();
        m_sources_monitor.push_front(SourceKeyValsMap());
    }

    if (m_sources_monitor.size() > 2)
    {
        auto monitorItr = m_sources_monitor.begin()++;
        for (monitorItr++; monitorItr != m_sources_monitor.end(); monitorItr++)
        {
            mergeMonitors(m_sources_monitor_backup, *monitorItr);
        }
    }

    m_sources.clear();
    for (auto source : m_sources_monitor_backup)
    {
        if (source.second.size() <= 2)
        {
            continue;
        }
        std::map<std::string, std::set<std::string>>& keyVals = source.second;
        for (auto key = keyVals.begin(); key != keyVals.end(); key++)
        {
            auto otherKey = key;
            int counter = 0;
            for (++otherKey; otherKey != keyVals.end(); otherKey++)
            {
                if (key->second != otherKey->second)
                {
                    continue;
                }
                dbgTrace(D_WAAP) << "source monitor: src: " << source.first << ", key_1: " << key->first << ", key_2: "
                    << otherKey->first << ", vals: " << Waap::Util::setToString(key->second);
                counter++;
            }
            if (counter >= EQUAL_VALUES_COUNT_THRESHOLD)
            {
                dbgDebug(D_WAAP) << "source: " << source.first << " will be ignored";
                m_sources.push_back(source.first);
                break;
            }
        }
    }

    if (m_sources_monitor.size() > MAX_RETENTION)
    {
        m_sources_monitor.pop_back();
    }
    m_sources_monitor_backup.clear();
    m_lastSync = Singleton::Consume<I_TimeGet>::by<WaapComponent>()->getWalltime();
}

void ScannerDetector::serialize(std::ostream& stream)
{
    (void)stream;
}

void ScannerDetector::deserialize(std::istream& stream)
{
    (void)stream;
}
