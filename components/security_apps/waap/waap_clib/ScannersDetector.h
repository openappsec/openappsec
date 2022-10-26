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

#ifndef __SCANNERS_DETECTOR_H__
#define __SCANNERS_DETECTOR_H__

#include "WaapKeywords.h"
#include "i_serialize.h"
#include "i_ignoreSources.h"
#include "WaapParameters.h"

class ScannerDetector : public SerializeToLocalAndRemoteSyncBase, public I_IgnoreSources
{
public:
    typedef std::map<std::string, std::map<std::string, std::set<std::string>>> SourceKeyValsMap;
    ScannerDetector(const std::string& localPath, const std::string& remotePath = "", const std::string &assetId = "");

    virtual bool ready();
    virtual std::vector<std::string>* getSourcesToIgnore();
    void log(const std::string& source, const std::string& key, Waap::Keywords::KeywordsSet& keywords);

    void loadParams(std::shared_ptr<Waap::Parameters::WaapParameters> pParams);

    virtual bool postData();
    virtual void pullData(const std::vector<std::string>& files);
    virtual void processData();
    virtual void postProcessedData();
    virtual void pullProcessedData(const std::vector<std::string>& files);
    virtual void updateState(const std::vector<std::string>& files);

    virtual void serialize(std::ostream& stream);
    virtual void deserialize(std::istream& stream);

private:
    void mergeMonitors(SourceKeyValsMap& mergeTo, SourceKeyValsMap& mergeFrom);

    std::list<SourceKeyValsMap> m_sources_monitor; // list of map source -> key -> set of indicators
    SourceKeyValsMap  m_sources_monitor_backup; // stores data of the last window to process

    std::vector<std::string> m_sources;
    std::chrono::microseconds m_lastSync;
};


#endif
