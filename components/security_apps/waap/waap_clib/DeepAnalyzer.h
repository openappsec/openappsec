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
#include "D2Main.h"
#include "i_waapConfig.h"
#include "WaapEnums.h"
#include "i_deepAnalyzer.h"
#include <memory>
#include <unordered_map>

struct D1AnalysisInput {
    std::string siteId;
    std::string sourceIp;
    std::string userAgent;
    std::string uri;
    std::string shortUri;
    std::string param;
    std::vector<std::string> keywordMatches;
    double score;
};

struct AnalysisResult {
    D2OutputData d2Analysis;
    ThreatLevel threatLevel;
    bool shouldBlock;
};

class DeepAnalyzer : Singleton::Provide<I_DeepAnalyzer> {
public:
    DeepAnalyzer();
    virtual ~DeepAnalyzer();

    virtual AnalysisResult analyzeData(IWaf2Transaction* waf2Trans, const IWaapConfig* pSitePolicy);

    void reset();

    class Impl;
protected:
    std::unique_ptr<Impl> pimpl;
};

class DeepAnalyzer::Impl : Singleton::Provide<I_DeepAnalyzer>::From<DeepAnalyzer>
{
public:
    Impl();
    virtual ~Impl();

    void reset();
    bool isMapEmpty();

    AnalysisResult analyzeData(const D2InputData& data, const IWaapConfig* pSitePolicy);
    virtual AnalysisResult analyzeData(IWaf2Transaction* waf2Trans, const IWaapConfig* pSitePolicy);
    static bool isException(const IWaapConfig* pSitePolicy, const std::string& sourceIp);

    // API for testing
    void setD2Main(std::string assetId, D2Main* d2main);
protected:
    const std::unique_ptr<D2Main>& getD2Main(const std::string& assetId);
    std::unordered_map<std::string, std::unique_ptr<D2Main> > m_d2MainMap;
};
