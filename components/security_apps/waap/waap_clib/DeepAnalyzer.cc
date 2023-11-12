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

// #define WAF2_LOGGING_ENABLE
#include "DeepAnalyzer.h"
#include "Waf2Engine.h"
#include "WaapConversions.h"
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP);

DeepAnalyzer::DeepAnalyzer() : pimpl(std::make_unique<DeepAnalyzer::Impl>())
{
}

DeepAnalyzer::~DeepAnalyzer()
{
}

void DeepAnalyzer::reset()
{
    pimpl->reset();
}

AnalysisResult DeepAnalyzer::analyzeData(IWaf2Transaction* pWaf2Trans, const IWaapConfig* pSitePolicy)
{
    return pimpl->analyzeData(pWaf2Trans, pSitePolicy);
}

bool DeepAnalyzer::Impl::isException(const IWaapConfig* pWaapConfig, const std::string& sourceIp)
{
    bool isException = false;
    if (pWaapConfig != NULL)

    {
        isException |= false;
    }

    return isException;
}

void DeepAnalyzer::Impl::setD2Main(std::string assetId, D2Main* d2main)
{
    std::unordered_map<std::string, std::unique_ptr<D2Main>>::iterator it;
    it = m_d2MainMap.find(assetId);

    if (it == m_d2MainMap.end())
    {
        m_d2MainMap.insert(std::make_pair(assetId, std::unique_ptr<D2Main>(d2main)));
    }
    else
    {
        m_d2MainMap[assetId].reset(d2main);
    }
}

DeepAnalyzer::Impl::Impl() : m_d2MainMap()
{
}

DeepAnalyzer::Impl::~Impl()
{
}

void DeepAnalyzer::Impl::reset()
{
    auto itr = m_d2MainMap.begin();
    while (itr != m_d2MainMap.end())
    {
        itr->second.reset();
        itr = m_d2MainMap.erase(itr);
    }
}

bool DeepAnalyzer::Impl::isMapEmpty()
{
    return m_d2MainMap.empty();
}

AnalysisResult DeepAnalyzer::Impl::analyzeData(const D2InputData& data, const IWaapConfig* pSitePolicy)
{
    AnalysisResult analysis;

    const std::unique_ptr<D2Main>& d2Main = getD2Main(data.siteId);

    analysis.d2Analysis = d2Main->analyzeData(data);

    ThreatLevel threat = Waap::Conversions::convertFinalScoreToThreatLevel(analysis.d2Analysis.finalScore);

    bool shouldBlock = Waap::Conversions::shouldDoWafBlocking(pSitePolicy, threat);
    bool shouldExcept = isException(pSitePolicy, data.sourceIdentifier);

    dbgDebug(D_WAAP) << "stage2 analysis: final score: " << analysis.d2Analysis.finalScore << ", reputation: " <<
        analysis.d2Analysis.relativeReputation << ", false positive mitigation score: " <<
        analysis.d2Analysis.fpMitigationScore << ", threat level: " << threat << "\nWAF2 decision to block: " <<
        (shouldBlock ? "block" : "pass") << ", is the request in exception list: " <<
        (shouldExcept ? "true" : "false");

    analysis.threatLevel = threat;
    analysis.shouldBlock = shouldBlock;

    return analysis;
}

AnalysisResult DeepAnalyzer::Impl::analyzeData(IWaf2Transaction* pWaf2Trans, const IWaapConfig* pSitePolicy)
{
    D2InputData input;

    if (pWaf2Trans == NULL || pSitePolicy == NULL)
    {
        dbgWarning(D_WAAP) << "invalid argument pWaf2Trans(0x" << std::hex << pWaf2Trans << "), pSitePolicy(0x" <<
            std::hex << pSitePolicy << ")";
        return AnalysisResult();
    }

    input.sourceIdentifier = pWaf2Trans->getSourceIdentifier();
    input.userAgent = pWaf2Trans->getUserAgent();
    input.param = pWaf2Trans->getParam();
    input.location = pWaf2Trans->getLocation();
    input.siteId = pSitePolicy->get_AssetId();
    input.keywordMatches = pWaf2Trans->getKeywordMatches();
    input.uri = pWaf2Trans->getUriStr();
    input.score = pWaf2Trans->getScore();

    return analyzeData(input, pSitePolicy);
}

const std::unique_ptr<D2Main>& DeepAnalyzer::Impl::getD2Main(const std::string& assetId)
{
    std::unordered_map<std::string, std::unique_ptr<D2Main>>::iterator it;
    std::string mapKey = assetId;
    if (Singleton::exists<I_InstanceAwareness>())
    {
        I_InstanceAwareness* instanceAwareness = Singleton::Consume<I_InstanceAwareness>::by<WaapComponent>();
        Maybe<std::string> uniqueId = instanceAwareness->getUniqueID();
        if (uniqueId.ok())
        {
            mapKey += "/" + uniqueId.unpack();
        }
    }
    it = m_d2MainMap.find(mapKey);

    if (it == m_d2MainMap.end())
    {
        m_d2MainMap.insert(std::make_pair(mapKey, std::unique_ptr<D2Main>(new D2Main(mapKey))));
    }

    const std::unique_ptr<D2Main>& result = m_d2MainMap[mapKey];
    return result;
};
