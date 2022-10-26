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

#include "KeywordIndicatorFilter.h"
#include "waap.h"
#include "WaapConfigApi.h"
#include "WaapConfigApplication.h"
#include "FpMitigation.h"
#include "i_transaction.h"
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/trim.hpp>

#define KEYWORDS_FILTER_PATH(dirPath) dirPath + "/5.data"
#define KEYWORDS_FILTER_TRUSTED_PATH(dirPath) dirPath + "/7.data"
#define KEYWORD_FILTER_PARAM(var) "KeywordsFilter." var

KeywordIndicatorFilter::KeywordIndicatorFilter(std::string dirPath,
    const std::string& remotePath,
    const std::string& assetId,
    I_IgnoreSources* ignoreSources,
    TuningDecision* tuning,
    size_t minSources,
    size_t minIntervals,
    std::chrono::minutes intervalDuration,
    double ratioThreshold) : IndicatorFilterBase(KEYWORDS_FILTER_PATH(dirPath),
        KEYWORDS_FILTER_TRUSTED_PATH(dirPath),
        (remotePath == "") ? remotePath : remotePath + "/Indicators",
        assetId,
        minSources,
        minIntervals,
        intervalDuration,
        ratioThreshold,
        "",
        tuning,
        ignoreSources)
{
    m_confidence_calc.setOwner("KeywordIndicatorFilter");
}

KeywordIndicatorFilter::~KeywordIndicatorFilter()
{

}

void KeywordIndicatorFilter::registerSource(const std::string &key, const std::string &source)
{
    dbgTrace(D_WAAP) << "registering source: " << source << " for parameter: " << key;
    m_confidence_calc.logSourceHit(key, source);
}

bool KeywordIndicatorFilter::shouldFilterKeyword(const std::string &key, const std::string &keyword) const
{
    bool is_confident = m_confidence_calc.is_confident(key, keyword);
    if (m_policy != nullptr)
    {
        is_confident |= m_trusted_confidence_calc.is_confident(key, keyword, m_policy->getNumOfSources());
    }
    std::string trimed_keyword = keyword;
    boost::algorithm::trim(trimed_keyword);
    is_confident |= m_confidence_calc.is_confident(key, trimed_keyword);
    return is_confident;
}

bool KeywordIndicatorFilter::loadParams(std::shared_ptr<Waap::Parameters::WaapParameters> pParams)
{
    ConfidenceCalculatorParams params;

    params.minSources = std::stoul(
        pParams->getParamVal("learnIndicators.minSources", std::to_string(CONFIDENCE_MIN_SOURCES)));
    params.minIntervals = std::stoul(
        pParams->getParamVal("learnIndicators.minIntervals", std::to_string(CONFIDENCE_MIN_INTERVALS)));
    params.intervalDuration = std::chrono::minutes(std::stoul(
        pParams->getParamVal("learnIndicators.intervalDuration",
            std::to_string(CONFIDENCE_WINDOW_INTERVAL.count()))));
    params.ratioThreshold = std::stod(pParams->getParamVal("learnIndicators.ratio",
        std::to_string(CONFIDENCE_THRESHOLD)));
    std::string learnPermanentlyStr = pParams->getParamVal("learnIndicators.learnPermanently", "true");
    params.learnPermanently = !boost::iequals(learnPermanentlyStr.c_str(), "false");

    std::string remoteSyncStr = pParams->getParamVal("remoteSync", "true");
    bool syncEnabled = !boost::iequals(remoteSyncStr, "false");

    dbgTrace(D_WAAP) << params << " remote sync: " << remoteSyncStr;

    m_confidence_calc.setRemoteSyncEnabled(syncEnabled);
    m_trusted_confidence_calc.setRemoteSyncEnabled(syncEnabled);
    return m_confidence_calc.reset(params);
}


void KeywordIndicatorFilter::registerKeywords(const std::string& key, Waap::Keywords::KeywordsSet& keywords,
    IWaf2Transaction* pTransaction)
{
    std::string source(pTransaction->getSourceIdentifier());
    std::string trusted_source = getTrustedSource(pTransaction);
    if (keywords.empty())
    {
        registerSource(key, source);
    }
    for (auto keyword : keywords)
    {
        boost::algorithm::trim(keyword);
        registerKeyword(key, keyword, source, trusted_source);
    }
    if (m_tuning != nullptr && (m_tuning->getDecision(pTransaction->getUri(), URL) == BENIGN ||
        m_tuning->getDecision(pTransaction->getLastScanSample(), PARAM_VALUE) == BENIGN))
    {
        source = "TuningDecisionSource_" + source;
        for (auto keyword : keywords)
        {
            boost::algorithm::trim(keyword);
            registerKeyword(key, keyword, source, trusted_source);
        }
    }
}
