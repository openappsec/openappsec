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

#include "TypeIndicatorsFilter.h"
#include "waap.h"
#include "debug.h"
#include <cereal/types/unordered_map.hpp>
#include <cereal/types/set.hpp>
#include <cereal/archives/json.hpp>
#include "FpMitigation.h"
#include "i_transaction.h"
#include "Waf2Util.h"
#include "IndicatorsFiltersManager.h"
#include <boost/algorithm/string/predicate.hpp>

USE_DEBUG_FLAG(D_WAAP);

#define TYPES_FILTER_PATH(dirPath) dirPath + "/4.data"
#define TYPES_FILTER_TRUST_PATH(dirPath) dirPath + "/9.data"

TypeIndicatorFilter::TypeIndicatorFilter(I_WaapAssetState* pWaapAssetState,
    const std::string& remotePath,
    const std::string& assetId,
    TuningDecision* tuning,
    size_t minSources,
    size_t minIntervals,
    std::chrono::minutes intervalDuration,
    double ratioThreshold) :
    IndicatorFilterBase(TYPES_FILTER_PATH(pWaapAssetState->getWaapDataDir()),
        TYPES_FILTER_TRUST_PATH(pWaapAssetState->getWaapDataDir()),
        (remotePath == "") ? remotePath : remotePath + "/Type",
        assetId,
        minSources,
        minIntervals,
        intervalDuration,
        ratioThreshold,
        "unknown",
        tuning),
    m_pWaapAssetState(pWaapAssetState)
{
    m_confidence_calc.setOwner("TypeIndicatorFilter");
}

TypeIndicatorFilter::~TypeIndicatorFilter()
{

}

bool TypeIndicatorFilter::shouldFilterKeyword(const std::string &key, const std::string &keyword) const
{
    auto keyTypes = getParamTypes(key);
    std::string htmlParam = ".html";
    bool isHtmlInput = keyTypes.find("html_input") != keyTypes.end() ||
        (key.size() > htmlParam.size() &&
            key.compare(key.size() - htmlParam.size(), htmlParam.size(), htmlParam) == 0);
    for (auto keyType : keyTypes)
    {
        static const std::string free_text = "free_text";
        if (!keyType.compare(0, free_text.size(), free_text) && !isHtmlInput)
        {
            return true;
        }
        if (m_pWaapAssetState->isKeywordOfType(keyword, Waap::Util::convertTypeStrToEnum(keyType)))
        {
            return true;
        }
    }
    return false;
}

void TypeIndicatorFilter::registerKeywords(const std::string& key, Waap::Keywords::KeywordsSet& keywords,
    IWaf2Transaction* pTransaction)
{
    (void)keywords;
    std::string sample = pTransaction->getLastScanSample();
    registerKeywords(key, sample, pTransaction);
}

void TypeIndicatorFilter::registerKeywords(const std::string& key, const std::string& sample,
    IWaf2Transaction* pTransaction)
{
    std::set<std::string> types = m_pWaapAssetState->getSampleType(sample);
    std::string source = pTransaction->getSourceIdentifier();
    std::string trusted_source = getTrustedSource(pTransaction);

    for (const std::string &type : types)
    {
        if (type == "local_file_path")
        {
            std::string location = IndicatorsFiltersManager::getLocationFromKey(key, pTransaction);
            if (location == "url" || location == "referer")
            {
                continue;
            }
        }
        registerKeyword(key, type, source, trusted_source);
        if (m_tuning != nullptr && m_tuning->getDecision(pTransaction->getUri(), URL) == BENIGN)
        {
            source = "TuningDecisionSource_" + source;
            registerKeyword(key, type, source, trusted_source);
        }

    }
}

void TypeIndicatorFilter::loadParams(std::shared_ptr<Waap::Parameters::WaapParameters> pParams)
{
    ConfidenceCalculatorParams params;

    params.minSources = std::stoul(
        pParams->getParamVal("typeIndicators.minSources", std::to_string(TYPE_FILTER_CONFIDENCE_MIN_SOURCES)));
    params.minIntervals = std::stoul(
        pParams->getParamVal("typeIndicators.minIntervals", std::to_string(TYPE_FILTER_CONFIDENCE_MIN_INTERVALS)));
    params.intervalDuration = std::chrono::minutes(std::stoul(
        pParams->getParamVal("typeIndicators.intervalDuration",
            std::to_string(TYPE_FILTER_INTERVAL_DURATION.count()))));
    params.ratioThreshold = std::stod(pParams->getParamVal("typeIndicators.ratio",
        std::to_string(TYPE_FILTER_CONFIDENCE_THRESHOLD)));
    std::string learnPermanentlyStr = pParams->getParamVal("typeIndicators.learnPermanently", "true");
    params.learnPermanently = !boost::iequals(learnPermanentlyStr, "false");

    std::string remoteSyncStr = pParams->getParamVal("remoteSync", "true");
    bool syncEnabled = !boost::iequals(remoteSyncStr, "false");

    dbgTrace(D_WAAP) << params << " remote sync: " << remoteSyncStr;

    m_confidence_calc.setRemoteSyncEnabled(syncEnabled);
    m_trusted_confidence_calc.setRemoteSyncEnabled(syncEnabled);

    m_confidence_calc.reset(params);
}

std::set<std::string> TypeIndicatorFilter::getParamTypes(const std::string& canonicParam) const
{
    std::set<std::string> types = m_confidence_calc.getConfidenceValues(canonicParam);
    if (m_policy != nullptr)
    {
        std::set<std::string> types_trusted = m_trusted_confidence_calc.getConfidenceValues(canonicParam,
            m_policy->getNumOfSources());
        types.insert(types_trusted.begin(), types_trusted.end());
    }
    return types;
}
