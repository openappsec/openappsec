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
#include "IndicatorsFilterBase.h"
#include "WaapKeywords.h"
#include "WaapEnums.h"
#include "i_waap_asset_state.h"
#include "ConfidenceCalculator.h"
#include "WaapParameters.h"
#include <unordered_map>

#define TYPE_FILTER_CONFIDENCE_MIN_SOURCES 10
#define TYPE_FILTER_CONFIDENCE_MIN_INTERVALS 5
#define TYPE_FILTER_CONFIDENCE_THRESHOLD 0.8
#define TYPE_FILTER_INTERVAL_DURATION std::chrono::minutes(60)

class TypeIndicatorFilter : public IndicatorFilterBase
{
public:
    TypeIndicatorFilter(I_WaapAssetState* pWaapAssetState,
        const std::string& remotePath,
        const std::string& assetId,
        TuningDecision* tuning = nullptr,
        size_t minSources = TYPE_FILTER_CONFIDENCE_MIN_SOURCES,
        size_t minIntervals = TYPE_FILTER_CONFIDENCE_MIN_INTERVALS,
        std::chrono::minutes intervalDuration = TYPE_FILTER_INTERVAL_DURATION,
        double ratioThreshold = TYPE_FILTER_CONFIDENCE_THRESHOLD);
    ~TypeIndicatorFilter();

    virtual void registerKeywords(const std::string& key, Waap::Keywords::KeywordsSet& keyword,
        IWaf2Transaction* pTransaction);

    void registerKeywords(const std::string& key, const std::string& sample, IWaf2Transaction* pTransaction);

    void loadParams(std::shared_ptr<Waap::Parameters::WaapParameters> pParams);
    virtual bool shouldFilterKeyword(const std::string &keyword, const std::string &key) const;
    std::set<std::string> getParamTypes(const std::string& canonicParam) const;

private:
    I_WaapAssetState* m_pWaapAssetState;
};
