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
#include "ConfidenceCalculator.h"
#include "WaapParameters.h"


#define CONFIDENCE_MIN_SOURCES 3
#define CONFIDENCE_MIN_INTERVALS 5
#define CONFIDENCE_THRESHOLD 0.8
#define CONFIDENCE_WINDOW_INTERVAL std::chrono::minutes(120)


class KeywordIndicatorFilter : public IndicatorFilterBase
{
public:
    KeywordIndicatorFilter(std::string dirPath,
        const std::string& remotePath,
        const std::string& assetId,
        I_IgnoreSources* ignoreSources,
        TuningDecision* tuning = nullptr,
        size_t minSources = CONFIDENCE_MIN_SOURCES,
        size_t minIntervals = CONFIDENCE_MIN_INTERVALS,
        std::chrono::minutes intervalDuration = CONFIDENCE_WINDOW_INTERVAL,
        double ratioThreshold = CONFIDENCE_THRESHOLD);
    ~KeywordIndicatorFilter();

    virtual void registerKeywords(const std::string& key, Waap::Keywords::KeywordsSet& keywords,
        IWaf2Transaction* pTransaction);

    virtual bool shouldFilterKeyword(const std::string &key, const std::string &keyword) const;

    bool loadParams(std::shared_ptr<Waap::Parameters::WaapParameters> pParams);
private:
    void registerSource(const std::string &key, const std::string &source);
};
