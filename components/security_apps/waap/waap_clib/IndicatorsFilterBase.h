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

#include "i_indicatorsFilter.h"
#include "i_messaging.h"
#include "waap.h"
#include "TrustedSources.h"
#include "TrustedSourcesConfidence.h"
#include "ConfidenceCalculator.h"
#include "TuningDecisions.h"

class IndicatorFilterBase : public I_IndicatorsFilter
{
public:
    IndicatorFilterBase(const std::string& confidence_path,
        const std::string& trusted_path,
        const std::string& remotePath,
        const std::string& assetId,
        size_t min_sources,
        size_t min_intervals,
        std::chrono::minutes interval_duration,
        double ratio_threshold,
        const std::string& null_obj,
        TuningDecision* tuning,
        I_IgnoreSources* ignoreSources = nullptr);
    virtual void filterKeywords(const std::string &key, Waap::Keywords::KeywordsSet& keywords,
        std::vector<std::string>& filteredKeywords);

    bool setTrustedSrcParameter(std::shared_ptr<Waap::TrustedSources::TrustedSourcesParameter> policy);
    void reset();
protected:
    std::string getTrustedSource(IWaf2Transaction* pTransaction);
    void registerKeyword(const std::string& key,
        const std::string& keyword,
        const std::string& source,
        const std::string& trusted_src);

    ConfidenceCalculator m_confidence_calc;
    TrustedSourcesConfidenceCalculator m_trusted_confidence_calc;
    std::shared_ptr<Waap::TrustedSources::TrustedSourcesParameter> m_policy;
    TuningDecision* m_tuning;
private:
    bool isTrustedSourceOfType(const std::string& source, Waap::TrustedSources::TrustedSourceType srcType);
};
