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
#include "TrustedSources.h"
#include "KeywordIndicatorFilter.h"
#include "TypeIndicatorsFilter.h"
#include "WaapParameters.h"
#include "i_waapConfig.h"
#include "ScannersDetector.h"
#include "TuningDecisions.h"
#include <cereal/cereal.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/archives/json.hpp>
#include "UnifiedIndicatorsContainer.h"

using namespace Waap::Parameters;
class IWaf2Transaction;
struct Waf2ScanResult;

class IndicatorsFiltersManager : public I_IndicatorsFilter, public SerializeToLocalAndRemoteSyncBase
{
public:
    IndicatorsFiltersManager(const std::string &remotePath, const std::string &assetId,
        I_WaapAssetState* pWaapAssetState);

    ~IndicatorsFiltersManager();

    virtual void registerKeywords(const std::string &key, Waap::Keywords::KeywordsSet &keywords,
        IWaf2Transaction* pWaapTransaction);
    virtual bool shouldFilterKeyword(const std::string &key, const std::string &keyword) const;
    virtual void filterKeywords(const std::string &key, Waap::Keywords::KeywordsSet &keywords,
        std::vector<std::string> &filteredKeywords);
    std::set<std::string> &getMatchedOverrideKeywords(void);

    void pushSample(const std::string &key, const std::string &sample, IWaf2Transaction* pTransaction);

    bool loadPolicy(IWaapConfig* pConfig);
    void reset();
    void filterVerbose(const std::string &param,
        std::vector<std::string> &filteredKeywords,
        std::map<std::string, std::vector<std::string>>& filteredKeywordsVerbose);
    static std::string getLocationFromKey(const std::string &canonicKey, IWaf2Transaction* pTransaction);
    static std::string generateKey(const std::string &location,
        const std::string &param,
        const IWaf2Transaction* pTransaction);

    virtual void serialize(std::ostream &stream);
    virtual void deserialize(std::istream &stream);

    virtual std::set<std::string> getParameterTypes(const std::string &canonicParam) const;

    // New required functions from SerializeToLocalAndRemoteSyncBase
    virtual bool postData() override;
    virtual void pullData(const std::vector<std::string>& files) override;
    virtual void processData() override;
    virtual void postProcessedData() override;
    virtual void pullProcessedData(const std::vector<std::string>& files) override;
    virtual void updateState(const std::vector<std::string>& files) override;

    // Getter for unified indicators (for testing)
    const UnifiedIndicatorsContainer& getUnifiedIndicators() const { return *m_unifiedIndicators; }
private:
    static std::string extractUri(const std::string &referer, const IWaf2Transaction* pTransaction);
    void updateLearningLeaderFlag();
    bool shouldRegister(
        const std::string& key,
        const Waap::Keywords::KeywordsSet& keywords,
        const IWaf2Transaction* pTransaction
    );
    void updateSourcesLimit();

    std::unique_ptr<KeywordIndicatorFilter> m_keywordsFreqFilter;
    std::unique_ptr<TypeIndicatorFilter> m_typeFilter;
    I_WaapAssetState* m_pWaapAssetState;
    std::shared_ptr<Waap::TrustedSources::TrustedSourcesParameter> m_trustedSrcParams;
    ScannerDetector m_ignoreSources;
    TuningDecision m_tuning;
    std::set<std::string> m_matchedOverrideKeywords;
    bool m_isLeading;
    int m_sources_limit = 0;
    std::unordered_set<std::string> m_uniqueSources;
    std::shared_ptr<UnifiedIndicatorsContainer> m_unifiedIndicators;
};
