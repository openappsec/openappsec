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
#include "i_messaging.h"
#include "ScannersDetector.h"
#include "TuningDecisions.h"
#include <cereal/cereal.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/archives/json.hpp>

using namespace Waap::Parameters;
class IWaf2Transaction;
struct Waf2ScanResult;

class IndicatorsFiltersManager : public I_IndicatorsFilter, public SerializeToFileBase
{
public:
    IndicatorsFiltersManager(const std::string &remotePath, const std::string &assetId,
        I_WaapAssetState* pWaapAssetState);
    ~IndicatorsFiltersManager();

    virtual void registerKeywords(const std::string& key, Waap::Keywords::KeywordsSet& keywords,
        IWaf2Transaction* pWaapTransaction);
    virtual bool shouldFilterKeyword(const std::string &key, const std::string &keyword) const;
    virtual void filterKeywords(const std::string &key, Waap::Keywords::KeywordsSet& keywords,
        std::vector<std::string>& filteredKeywords);
    std::set<std::string> &getMatchedOverrideKeywords(void);

    void pushSample(const std::string& key, const std::string& sample, IWaf2Transaction* pTransaction);

    bool loadPolicy(IWaapConfig* pConfig);
    void reset();
    void filterVerbose(const std::string &param,
        std::vector<std::string>& filteredKeywords,
        std::map<std::string, std::vector<std::string>>& filteredKeywordsVerbose);
    static std::string getLocationFromKey(const std::string& canonicKey, IWaf2Transaction* pTransaction);
    static std::string generateKey(const std::string& location,
        const std::string& param,
        const IWaf2Transaction* pTransaction);

    virtual void serialize(std::ostream& stream);
    virtual void deserialize(std::istream& stream);

    virtual std::set<std::string> getParameterTypes(const std::string& canonicParam) const;
private:
    static std::string extractUri(const std::string& referer, const IWaf2Transaction* pTransaction);

    std::unique_ptr<KeywordIndicatorFilter> m_keywordsFreqFilter;
    std::unique_ptr<TypeIndicatorFilter> m_typeFilter;
    std::shared_ptr<Waap::TrustedSources::TrustedSourcesParameter> m_trustedSrcParams;
    ScannerDetector m_ignoreSources;
    TuningDecision m_tuning;
    std::set<std::string> m_matchedOverrideKeywords;
};
