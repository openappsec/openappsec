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

#include "IndicatorsFiltersManager.h"
#include "WaapConfigApi.h"
#include "WaapConfigApplication.h"
#include <vector>
#include "Waf2Util.h"
#include "FpMitigation.h"
#include "Waf2Engine.h"
#include "WaapKeywords.h"
#include "config.h"

USE_DEBUG_FLAG(D_WAAP_LEARN);
static constexpr int DEFAULT_SOURCES_LIMIT = 1000;


using namespace std;

// // Helper class for posting unified indicators
// class UnifiedIndicatorsLogPost : public RestGetFile {
// public:
//     UnifiedIndicatorsLogPost(shared_ptr<UnifiedIndicatorsContainer> container_ptr)
//     {
//         window_logger = move(*container_ptr);
//     }
// private:
//     C2S_PARAM(UnifiedIndicatorsContainer, window_logger);
// };

IndicatorsFiltersManager::IndicatorsFiltersManager(const string& remotePath, const string &assetId,
    I_WaapAssetState* pWaapAssetState)
    :
    SerializeToLocalAndRemoteSyncBase(
        chrono::minutes(120),
        chrono::seconds(300),
    pWaapAssetState->getWaapDataDir() + "/6.data",
        (remotePath == "") ? remotePath : remotePath + "/CentralizedData",
        assetId,
        "IndicatorsFiltersManager"
    ),
    m_pWaapAssetState(pWaapAssetState),
    m_ignoreSources(pWaapAssetState->getWaapDataDir(), remotePath, assetId),
    m_tuning(remotePath),
    m_matchedOverrideKeywords(),
    m_isLeading(getSettingWithDefault<bool>(true, "features", "learningLeader")),
    m_sources_limit(DEFAULT_SOURCES_LIMIT),
    m_uniqueSources(),
    m_unifiedIndicators(make_shared<UnifiedIndicatorsContainer>())
{
    restore();
    m_keywordsFreqFilter = make_unique<KeywordIndicatorFilter>(
        pWaapAssetState->getWaapDataDir(),
        remotePath,
        assetId,
        &m_ignoreSources,
        &m_tuning);
    m_typeFilter = make_unique<TypeIndicatorFilter>(pWaapAssetState, remotePath, assetId, &m_tuning);
    m_uniqueSources.reserve(m_sources_limit);

    registerConfigLoadCb([this](){
        updateSourcesLimit();
        updateLearningLeaderFlag();
    });
}

IndicatorsFiltersManager::~IndicatorsFiltersManager()
{
}

bool IndicatorsFiltersManager::shouldRegister(
    const string& key,
    const Waap::Keywords::KeywordsSet& keywords,
    const IWaf2Transaction* pTransaction)
{
    // Check if the learning leader flag is true
    if (!m_isLeading) {
        dbgDebug(D_WAAP_LEARN) << "Learning leader flag is false. Skipping source ID assertion.";
        return false;
    }

    // if key needs tracking
    if (m_keywordsFreqFilter->shouldTrack(key, keywords) ||
        m_typeFilter->shouldTrack(key, pTransaction)) {
        dbgDebug(D_WAAP_LEARN) << "Key '" << key << "' needs tracking.";
    } else {
        dbgTrace(D_WAAP_LEARN) << "Key '" << key << "' does not need tracking.";
        return false;
    }

    auto sourceId = pTransaction->getSourceIdentifier();

    // Check if the database has reached its limit and source is unknown
    if (m_uniqueSources.size() >= static_cast<size_t>(m_sources_limit) &&
        m_uniqueSources.find(sourceId) == m_uniqueSources.end() ) {
        dbgDebug(D_WAAP_LEARN) << "Database limit reached. Cannot insert new source ID '" << sourceId << "'.";
        return false;
    }

    // Insert the sourceId into the database when did not reached the limit
    // If limit is reached, we know that sourceId is already in the database
    auto insertResult = m_uniqueSources.insert(sourceId);
    if (insertResult.second) {
        dbgDebug(D_WAAP_LEARN) << "Inserted new source ID '" << sourceId << "' into the database.";
    } else {
        dbgTrace(D_WAAP_LEARN) << "source ID '" << sourceId << "' exists in database.";
    }
    return true;
}

void IndicatorsFiltersManager::registerKeywords(
    const string& key,
    Waap::Keywords::KeywordsSet& keywords,
    IWaf2Transaction* pWaapTransaction)
{
    // Check should register - if false, do not collect data
    if (!shouldRegister(key, keywords, pWaapTransaction)) {
        return;
    }

    const std::string& sourceId = pWaapTransaction->getSourceIdentifier();

    if (m_tuning.getDecision(pWaapTransaction->getLastScanParamName(), PARAM_NAME) == MALICIOUS ||
        m_tuning.getDecision(pWaapTransaction->getLastScanSample(), PARAM_VALUE) == MALICIOUS ||
        m_tuning.getDecision(pWaapTransaction->getUri(), URL) == MALICIOUS ||
        m_tuning.getDecision(sourceId, SOURCE) == MALICIOUS)
    {
        dbgDebug(D_WAAP_LEARN) << "Skipping registration due to tuning decision (malicious)";
        return;
    }

    // TODO: add configuration to choose central logging and return, else do legacy
    if(getProfileAgentSettingWithDefault<bool>(false, "agent.learning.centralLogging")) {
        dbgDebug(D_WAAP_LEARN) << "Central logging is enabled.";
        // Build unified entry
        UnifiedIndicatorsContainer::Entry entry;
        entry.key = key;
        entry.sourceId = pWaapTransaction->getSourceIdentifier();
        
        // Use the new getTrustedSource method for proper trusted source checking
        if (m_keywordsFreqFilter) {
            auto trustedSourceResult = m_keywordsFreqFilter->getTrustedSource(pWaapTransaction);
            entry.isTrusted = trustedSourceResult.ok();
            if (entry.isTrusted) {
                dbgDebug(D_WAAP_LEARN) << "Entry is from trusted source: " << trustedSourceResult.unpack();
            }
        } else {
            entry.isTrusted = false;
        }
        
        for (const auto &kw : keywords) {
            entry.indicators.push_back(kw);
        }

        // Add parameter types as TYPE indicators if applicable (skip url# keys)
        if (key.rfind("url#", 0) != 0) {
            string sample = pWaapTransaction->getLastScanSample();
            auto sampleTypes = m_pWaapAssetState->getSampleType(sample);
            entry.types.insert(entry.types.end(), sampleTypes.begin(), sampleTypes.end());
        }

        // Push to unified container
        m_unifiedIndicators->addEntry(entry);
        return;
    }
    dbgTrace(D_WAAP_LEARN) << "Central logging is disabled. Using legacy filters.";

    // Legacy behavior (optional): keep existing filters updates for backward compatibility
    if (!keywords.empty())
    {
        m_ignoreSources.log(sourceId, key, keywords);
    }

    m_keywordsFreqFilter->registerKeywords(key, keywords, pWaapTransaction);
    if (key.rfind("url#", 0) == 0)
    {
        return;
    }
    m_typeFilter->registerKeywords(key, keywords, pWaapTransaction);
    auto types = getParameterTypes(key);
    for (auto type : types)
    {
        if (type == "html_input")
        {
            m_keywordsFreqFilter->registerKeywords(type, keywords, pWaapTransaction);
        }
    }
}

bool IndicatorsFiltersManager::shouldFilterKeyword(const string &key, const string &keyword) const
{
    bool shouldFilter = false;
    if (m_keywordsFreqFilter != nullptr)
    {
        shouldFilter |= m_keywordsFreqFilter->shouldFilterKeyword(key, keyword);
    }
    if (m_typeFilter != nullptr)
    {
        shouldFilter |= m_typeFilter->shouldFilterKeyword(key, keyword);
        auto types = getParameterTypes(key);
        for (auto& type : types)
        {
            shouldFilter |= m_keywordsFreqFilter->shouldFilterKeyword(type, keyword);
        }
    }

    if (m_matchedOverrideKeywords.size() > 0 &&
            m_matchedOverrideKeywords.find(keyword) != m_matchedOverrideKeywords.end())
    {
        dbgTrace(D_WAAP_OVERRIDE) << "Filtering keyword '" << keyword << "' due to override";
        shouldFilter = true;
    }
    return shouldFilter;
}

void IndicatorsFiltersManager::serialize(ostream& stream)
{
    cereal::JSONOutputArchive archive(stream);

    archive(cereal::make_nvp("version", 1), cereal::make_nvp("trustedSrcParams", m_trustedSrcParams));
}

void IndicatorsFiltersManager::deserialize(istream& stream)
{
    cereal::JSONInputArchive archive(stream);

    size_t version = 0;

    try
    {
        archive(cereal::make_nvp("version", version));
    }
    catch (runtime_error & e) {
        archive.setNextName(nullptr);
        version = 0;
        dbgDebug(D_WAAP_LEARN) << "Can't load file version: " << e.what();
    }

    switch (version)
    {
    case 0:
        archive(cereal::make_nvp("m_trustedSrcParams", m_trustedSrcParams));
        break;
    case 1:
        archive(cereal::make_nvp("trustedSrcParams", m_trustedSrcParams));
        break;
    default:
        dbgWarning(D_WAAP_LEARN) << "unknown file format version: " << version;
        break;
    }
}

set<string> IndicatorsFiltersManager::getParameterTypes(const string& canonicParam) const
{
    return m_typeFilter->getParamTypes(canonicParam);
}

bool IndicatorsFiltersManager::loadPolicy(IWaapConfig* pConfig)
{
    bool shouldSave = false;
    if (pConfig != NULL)
    {
        m_trustedSrcParams = pConfig->get_TrustedSourcesPolicy();
        if (m_trustedSrcParams != nullptr)
        {
            shouldSave = m_keywordsFreqFilter->setTrustedSrcParameter(m_trustedSrcParams);
            shouldSave |= m_typeFilter->setTrustedSrcParameter(m_trustedSrcParams);
        }
        auto waapParams = pConfig->get_WaapParametersPolicy();
        if (waapParams != nullptr)
        {
            m_keywordsFreqFilter->loadParams(waapParams);
            m_typeFilter->loadParams(waapParams);
            m_ignoreSources.loadParams(waapParams);
        }
        if (shouldSave)
        {
            saveData();
        }
    }
    else
    {
        dbgWarning(D_WAAP_LEARN) << "Failed to get configuration";
    }

    return pConfig != NULL;
}

void IndicatorsFiltersManager::filterVerbose(const string &param,
    vector<string>& filteredKeywords,
    map<string, vector<string>>& filteredKeywordsVerbose)
{
    static string typeFilterName = "type indicators filter";
    static string keywordsFilterName = "keywords frequency indicators filter";
    filteredKeywordsVerbose[typeFilterName];
    filteredKeywordsVerbose[keywordsFilterName];
    auto types = getParameterTypes(param);
    for (auto keyword : filteredKeywords)
    {
        if (m_typeFilter->shouldFilterKeyword(param, keyword))
        {
            filteredKeywordsVerbose[typeFilterName].push_back(param + "#" + keyword);
        }
        if (m_keywordsFreqFilter->shouldFilterKeyword(param, keyword))
        {
            filteredKeywordsVerbose[keywordsFilterName].push_back(param + "#" + keyword);
            for (auto type : types)
            {
                if (m_keywordsFreqFilter->shouldFilterKeyword(type, keyword))
                {
                    filteredKeywordsVerbose[keywordsFilterName].push_back(param + "#" + type + "#" + keyword);
                }

            }
        }
    }
}

void IndicatorsFiltersManager::reset()
{
    m_typeFilter->reset();
    m_keywordsFreqFilter->reset();
}


string IndicatorsFiltersManager::extractUri(const string& referer, const IWaf2Transaction* pTransaction)
{
    string url;

    size_t pos = referer.find("://");
    if (pos == string::npos || (pos + 3) > referer.size())
    {
        url = referer;
    }
    else
    {
        url = referer.substr(pos + 3);
    }
    pos = url.find('/');
    if (pos == string::npos)
    {
        return url;
    }
    string host = url.substr(0, pos);
    if (host == pTransaction->getHdrContent("host"))
    {
        return url.substr(pos);
    }
    return url;
}

string IndicatorsFiltersManager::generateKey(const string& location,
    const string& param_name,
    const IWaf2Transaction* pTransaction)
{
    string key = location;
    static const string delim = "#";
    string param = normalize_param(param_name);

    if (location == "header" || location == "cookie" || location == "url_param")
    {
        key += delim + param;
    }
    else if (location == "referer_param")
    {
        key = "url_param" + delim + param;
    }
    else if (location == "body")
    {
        if (param == "")
        {
            key += delim + normalize_uri(pTransaction->getUriStr());
        }
        else
        {
            key += delim + param;
        }
    }
    else if (location == "url")
    {
        key += delim + normalize_uri(pTransaction->getUriStr());
    }
    else if (location == "referer")
    {
        string referer = pTransaction->getHdrContent("referer");
        string uri = extractUri(referer, pTransaction);
        key = "url" + delim + normalize_uri(uri);
    }
    else
    {
        key = normalize_uri(pTransaction->getUriStr()) + delim + param;
    }
    return key;
}

string IndicatorsFiltersManager::getLocationFromKey(const string& canonicKey, IWaf2Transaction* pTransaction)
{
    vector<string> known_locations = { "header", "cookie", "url", "body", "referer", "url_param" };
    string delim = "#";
    for (auto location : known_locations)
    {
        if (canonicKey.find(location + delim) == 0)
        {
            return location;
        }
    }
    return "";
}

void IndicatorsFiltersManager::filterKeywords(
    const string &key,
    Waap::Keywords::KeywordsSet& keywords,
    vector<string>& filteredKeywords)
{
    for (auto keyword = keywords.begin(); keyword != keywords.end(); )
    {
        if (shouldFilterKeyword(key, *keyword))
        {
            filteredKeywords.push_back(*keyword);
            keyword = keywords.erase(keyword);
        }
        else
        {
            keyword++;
        }
    }
}

void IndicatorsFiltersManager::pushSample(
    const string& key,
    const string& sample,
    IWaf2Transaction* pTransaction)
{
    // Check learning leader flag - if false, do not collect data
    if (!m_isLeading) {
        return;
    }

    if (key.rfind("url#", 0) == 0)
    {
        return;
    }
    m_typeFilter->registerKeywords(key, sample, pTransaction);
}

set<string> & IndicatorsFiltersManager::getMatchedOverrideKeywords(void)
{
    return m_matchedOverrideKeywords;
}

void IndicatorsFiltersManager::updateLearningLeaderFlag() {
    m_isLeading = getSettingWithDefault<bool>(true, "features", "learningLeader");
    dbgDebug(D_WAAP_LEARN) << "Updating learning leader flag from configuration: " << (m_isLeading ? "true" : "false");
}

void IndicatorsFiltersManager::updateSourcesLimit()
{
    int new_limit = getProfileAgentSettingWithDefault<int>(DEFAULT_SOURCES_LIMIT, "agent.learning.sourcesLimit");
    if (new_limit != m_sources_limit) {
        m_sources_limit = new_limit;
        m_uniqueSources.reserve(m_sources_limit);
    }
}

bool IndicatorsFiltersManager::postData()
{
    dbgDebug(D_WAAP_LEARN) << "Posting indicators data";
    // Example: post unified indicators data if present
    if (m_unifiedIndicators->getKeyCount() == 0) {
        dbgDebug(D_WAAP_LEARN) << "No unified indicators to post, skipping";
        return true; // Nothing to post
    }

    // Post unified indicators using REST client with C2S_PARAM
    UnifiedIndicatorsLogPost logPost(m_unifiedIndicators);
    string postUrl = getPostDataUrl();
    dbgTrace(D_WAAP_LEARN) << "Posting unified indicators to: " << postUrl;
    bool ok = sendNoReplyObjectWithRetry(logPost, HTTPMethod::PUT, postUrl);
    if (!ok) {
        dbgError(D_WAAP_LEARN) << "Failed to post unified indicators to: " << postUrl;
    }
    m_unifiedIndicators = make_shared<UnifiedIndicatorsContainer>();
    m_uniqueSources.clear();
    return ok;
}


void IndicatorsFiltersManager::pullData(const vector<string>& files)
{
    // Phase 2 : backup sync flow
    // Add logic for pulling data from a remote service
}

void IndicatorsFiltersManager::processData()
{
    // Phase 2 : backup sync flow
    // Add logic for processing pulled data
    // call filters with ptr to unified data to process data from m_unifiedIndicators
}

void IndicatorsFiltersManager::postProcessedData()
{
    // Add logic for posting processed data to a remote service
}

void IndicatorsFiltersManager::pullProcessedData(const vector<string>& files)
{
    // Add logic for pulling processed data from a remote service
}

// TODO: Phase 3 implement getRemoteStateFilePath to return the base dir

void IndicatorsFiltersManager::updateState(const vector<string>& files)
{
    // files is a list of single file base dir
    // TODO phase 3: call each filter to update internal states
}
