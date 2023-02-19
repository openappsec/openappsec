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

IndicatorsFiltersManager::IndicatorsFiltersManager(const std::string& remotePath, const std::string &assetId,
    I_WaapAssetState* pWaapAssetState)
    :
    SerializeToFileBase(pWaapAssetState->getWaapDataDir() + "/6.data"),
    m_ignoreSources(pWaapAssetState->getWaapDataDir(), remotePath, assetId),
    m_tuning(remotePath),
    m_matchedOverrideKeywords()
{
    restore();
    m_keywordsFreqFilter = std::make_unique<KeywordIndicatorFilter>(
        pWaapAssetState->getWaapDataDir(),
        remotePath,
        assetId,
        &m_ignoreSources,
        &m_tuning);
    m_typeFilter = std::make_unique<TypeIndicatorFilter>(pWaapAssetState, remotePath, assetId, &m_tuning);
}

IndicatorsFiltersManager::~IndicatorsFiltersManager()
{
}

void IndicatorsFiltersManager::registerKeywords(const std::string& key,
    Waap::Keywords::KeywordsSet& keywords,
    IWaf2Transaction* pWaapTransaction)
{
    if (m_tuning.getDecision(pWaapTransaction->getLastScanParamName(), PARAM_NAME) == MALICIOUS ||
        m_tuning.getDecision(pWaapTransaction->getLastScanSample(), PARAM_VALUE) == MALICIOUS ||
        m_tuning.getDecision(pWaapTransaction->getUri(), URL) == MALICIOUS ||
        m_tuning.getDecision(pWaapTransaction->getSourceIdentifier(), SOURCE) == MALICIOUS)
    {
        return;
    }
    if (!keywords.empty())
    {
        m_ignoreSources.log(pWaapTransaction->getSourceIdentifier(), key, keywords);
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

bool IndicatorsFiltersManager::shouldFilterKeyword(const std::string &key, const std::string &keyword) const
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

void IndicatorsFiltersManager::serialize(std::ostream& stream)
{
    cereal::JSONOutputArchive archive(stream);

    archive(cereal::make_nvp("version", 1), cereal::make_nvp("trustedSrcParams", m_trustedSrcParams));
}

void IndicatorsFiltersManager::deserialize(std::istream& stream)
{
    cereal::JSONInputArchive archive(stream);

    size_t version = 0;

    try
    {
        archive(cereal::make_nvp("version", version));
    }
    catch (std::runtime_error & e) {
        archive.setNextName(nullptr);
        version = 0;
        dbgDebug(D_WAAP) << "Can't load file version: " << e.what();
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
        dbgWarning(D_WAAP) << "unknown file format version: " << version;
        break;
    }
}

std::set<std::string> IndicatorsFiltersManager::getParameterTypes(const std::string& canonicParam) const
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
        dbgWarning(D_WAAP) << "Failed to get configuration";
    }

    return pConfig != NULL;
}

void IndicatorsFiltersManager::filterVerbose(const std::string &param,
    std::vector<std::string>& filteredKeywords,
    std::map<std::string, std::vector<std::string>>& filteredKeywordsVerbose)
{
    static std::string typeFilterName = "type indicators filter";
    static std::string keywordsFilterName = "keywords frequency indicators filter";
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


std::string IndicatorsFiltersManager::extractUri(const std::string& referer, const IWaf2Transaction* pTransaction)
{
    std::string url;

    size_t pos = referer.find("://");
    if (pos == std::string::npos || (pos + 3) > referer.size())
    {
        url = referer;
    }
    else
    {
        url = referer.substr(pos + 3);
    }
    pos = url.find('/');
    if (pos == std::string::npos)
    {
        return url;
    }
    std::string host = url.substr(0, pos);
    if (host == pTransaction->getHdrContent("host"))
    {
        return url.substr(pos);
    }
    return url;
}

std::string IndicatorsFiltersManager::generateKey(const std::string& location,
    const std::string& param_name,
    const IWaf2Transaction* pTransaction)
{
    std::string key = location;
    static const std::string delim = "#";
    std::string param = normalize_param(param_name);

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
        std::string referer = pTransaction->getHdrContent("referer");
        std::string uri = extractUri(referer, pTransaction);
        key = "url" + delim + normalize_uri(uri);
    }
    else
    {
        key = normalize_uri(pTransaction->getUriStr()) + delim + param;
    }
    return key;
}

std::string IndicatorsFiltersManager::getLocationFromKey(const std::string& canonicKey, IWaf2Transaction* pTransaction)
{
    std::vector<std::string> known_locations = { "header", "cookie", "url", "body", "referer", "url_param" };
    std::string delim = "#";
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
    const std::string &key,
    Waap::Keywords::KeywordsSet& keywords,
    std::vector<std::string>& filteredKeywords)
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
    const std::string& key,
    const std::string& sample,
    IWaf2Transaction* pTransaction)
{
    if (key.rfind("url#", 0) == 0)
    {
        return;
    }
    m_typeFilter->registerKeywords(key, sample, pTransaction);
}

std::set<std::string> & IndicatorsFiltersManager::getMatchedOverrideKeywords(void)
{
    return m_matchedOverrideKeywords;
}
