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

#include "ScoreBuilder.h"
#include "Waf2Regex.h"
#include <iostream>
#include <algorithm>
#include <math.h>
#include "WaapAssetState.h"
#include <cereal/types/unordered_map.hpp>
#include <cereal/archives/json.hpp>
#include <cereal/types/memory.hpp>
#include <sstream>
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP_SCORE_BUILDER);

#define GENERATE_FALSE_POSITIVES_LIST_THRESHOLD 100
#define SCORE_CALCULATION_THRESHOLD 5000

using namespace std::chrono;

ScoreBuilderData::ScoreBuilderData() :
    m_sourceIdentifier(),
    m_userAgent(),
    m_sample(),
    m_relativeReputation(0.0),
    m_fpClassification(UNKNOWN_TYPE)
{}

ScoreBuilderData::ScoreBuilderData(
    const std::string &sourceIdentifier,
    const std::string &userAgent,
    const std::string &sample,
    double relativeReputation,
    PolicyCounterType type,
    const std::vector<std::string> &keywordsMatches,
    const std::vector<std::string> &keywordsCombinations)
    :
    m_sourceIdentifier(sourceIdentifier),
    m_userAgent(userAgent),
    m_sample(sample),
    m_relativeReputation(relativeReputation),
    m_fpClassification(type),
    m_keywordsMatches(keywordsMatches),
    m_keywordsCombinations(keywordsCombinations)
{}

KeywordsScorePool::KeywordsScorePool()
:
m_keywordsDataMap(),
m_stats()
{
}

void KeywordsScorePool::mergeScores(const KeywordsScorePool& baseScores)
{
    // find all keywords that exist in base but not in this
    std::vector<std::string> removedElements;
    std::vector<std::string>::iterator removedElementsIt;
    for (KeywordDataMap::const_iterator it = m_keywordsDataMap.begin();
        it != m_keywordsDataMap.end(); ++it)
    {
        // key not found in base array
        if (baseScores.m_keywordsDataMap.find(it->first) == baseScores.m_keywordsDataMap.end())
        {
            removedElements.push_back(it->first);
        }
    }

    // removing elements that were deleted
    for (removedElementsIt = removedElements.begin();
        removedElementsIt != removedElements.end();
        ++removedElementsIt)
    {
        m_keywordsDataMap.erase(*removedElementsIt);
    }

    // learning new scores
    for (KeywordDataMap::const_iterator it = baseScores.m_keywordsDataMap.begin();
        it != baseScores.m_keywordsDataMap.end(); ++it)
    {
        if (m_keywordsDataMap.find(it->first) == m_keywordsDataMap.end())
        {
            m_keywordsDataMap[it->first] = it->second;
        }
    }
}


ScoreBuilder::ScoreBuilder(I_WaapAssetState* pWaapAssetState) :
    m_scoreTrigger(0),
    m_fpStore(),
    m_serializedData(),
    m_keywordsScorePools(m_serializedData.m_keywordsScorePools),
    m_falsePositivesSetsIntersection(),
    m_pWaapAssetState(pWaapAssetState)
{
    restore();
}

ScoreBuilder::ScoreBuilder(I_WaapAssetState* pWaapAssetState, ScoreBuilder& baseScores) :
    m_scoreTrigger(0),
    m_fpStore(),
    m_serializedData(),
    m_keywordsScorePools(m_serializedData.m_keywordsScorePools),
    m_falsePositivesSetsIntersection(),
    m_pWaapAssetState(pWaapAssetState)
{
    restore();

    // merge
    mergeScores(baseScores);
}

void ScoreBuilder::restore()
{
    const std::string filePath = this->m_pWaapAssetState->getWaapDataFileName();

    dbgTrace(D_WAAP_SCORE_BUILDER) << "loadFromFile() file: " << filePath;
    std::fstream filestream;

    filestream.open(filePath, std::fstream::in);

    if (filestream.is_open() == false) {
        dbgTrace(D_WAAP_SCORE_BUILDER) << "failed to open file: " << filePath << " Error: " << errno;
        return;
    }

    dbgTrace(D_WAAP_SCORE_BUILDER) << "loading from file: " << filePath;

    int length;
    filestream.seekg(0, std::ios::end);    // go to the end
    length = filestream.tellg();           // report location (this is the length)
    dbgTrace(D_WAAP_SCORE_BUILDER) << "file length: " << length;
    assert(length >= 0); // length -1 really happens if filePath is a directory (!)
    char* buffer = new char[length];       // allocate memory for a buffer of appropriate dimension
    filestream.seekg(0, std::ios::beg);    // go back to the beginning
    if (!filestream.read(buffer, length))  // read the whole file into the buffer
    {
        filestream.close();
        delete[] buffer;
        dbgWarning(D_WAAP_SCORE_BUILDER) << "Failed to read file, file: " << filePath;
        return;
    }
    filestream.close();


    std::stringstream ss(std::string(buffer, length));
    delete[] buffer;

    try
    {
        cereal::JSONInputArchive iarchive(ss);
        iarchive(
            cereal::make_nvp("waap_scores", m_serializedData)
        );
    }
    catch (std::runtime_error & e) {
        dbgWarning(D_WAAP_SCORE_BUILDER) << "failed to deserialize file: " << filePath << ", error: " <<
            e.what();
    }
}

void ScoreBuilder::analyzeFalseTruePositive(ScoreBuilderData& data, const std::string &poolName, bool doBackup)
{
    if (data.m_fpClassification == UNKNOWN_TYPE)
    {
        dbgTrace(D_WAAP_SCORE_BUILDER) <<
            "analyzeFalseTruePositive(): Got UNKNOWN_TYPE as false positive classification "
            ", will not pump keywords score";
        return;
    }
    dbgTrace(D_WAAP_SCORE_BUILDER) << "ScoreBuilder::analyzeFalseTruePositive: pumping score pool=" << poolName;
    pumpKeywordScore(data, poolName, doBackup);
}

bool ScoreBuilder::isHtmlContent(std::string sample)
{
    // count closing html elements
    unsigned int closingHtmlElem = 0;
    std::string::size_type pos = 0;
    std::string htmlClosingElementHint = "</";

    while ((pos = sample.find(htmlClosingElementHint, pos)) != std::string::npos) {
        ++closingHtmlElem;
        pos += htmlClosingElementHint.length();
    }

    if (closingHtmlElem > 3)
    {
        return true;
    }

    unsigned int openingHtmlElem = 0;
    bool regexError = false;
    std::string reName = "html opening element regex";
    Regex htmlOpenElementRe("<html|<p|<div|<img|<ul|<li|<body|<a", regexError, reName);
    std::vector<RegexMatch> matches;

    if (sample.length() <= 30)
    {
        return false;
    }

    openingHtmlElem = htmlOpenElementRe.findAllMatches(sample, matches);

    if (openingHtmlElem > 5)
    {
        return true;
    }
    return false;
}

void ScoreBuilder::checkBadSourcesForLearning(double reputation, std::string& source, std::string& userAgent)
{
    if (m_fpStore.count == 0)
    {
        return;
    }
    m_fpStore.count++;

    if (reputation < 2.0)
    {
        if (m_fpStore.hasUaItem(userAgent))
        {
            m_fpStore.uaItems.erase(userAgent);
        }
        if (m_fpStore.hasIpItem(source))
        {
            m_fpStore.ipItems.erase(source);
        }
    }

    if (m_fpStore.count >= GENERATE_FALSE_POSITIVES_LIST_THRESHOLD)
    {
        m_fpStore.appendKeywordsSetsIntersectionToList(m_falsePositivesSetsIntersection);
        m_fpStore.clear();
    }
}

void ScoreBuilder::pumpKeywordScore(ScoreBuilderData& data, const std::string &poolName, bool doBackup)
{
    std::map<std::string, KeywordsScorePool>::iterator poolIt = m_keywordsScorePools.find(poolName);

    if (poolIt == m_keywordsScorePools.end()) {
        dbgDebug(D_WAAP_SCORE_BUILDER) << "pumpKeywordScore() is called with unknown poolName='" << poolName <<
            "'. Creating the pool.";
        m_keywordsScorePools[poolName] = KeywordsScorePool();
    }

    poolIt = m_keywordsScorePools.find(poolName);
    if (poolIt == m_keywordsScorePools.end()) {
        dbgWarning(D_WAAP_SCORE_BUILDER) << "pumpKeywordScore() failed to create pool '" << poolName << "'";
        return;
    }

    KeywordsScorePool &keywordsScorePool = poolIt->second;

    if (isHtmlContent(data.m_sample))
    {
        dbgTrace(D_WAAP_SCORE_BUILDER) << "pumpKeywordScore: isHtmlContent -> do not process";
        return;
    }
    for (const std::string &keyword : data.m_keywordsMatches) {
        pumpKeywordScorePerKeyword(data, keyword, KEYWORD_TYPE_KEYWORD, keywordsScorePool);
    }

    for (const std::string &keyword : data.m_keywordsCombinations) {
        pumpKeywordScorePerKeyword(data, keyword, KEYWORD_TYPE_COMBINATION, keywordsScorePool);
    }

    if (doBackup && m_scoreTrigger >= SCORE_CALCULATION_THRESHOLD)
    {
        calcScore(poolName);
        if (m_pWaapAssetState != NULL)
        {
            m_pWaapAssetState->updateScores();
        }
    }
}

void ScoreBuilder::calcScore(const std::string &poolName)
{
    std::map<std::string, KeywordsScorePool>::iterator poolIt = m_keywordsScorePools.find(poolName);

    if (poolIt == m_keywordsScorePools.end()) {
        dbgDebug(D_WAAP_SCORE_BUILDER) << "calcScore() is called with unknown poolName='" << poolName <<
            "'. Creating the pool.";
        m_keywordsScorePools[poolName] = KeywordsScorePool();
    }

    poolIt = m_keywordsScorePools.find(poolName);
    if (poolIt == m_keywordsScorePools.end()) {
        dbgWarning(D_WAAP_SCORE_BUILDER) << "calcScore() failed to create pool '" << poolName << "'";
        return;
    }

    KeywordsScorePool &keywordsScorePool = poolIt->second;
    KeywordDataMap &keywordsDataMap = keywordsScorePool.m_keywordsDataMap;
    KeywordsStats &keywordsStats = keywordsScorePool.m_stats;

    m_scoreTrigger = 0;

    for (auto fpKeyword : m_falsePositivesSetsIntersection)
    {
        if (keywordsDataMap.find(fpKeyword) == keywordsScorePool.m_keywordsDataMap.end())
        {
            keywordsDataMap[fpKeyword];
        }

        keywordsDataMap[fpKeyword].falsePositiveCtr++;
        keywordsStats.falsePositiveCtr++;
    }

    m_falsePositivesSetsIntersection.clear();

    KeywordDataMap newKeywordsDataMap;

    double tpAverageLog = log(keywordsStats.truePositiveCtr / std::max(keywordsDataMap.size(), (size_t)1) + 101);
    for (auto keyword : keywordsDataMap)
    {
        double tpLog = log(keyword.second.truePositiveCtr + 1);
        double tpScore = tpLog / (tpLog + tpAverageLog / 4 + 1); // range [0,1)
        int fpAvg = 1;
        keyword.second.score = 10 * tpScore * (fpAvg + 1) / (fpAvg + (keyword.second.falsePositiveCtr * 5) + 2);

        if (keyword.second.score > 1 ||
            keyword.second.falsePositiveCtr < 10 ||
            keyword.second.type == KEYWORD_TYPE_KEYWORD)
        {
            newKeywordsDataMap[keyword.first] = keyword.second;
        }
    }
    keywordsDataMap = newKeywordsDataMap;
}

void ScoreBuilder::snap()
{
    // Copy data from all mutable score pools to "snapshot" keyword->scores map
    for (const auto &pool : m_keywordsScorePools) {
        const std::string &poolName = pool.first;
        const KeywordsScorePool& keywordScorePool = pool.second;
        m_snapshotKwScoreMap[poolName];

        for (const auto &kwData : keywordScorePool.m_keywordsDataMap)
        {
            const std::string &kwName = kwData.first;
            double kwScore = kwData.second.score;
            m_snapshotKwScoreMap[poolName][kwName] = kwScore;
        }
    }
}

double ScoreBuilder::getSnapshotKeywordScore(const std::string &keyword, double defaultScore,
    const std::string &poolName) const
{
    std::map<std::string, KeywordScoreMap>::const_iterator poolIt = m_snapshotKwScoreMap.find(poolName);
    if (poolIt == m_snapshotKwScoreMap.end()) {
        dbgTrace(D_WAAP_SCORE_BUILDER) << "pool " << poolName << " does not exist. Getting score from base pool";
        poolIt = m_snapshotKwScoreMap.find(KEYWORDS_SCORE_POOL_BASE);
    }

    if (poolIt == m_snapshotKwScoreMap.end()) {
        dbgDebug(D_WAAP_SCORE_BUILDER) <<
            "base pool does not exist! This is probably a bug. Returning default score " << defaultScore;
        return defaultScore;
    }

    const KeywordScoreMap &kwScoreMap = poolIt->second;

    KeywordScoreMap::const_iterator kwScoreFound = kwScoreMap.find(keyword);
    if (kwScoreFound == kwScoreMap.end()) {
        dbgTrace(D_WAAP_SCORE_BUILDER) << "keywordScore:'" << keyword << "': " << defaultScore <<
            " (default, keyword not found in pool '" << poolName << "')";
        return defaultScore;
    }

    dbgTrace(D_WAAP_SCORE_BUILDER) << "keywordScore:'" << keyword << "': " << kwScoreFound->second << " (pool '" <<
        poolName << "')";
    return kwScoreFound->second;
}

keywords_set ScoreBuilder::getIpItemKeywordsSet(std::string ip)
{
    return m_fpStore.ipItems[ip];
}

keywords_set ScoreBuilder::getUaItemKeywordsSet(std::string userAgent)
{
    return m_fpStore.uaItems[userAgent];
}

unsigned int ScoreBuilder::getFpStoreCount()
{
    return m_fpStore.count;
}

void ScoreBuilder::mergeScores(const ScoreBuilder& baseScores)
{
    for (const auto &pool : baseScores.m_keywordsScorePools) {
        const std::string &poolName = pool.first;
        if (m_keywordsScorePools.find(poolName) == m_keywordsScorePools.end()) {
            m_keywordsScorePools[poolName];
        }
        const KeywordsScorePool &baseKeywordsScorePool = pool.second;
        m_keywordsScorePools[poolName].mergeScores(baseKeywordsScorePool);
    }
}

void ScoreBuilder::pumpKeywordScorePerKeyword(ScoreBuilderData& data, const std::string& keyword,
    KeywordType keywordSource, KeywordsScorePool &keywordsScorePool)
{
    m_scoreTrigger++;
    if (data.m_fpClassification == UNKNOWN_TYPE) {
        dbgTrace(D_WAAP_SCORE_BUILDER) <<
            "pumpKeywordScorePerKeyword(): Got UNKNOWN_TYPE as false positive classifiaction "
            ", will not pump keywords score";
        return;
    }

    if (keywordsScorePool.m_keywordsDataMap.find(keyword) == keywordsScorePool.m_keywordsDataMap.end())
    {
        keywordsScorePool.m_keywordsDataMap[keyword];
    }
    KeywordData& keyData = keywordsScorePool.m_keywordsDataMap[keyword];
    keyData.type = keywordSource;

    if (data.m_fpClassification == TRUE_POSITIVE  && keyData.score < 8)
    {
        dbgTrace(D_WAAP_SCORE_BUILDER) <<
            "pumpKeywordScorePerKeyword(): fpClassification = TRUE_POSITIVE for keyword: " << keyword;
        keyData.truePositiveCtr++;
        keywordsScorePool.m_stats.truePositiveCtr++;
    }
    else if (data.m_fpClassification == FALSE_POSITIVE  && (keyData.score > 0.1 || keyData.truePositiveCtr < 10))
    {
        dbgTrace(D_WAAP_SCORE_BUILDER) <<
            "pumpKeywordScorePerKeyword(): fpClassification = FALSE_POSITIVE for keyword: " << keyword;
        m_fpStore.putFalsePositive(data.m_sourceIdentifier, data.m_userAgent, keyword);
    }

}

void FalsePoisitiveStore::putFalsePositive(const std::string& ip, const std::string& userAgent,
    const std::string& keyword)
{
    count = 1;
    ipItems[ip].insert(keyword);
    uaItems[userAgent].insert(keyword);
}

bool FalsePoisitiveStore::hasIpItem(const std::string& ip) const
{
    return ipItems.find(ip) != ipItems.end();
}

bool FalsePoisitiveStore::hasUaItem(const std::string& ua) const
{
    return uaItems.find(ua) != uaItems.end();
}

void FalsePoisitiveStore::appendKeywordsSetsIntersectionToList(std::list<std::string>& keywordsList)
{
    std::list<std::string> ipKeywords;
    std::unordered_set<std::string> uaKeywords;

    for (auto ip : ipItems) {
        for (auto keyword : ip.second)
        {
            ipKeywords.push_back(keyword);
        }
    }

    for (auto ua : uaItems) {
        for (auto keyword : ua.second)
        {
            uaKeywords.insert(keyword);
        }
    }

    for (auto keyword : ipKeywords)
    {
        if (uaKeywords.find(keyword) != uaKeywords.end())
        {
            keywordsList.push_back(keyword);
        }
    }
}

void FalsePoisitiveStore::clear()
{
    count = 0;
    ipItems.clear();
    uaItems.clear();
}
