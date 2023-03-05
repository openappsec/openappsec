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

#ifndef __WAF2_SIGS_H__02a5bdaa
#define __WAF2_SIGS_H__02a5bdaa

#include "Waf2Regex.h"
#include "Signatures.h"
#include "picojson.h"
#include "lru_cache_set.h"
#include "lru_cache_map.h"
#include <string>
#include <map>
#include <set>
#include <boost/noncopyable.hpp>
#include "ScoreBuilder.h"
#include "i_waap_asset_state.h"
#include "RateLimiting.h"
#include "SecurityHeadersPolicy.h"
#include "WaapDefines.h"
#include "IndicatorsFiltersManager.h"
#include "WaapKeywords.h"
#include "KeywordTypeValidator.h"
#include "ScanResult.h"
#include "WaapSampleValue.h"

enum space_stage {SPACE_SYNBOL, BR_SYMBOL, BN_SYMBOL, BRN_SEQUENCE, BNR_SEQUENCE, NO_SPACES};

class IWaf2Transaction;

class WaapAssetState : public boost::noncopyable, public I_WaapAssetState
{
private: //ugly but needed for build
    std::shared_ptr<Signatures> m_Signatures;
    std::string m_waapDataFileName;
    std::map<std::string, std::vector<std::string>> m_filtered_keywords_verbose;

    void checkRegex(const SampleValue &sample, const Regex & pattern, std::vector<std::string>& keyword_matches,
        Waap::Util::map_of_stringlists_t & found_patterns, bool longTextFound, bool binaryDataFound) const;

    void filterKeywordsDueToLongText(Waf2ScanResult &res) const;

public:
    // Load and compile signatures from file
    explicit WaapAssetState(std::shared_ptr<Signatures> signatures, const std::string& waapDataFileName,
        size_t cleanCacheCapacity = SIGS_APPLY_CLEAN_CACHE_CAPACITY,
        size_t suspiciousCacheCapacity = SIGS_APPLY_SUSPICIOUS_CACHE_CAPACITY,
        size_t sampleTypeCacheCapacity = SIGS_SAMPLE_TYPE_CACHE_CAPACITY,
        const std::string& assetId = "");
    explicit WaapAssetState(const std::shared_ptr<WaapAssetState>& pWaapAssetState,
        const std::string& waapDataFileName, const std::string& assetId);
    virtual ~WaapAssetState();

    std::shared_ptr<Signatures> getSignatures() const;
    void reset();

    const std::string m_assetId;

    ScoreBuilder scoreBuilder;
    std::shared_ptr<Waap::RateLimiting::State> m_rateLimitingState;
    std::shared_ptr<Waap::RateLimiting::State> m_errorLimitingState;
    std::shared_ptr<Waap::SecurityHeaders::State> m_securityHeadersState;
    std::shared_ptr<IndicatorsFiltersManager> m_filtersMngr;
    KeywordTypeValidator m_typeValidator;

    bool apply(const std::string &v, Waf2ScanResult &res, const std::string &scanStage, bool isBinaryData=false,
        const Maybe<std::string> splitType=genError("not splitted")) const;

    virtual void updateScores();
    virtual std::string getWaapDataFileName() const;
    virtual std::string getWaapDataDir() const;
    std::map<std::string, std::vector<std::string>>& getFilterVerbose();

    void updateFilterManagerPolicy(IWaapConfig* pConfig);
    virtual bool isKeywordOfType(const std::string& keyword, ParamType type) const;
    virtual bool isBinarySampleType(const std::string& sample) const;
    virtual bool isWBXMLSampleType(const std::string &sample) const;
    virtual std::set<std::string> getSampleType(const std::string& sample) const;
    void logIndicatorsInFilters(const std::string &param, Waap::Keywords::KeywordsSet& keywords,
        IWaf2Transaction* pTransaction);
    void logParamHit(Waf2ScanResult& res, IWaf2Transaction* pTransaction);
    void filterKeywords(const std::string &param, Waap::Keywords::KeywordsSet& keywords,
        std::vector<std::string>& filteredKeywords);
    void clearFilterVerbose();
    void filterVerbose(const std::string &param,
        std::vector<std::string>& filteredKeywords);
    void filterKeywordsByParameters(const std::string &parameter_name, Waap::Keywords::KeywordsSet &keywords_set);
    void removeKeywords(Waap::Keywords::KeywordsSet &keywords_set);
    void removeWBXMLKeywords(Waap::Keywords::KeywordsSet &keywords_set, std::vector<std::string> &filtered_keywords);

    void createRateLimitingState(const std::shared_ptr<Waap::RateLimiting::Policy> &rateLimitingPolicy);
    void createErrorLimitingState(const std::shared_ptr<Waap::RateLimiting::Policy> &errorLimitingPolicy);
    void createSecurityHeadersState(const std::shared_ptr<Waap::SecurityHeaders::Policy> &securityHeadersPolicy);

    void clearRateLimitingState();
    void clearErrorLimitingState();
    void clearSecurityHeadersState();


    std::shared_ptr<Waap::RateLimiting::State>& getRateLimitingState();
    std::shared_ptr<Waap::RateLimiting::State>& getErrorLimitingState();
    std::shared_ptr<Waap::SecurityHeaders::State>& getSecurityHeadersState();

    // Key for the caches includes input values passed to the WaapAssetState::apply()
    struct CacheKey {
        std::string line;
        std::string scanStage;
        bool isBinaryData;
        std::string splitType;
        CacheKey(
            const std::string &line,
            const std::string &scanStage,
            bool isBinaryData,
            const std::string &splitType)
                :
            line(line),
            scanStage(scanStage),
            isBinaryData(isBinaryData),
            splitType(splitType)
        {
        }

        // comparison operator should be implemented to use this struct as a key in an LRU cache.
        bool operator==(CacheKey const& other) const
        {
            return
                line == other.line &&
                scanStage == other.scanStage &&
                isBinaryData == other.isBinaryData &&
                splitType == other.splitType;
        }
    };

    // LRU caches are used to increase performance of apply() method for most frequent values
    mutable LruCacheSet<CacheKey> m_cleanValuesCache;
    mutable LruCacheMap<CacheKey, Waf2ScanResult> m_suspiciousValuesCache;
    mutable LruCacheSet<std::string> m_sampleTypeCache;
};

// Support efficient hashing for the CacheKey struct so it can participate in unordered (hashed) containers
inline std::size_t hash_value(WaapAssetState::CacheKey const &cacheKey)
{
    std::size_t hash = 0;
    boost::hash_combine(hash, cacheKey.line);
    boost::hash_combine(hash, cacheKey.scanStage);
    return hash;
}

void filterUnicode(std::string & text);
void trimSpaces(std::string & text);
void replaceUnicodeSequence(std::string & text, const char repl);
std::string unescape(const std::string & s);

// This if function is exposed to be tested by unit tests
void
checkRegex(
    std::string line,
    const Regex &pattern,
    std::vector<std::string>& keyword_matches,
    std::vector<std::string>& keyword_matches_raw,
    Waap::Util::map_of_stringlists_t &found_patterns,
    bool longTextFound);

#endif // __WAF2_SIGS_H__02a5bdaa
