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

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <list>
#include <memory>
#include "FpMitigation.h"
#include "Waf2Util.h"
#include "picojson.h"
#include "i_mainloop.h"
#include "i_serialize.h"
#include <cereal/archives/json.hpp>
#include <cereal/types/unordered_map.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/vector.hpp>
#include "WaapDefines.h"

USE_DEBUG_FLAG(D_WAAP_SCORE_BUILDER);

struct ScoreBuilderData {
    std::string m_sourceIdentifier;
    std::string m_userAgent;
    std::string m_sample;
    double m_relativeReputation;
    PolicyCounterType m_fpClassification;
    std::vector<std::string> m_keywordsMatches;
    std::vector<std::string> m_keywordsCombinations;

    ScoreBuilderData();
    ScoreBuilderData(
        const std::string &sourceIdentifier,
        const std::string &userAgent,
        const std::string &sample,
        double relativeReputation,
        PolicyCounterType type,
        const std::vector<std::string> &keywordsMatches,
        const std::vector<std::string> &keywordsCombinations);
};
enum KeywordType {
    KEYWORD_TYPE_UNKNOWN,
    KEYWORD_TYPE_KEYWORD,
    KEYWORD_TYPE_COMBINATION,
    KEYWORD_TYPE_SPECIAL_COMBINATION
};

struct KeywordData {
    KeywordData() :
        truePositiveCtr(0), falsePositiveCtr(0), score(0.0), coef(0.0), new_score(0.0), type(KEYWORD_TYPE_UNKNOWN)
    {}

    unsigned int truePositiveCtr;
    unsigned int falsePositiveCtr;
    double score;
    double coef;
    double new_score;
    KeywordType type;
    std::vector<std::string> special_links;

    template <class Archive>
    void serialize(Archive& ar) {
        ar(cereal::make_nvp("false_positives", falsePositiveCtr),
            cereal::make_nvp("true_positives", truePositiveCtr),
            cereal::make_nvp("score", score),
            cereal::make_nvp("type", type));
        try {
            ar(cereal::make_nvp("coef", coef),
                cereal::make_nvp("new_score", new_score));
        } catch (const cereal::Exception &e) {
            ar.setNextName(nullptr);
            coef = 0;
            new_score = 0;
        }
        try {
            ar(cereal::make_nvp("special_links", special_links));
        } catch (const cereal::Exception &e) {
            ar.setNextName(nullptr);
        }
    }
};

struct KeywordsStats {
    KeywordsStats() : truePositiveCtr(0), falsePositiveCtr(0), linModelIntercept(0), linModelNNZCoef(0), isLinModel(0)
    {}

    template <class Archive>
    void serialize(Archive& ar) {
        ar(cereal::make_nvp("false_positives", falsePositiveCtr),
                cereal::make_nvp("true_positives", truePositiveCtr));
        try {
            ar(cereal::make_nvp("intercept", linModelIntercept),
                cereal::make_nvp("log_nnz_coef", linModelNNZCoef));
            isLinModel = true;
        } catch (const cereal::Exception &e) {
            ar.setNextName(nullptr);
            linModelIntercept = 0;
            linModelNNZCoef = 0;
            isLinModel = false;
        }
    }

    unsigned int truePositiveCtr;
    unsigned int falsePositiveCtr;
    double linModelIntercept;
    double linModelNNZCoef;
    bool isLinModel;
};

typedef std::unordered_set<std::string> keywords_set;

struct FalsePoisitiveStore {
    unsigned int count;
    std::unordered_map<std::string, keywords_set> ipItems;
    std::unordered_map<std::string, keywords_set> uaItems;

    FalsePoisitiveStore() : count(0), ipItems(), uaItems() {}
    void putFalsePositive(const std::string& ip, const std::string& userAgent, const std::string& keyword);
    bool hasIpItem(const std::string& ip) const;
    bool hasUaItem(const std::string& ua) const;
    void appendKeywordsSetsIntersectionToList(std::list<std::string>& keywordsList);
    void clear();
};

class I_WaapAssetState;

typedef std::unordered_map<std::string, KeywordData> KeywordDataMap;

struct KeywordsScorePool {
    KeywordDataMap m_keywordsDataMap;
    KeywordsStats m_stats;

    KeywordsScorePool();

    // LCOV_EXCL_START Reason: no test exist
    template <typename _A>
    KeywordsScorePool(_A &iarchive)
    {
        KeywordDataMap tmpKeyordsDataMap;
        iarchive(cereal::make_nvp("keyword_data", tmpKeyordsDataMap),
            cereal::make_nvp("keyword_stats", m_stats));

        // Decode keys (originally urlencoded in the source file)
        for (auto item : tmpKeyordsDataMap) {
            std::string key = item.first;
            key.erase(unquote_plus(key.begin(), key.end()), key.end());
            m_keywordsDataMap[key] = item.second;
        }
    }
    // LCOV_EXCL_STOP

    template <class Archive>
    void serialize(Archive& ar) {
        ar(
            cereal::make_nvp("keyword_data", m_keywordsDataMap),
            cereal::make_nvp("keyword_stats", m_stats)
        );
    }

    void mergeScores(const KeywordsScorePool& baseScores);
};

class ScoreBuilder {
public:
    ScoreBuilder(I_WaapAssetState* pWaapAssetState);
    ScoreBuilder(I_WaapAssetState* pWaapAssetState, ScoreBuilder& baseScores);
    ~ScoreBuilder();

    // Copying would alias m_serializedData through the reference member and
    // duplicate ownership of the pending rebuild routine (double stop()).
    ScoreBuilder(const ScoreBuilder &) = delete;
    ScoreBuilder &operator=(const ScoreBuilder &) = delete;

    void analyzeFalseTruePositive(ScoreBuilderData& data, const std::string &poolName, bool doBackup=true);

    bool isHtmlContent(std::string sample);

    void checkBadSourcesForLearning(double reputation, std::string& source, std::string& userAgent);
    void pumpKeywordScore(ScoreBuilderData& data, const std::string &poolName, bool doBackup=true);
    void calcScore(const std::string &poolName);

    void snap();
    double getSnapshotKeywordScore(
        const std::string &keyword,
        double defaultScore,
        const std::string &poolName
    ) const;
    double getSnapshotKeywordCoef(
        const std::string &keyword,
        double defaultCoef,
        const std::string &poolName
    ) const;
    KeywordType getSnapshotKeywordType(
        const std::string &keyword,
        const std::string &poolName
    ) const;
    // Returns by value: the result must not reference a snapshot that a later
    // rebuild swap can retire while the caller still holds it.
    std::vector<std::string> getSnapshotSpecialLinks(
        const std::string &keyword,
        const std::string &poolName
    ) const;

    KeywordsStats getSnapshotStats(const std::string &poolName) const;

    keywords_set getIpItemKeywordsSet(std::string ip);
    keywords_set getUaItemKeywordsSet(std::string userAgent);
    unsigned int getFpStoreCount();

    void restore();

    void mergeScores(const ScoreBuilder& baseScores);
protected:
    typedef std::map<std::string, std::vector<std::string>> KeywordSpecialLinksMap;

    // Consolidated snapshot entry -- replaces 3 separate maps (score, coef, type)
    // with a single map, eliminating duplicate string key storage.
    struct SnapshotEntry {
        double score = 0.0;
        double coef = 0.0;
        KeywordType type = KEYWORD_TYPE_UNKNOWN;
    };
    typedef std::map<std::string, SnapshotEntry> KeywordSnapshotMap;

    // Immutable snapshot of the live score pools, published by pointer swap
    // (double buffer). Readers copy the shared_ptr at entry; the single-threaded
    // cooperative mainloop makes plain assignment the atomic publish.
    struct SnapshotState {
        std::map<std::string, KeywordSnapshotMap> keywordsMap;
        std::map<std::string, KeywordSpecialLinksMap> specialLinksMap;
        std::map<std::string, KeywordsStats> statsMap;
    };

    struct SerializedData {
        template <class Archive>
        void serialize(Archive& ar) {
            size_t version = 0;
            try {
                ar(cereal::make_nvp("version", version));
            }
            catch (std::runtime_error & e) {
                ar.setNextName(nullptr);
                version = 0;
            }

            switch (version)
            {
                case 1: {
                    ar(cereal::make_nvp("scorePools", m_keywordsScorePools));
                    break;
                }
                case 0: {
                    m_keywordsScorePools[KEYWORDS_SCORE_POOL_BASE] = KeywordsScorePool(ar);
                    break;
                }
                default: {
                    break;
                }
            }
        }

        std::map<std::string, KeywordsScorePool> m_keywordsScorePools; // live data continuously updated during traffic
    };

    void pumpKeywordScorePerKeyword(ScoreBuilderData& data,
        const std::string& keyword,
        KeywordType keywordSource,
        KeywordsScorePool &keywordsScorePool);

    std::shared_ptr<const SnapshotState> buildSnapshot(I_MainLoop *yieldingMainLoop) const;
    void scheduleSnapshotRebuild();

    unsigned int m_scoreTrigger;
    FalsePoisitiveStore m_fpStore;
    SerializedData m_serializedData;
    std::map<std::string, KeywordsScorePool> &m_keywordsScorePools;
    std::shared_ptr<const SnapshotState> m_snapshot; // never null
    I_MainLoop::RoutineID m_snapRoutineId; // 0 == no rebuild pending
    unsigned int m_calcScoreGeneration; // bumped by calcScore(); a rebuild re-runs if it changed mid-build
    std::list<std::string> m_falsePositivesSetsIntersection;
    I_WaapAssetState* m_pWaapAssetState;
};
