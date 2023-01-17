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

#include "WaapScores.h"
#include <vector>
#include <string>
#include "ScoreBuilder.h"
#include "WaapDefines.h"
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP_SCORE_BUILDER);

namespace Waap {
namespace Scores {

std::string getScorePoolNameByLocation(const std::string &location) {
    std::string poolName = KEYWORDS_SCORE_POOL_BASE;
    if (location == "header") {
        poolName = KEYWORDS_SCORE_POOL_HEADERS;
    }
    return poolName;
}

void
addKeywordScore(
    const ScoreBuilder& scoreBuilder,
    const std::string &poolName,
    std::string keyword,
    double defaultScore,
    std::vector<double>& scoresArray)
{
    scoresArray.push_back(scoreBuilder.getSnapshotKeywordScore(keyword, defaultScore, poolName));
}

// Calculate score of individual keywords
void
calcIndividualKeywords(
    const ScoreBuilder& scoreBuilder,
    const std::string &poolName,
    const std::vector<std::string>& keyword_matches,
    std::vector<double>& scoresArray)
{
    std::vector<std::string> keywords = keyword_matches; // deep copy!! (PERFORMANCE WARNING!)
    std::sort(keywords.begin(), keywords.end());

    for (auto pKeyword = keywords.begin(); pKeyword != keywords.end(); ++pKeyword) {
        addKeywordScore(scoreBuilder, poolName, *pKeyword, 2.0f, scoresArray);
    }
}

// Calculate keyword combinations and their scores
void
calcCombinations(
    const ScoreBuilder& scoreBuilder,
    const std::string &poolName,
    const std::vector<std::string>& keyword_matches,
    std::vector<double>& scoresArray,
    std::vector<std::string>& keyword_combinations)
{
    keyword_combinations.clear();
    static const double max_combi_score = 1.0f;

    for (size_t i = 0; i < keyword_matches.size(); ++i) {
        std::vector<std::string> combinations;
        for (size_t j = i; j < std::min(i + 2, keyword_matches.size()); ++j) {
            combinations.push_back(keyword_matches[j]);
        }
        if (combinations.size() > 1) {
            // Must be sorted to build a string that exactly matches the keys (strings)
            // from signature_scores database.
            std::sort(combinations.begin(), combinations.end());
            std::string combination;
            double default_score = 0.0f;

            // note that std::set<> container output sorted data when iterated.
            for (auto it = combinations.begin(); it != combinations.end(); it++) {
                // add space between all items, except the first one
                if (it != combinations.begin()) {
                    combination += " ";
                }
                combination += *it;
                default_score += scoreBuilder.getSnapshotKeywordScore(*it, 0.0f, poolName);
            }
            // set default combination score to be the sum of its keywords, bounded by 1
            default_score = std::min(default_score, max_combi_score);
            addKeywordScore(scoreBuilder, poolName, combination, default_score, scoresArray);
            keyword_combinations.push_back(combination);
        }
    }
}

double
calcArrayScore(std::vector<double>& scoreArray)
{
    // Calculate cumulative score from array of individual scores
    double score = 1.0f;
    for (auto pScore = scoreArray.begin(); pScore != scoreArray.end(); ++pScore) {
        dbgTrace(D_WAAP_SCORE_BUILDER) << "scoreArr[]=" << *pScore;
        double left = 10.0f - score;
        double divisor = (*pScore / 3.0f + 10.0f);  // note: divisor can't be empty because
                                                    // *pScore is always positive and there's a +10 offset
        score = 10.0f - left * 10.0f / divisor;
    }
    dbgTrace(D_WAAP_SCORE_BUILDER) << "calculated score: " << score;
    return score;
}

}
}
