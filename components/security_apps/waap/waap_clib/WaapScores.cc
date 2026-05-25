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
#include <cmath>
#include <algorithm>
#include <set>

#include "ScoreBuilder.h"
#include "WaapDefines.h"
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP_SCORE_BUILDER);

namespace Waap {
namespace Scores {

std::string getScorePoolNameByLocation(const std::string &location) {
    auto maybePoolName = getProfileAgentSetting<std::string>("agent.waap.scorePoolName");
    std::string res = KEYWORDS_SCORE_POOL_BASE;
    if (maybePoolName.ok()) {
        res = maybePoolName.unpack();
    }
    else if (location == "header") {
        res = KEYWORDS_SCORE_POOL_HEADERS;
    }
    return res;
}

std::string getOtherScorePoolName()
{
    auto maybePoolName = getProfileAgentSetting<std::string>("agent.waap.otherScorePoolName");
    if (maybePoolName.ok()) {
        return maybePoolName.unpack();
    }
    return KEYWORDS_SCORE_POOL_BASE;
}

ModelLoggingSettings getModelLoggingSettings()
{
    ModelLoggingSettings settings = {.logLevel = ModelLogLevel::DIFF,
                                    .logToS3 = false,
                                    .logToStream = true};
    auto maybeLogS3 = getProfileAgentSetting<bool>("agent.waap.modelLogToS3");
    if (maybeLogS3.ok()) {
        settings.logToS3 = maybeLogS3.unpack();
    }
    auto maybeLogKusto = getProfileAgentSetting<bool>("agent.waap.modelLogToStream");
    if (maybeLogKusto.ok()) {
        settings.logToStream = maybeLogKusto.unpack();
    }
    auto maybeLogLevel = getProfileAgentSetting<uint>("agent.waap.modelLogLevel");
    if (maybeLogLevel.ok() && (settings.logToS3 || settings.logToStream)) {
        settings.logLevel = static_cast<ModelLogLevel>(maybeLogLevel.unpack());
    }
    return settings;
}

void
addKeywordScore(
    const ScoreBuilder& scoreBuilder,
    const std::string &poolName,
    std::string keyword,
    double defaultScore,
    double defaultCoef,
    std::vector<double>& scoresArray,
    std::vector<double>& coefArray)
{
    double score = scoreBuilder.getSnapshotKeywordScore(keyword, defaultScore, poolName);
    double coef = scoreBuilder.getSnapshotKeywordCoef(keyword, defaultCoef, poolName);
    dbgDebug(D_WAAP_SCORE_BUILDER)
        << "Adding score: "
        << score
        << " coef: "
        << coef
        << " keyword: '"
        << keyword
        << "' pool: "
        << poolName;
    scoresArray.push_back(score);
    coefArray.push_back(coef);
}

// Calculate score of individual keywords
void
calcIndividualKeywords(
    const ScoreBuilder& scoreBuilder,
    const std::string &poolName,
    const std::vector<std::string>& keyword_matches,
    std::vector<double>& scoresArray,
    std::vector<double>& coefArray)
{
    std::vector<std::string> keywords = keyword_matches; // deep copy!! (PERFORMANCE WARNING!)
    std::sort(keywords.begin(), keywords.end());

    for (auto pKeyword = keywords.begin(); pKeyword != keywords.end(); ++pKeyword) {
        addKeywordScore(
            scoreBuilder, poolName, *pKeyword, DEFAULT_KEYWORD_SCORE, DEFAULT_KEYWORD_COEF, scoresArray, coefArray
        );
    }
}

// Helper: Calculate default score for a keyword combination
// Returns calculated average if poolName is base_scores, otherwise DEFAULT_COMBI_SCORE
static double calcDefaultCombinationScore(
    const ScoreBuilder& scoreBuilder,
    const std::string& poolName,
    const std::string& keyword1,
    const std::string& keyword2)
{
    if (poolName != KEYWORDS_SCORE_POOL_BASE) {
        return DEFAULT_COMBI_SCORE;
    }
    double score1 = scoreBuilder.getSnapshotKeywordScore(keyword1, DEFAULT_KEYWORD_SCORE, poolName);
    double score2 = scoreBuilder.getSnapshotKeywordScore(keyword2, DEFAULT_KEYWORD_SCORE, poolName);
    return std::min((score1 + score2) / 2.0, DEFAULT_COMBI_SCORE);
}

// Helper: Process special links for a keyword, checking only forward in keyword_matches
static void processSpecialLinksForKeyword(
    const ScoreBuilder& scoreBuilder,
    const std::string& poolName,
    const std::string& keyword,
    const std::vector<std::string>& keyword_matches,
    size_t startIndex,
    std::set<std::string>& processedCombinations,
    std::vector<double>& scoresArray,
    std::vector<double>& coefArray,
    std::vector<std::string>& keyword_combinations)
{
    const std::vector<std::string>& links = scoreBuilder.getSnapshotSpecialLinks(keyword, poolName);

    if (links.empty()) {
        return;
    }

    // Two-pointer technique: both keyword_matches and links are sorted
    // O(L + M) instead of O(L x M)
    size_t j = startIndex;
    for (const std::string& link : links) {
        // Skip keywords that are lexicographically before the current link
        while (j < keyword_matches.size() && keyword_matches[j] < link) {
            ++j;
        }

        // Check if we've exhausted keyword_matches or passed the link
        if (j >= keyword_matches.size() || keyword_matches[j] > link) {
            continue; // No match for this link
        }

        // Match found: keyword_matches[j] == link
        std::string combo_key = keyword + " " + keyword_matches[j];

        dbgTrace(D_WAAP_SCORE_BUILDER)
            << "  Special link match found: '"
            << combo_key
            << "'";

        // Skip if already processed
        if (processedCombinations.count(combo_key)) {
            ++j; // Move to next keyword for subsequent links
            continue;
        }

        processedCombinations.insert(combo_key);
        keyword_combinations.push_back(combo_key);

        // Apply model score for special non-adjacent combination
        double score = scoreBuilder.getSnapshotKeywordScore(combo_key, 0.0, poolName);
        double coef = scoreBuilder.getSnapshotKeywordCoef(combo_key, DEFAULT_COMBI_COEF, poolName);
        addKeywordScore(scoreBuilder, poolName, combo_key, score, coef, scoresArray, coefArray);

        ++j; // Move to next keyword for subsequent links
    }
}

// Calculate keyword combinations and their scores
void
calcCombinations(
    const ScoreBuilder& scoreBuilder,
    const std::string &poolName,
    const std::vector<std::string>& keyword_matches,
    std::vector<double>& scoresArray,
    std::vector<double>& coefArray,
    std::vector<std::string>& keyword_combinations)
{
    keyword_combinations.clear();

    static std::set<std::string> processedCombinations;
    processedCombinations.clear();

    // Process adjacent pairs AND special links for each keyword
    for (size_t i = 0; i < keyword_matches.size() - 1; ++i)
    {
        const std::string& current = keyword_matches[i];
        const std::string& next = keyword_matches[i + 1];
        std::string combo_key = current + " " + next;

        processedCombinations.insert(combo_key);
        keyword_combinations.push_back(combo_key);

        // Check if special combination (single type lookup)
        if (scoreBuilder.getSnapshotKeywordType(combo_key, poolName) == KEYWORD_TYPE_SPECIAL_COMBINATION) {
            // Adjacent special pair: Use default score (average of parts)
            double defaultScore = calcDefaultCombinationScore(scoreBuilder, poolName, current, next);

            dbgTrace(D_WAAP_SCORE_BUILDER)
                << "Applying default score for adjacent special pair: "
                << combo_key
                << " Score: "
                << defaultScore;

            scoresArray.push_back(defaultScore);
            coefArray.push_back(DEFAULT_COMBI_COEF);
        }
        else {
            // Standard adjacent pair: Look up in model
            double score = scoreBuilder.getSnapshotKeywordScore(combo_key, 0.0, poolName);
            double coef = scoreBuilder.getSnapshotKeywordCoef(combo_key, 0.0, poolName);

            if (score == 0.0 && coef == 0.0) {
                // Not in model: calculate default
                score = calcDefaultCombinationScore(scoreBuilder, poolName, current, next);
                coef = DEFAULT_COMBI_COEF;
            }

            addKeywordScore(scoreBuilder, poolName, combo_key, score, coef, scoresArray, coefArray);
        }

        // Process special links for current keyword (check forward from i+1)
        processSpecialLinksForKeyword(
            scoreBuilder,
            poolName,
            current,
            keyword_matches,
            i + 1,  // Start checking from next position forward
            processedCombinations,
            scoresArray,
            coefArray,
            keyword_combinations
        );
    }
}

double
calcArrayScore(std::vector<double>& scoreArray)
{
    // Calculate cumulative score from array of individual scores
    double score = 1.0f;
    for (auto pScore = scoreArray.begin(); pScore != scoreArray.end(); ++pScore) {
        double left = 10.0f - score;
        double divisor = (*pScore / 3.0f + 10.0f);  // note: divisor can't be empty because
                                                    // *pScore is always positive and there's a +10 offset
        score = 10.0f - left * 10.0f / divisor;
    }
    dbgDebug(D_WAAP_SCORE_BUILDER) << "calculated score: " << score;
    return score;
}

double
calcLogisticRegressionScore(std::vector<double> &coefArray, double intercept, double nnzCoef)
{
    // Sparse logistic regression model, with boolean feature values
    //Instead of performing a dot product of features*coefficients, we sum the coefficients of the non-zero features
    // An additional feature was added for the log of the number of non-zero features, as a regularization term
    double log_odds = intercept + nnzCoef * log(static_cast<double>(coefArray.size()) + 1);
    for (double &pCoef : coefArray) {
        log_odds += pCoef;
    }
    // Apply the expit function to the log-odds to obtain the probability,
    // and multiply by 10 to obtain a 'score' in the range [0, 10]
    double score = 1.0f / (1.0f + exp(-log_odds)) * 10.0f;
    dbgDebug(D_WAAP_SCORE_BUILDER) << "calculated score (log_odds): " << score << " (" << log_odds << ")";
    return score;
}

}
}
