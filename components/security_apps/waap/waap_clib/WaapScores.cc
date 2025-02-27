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
    dbgDebug(D_WAAP_SCORE_BUILDER) << "Adding score: " << score << " coef: " << coef
                                    << " keyword: '" << keyword << "' pool: " << poolName;
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
            default_score = std::min(default_score, DEFAULT_COMBI_SCORE);
            addKeywordScore(
                scoreBuilder, poolName, combination, default_score, DEFAULT_COMBI_COEF, scoresArray, coefArray
            );
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
    // Instead of performing a dot product of features*coefficients, we sum the coefficients of the non-zero features
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
