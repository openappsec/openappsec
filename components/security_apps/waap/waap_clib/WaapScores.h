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

#include <vector>
#include <string>
#include "ScoreBuilder.h"

namespace Waap {
namespace Scores {

std::string getScorePoolNameByLocation(const std::string &location);

void
addKeywordScore(
    const ScoreBuilder& scoreBuilder,
    const std::string &poolName,
    std::string keyword,
    double defaultScore,
    std::vector<double>& scoresArray);

// Calculate score of individual keywords
void
calcIndividualKeywords(
    const ScoreBuilder& scoreBuilder,
    const std::string &poolName,
    const std::vector<std::string>& keyword_matches,
    std::vector<double>& scoresArray);

// Calculate keyword combinations and their scores
void
calcCombinations(
    const ScoreBuilder& scoreBuilder,
    const std::string &poolName,
    const std::vector<std::string>& keyword_matches,
    std::vector<double>& scoresArray,
    std::vector<std::string>& keyword_combinations);

double calcArrayScore(std::vector<double>& scoreArray);

}
}
