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

#include "WaapKeywords.h"

namespace Waap {
namespace Keywords {

void
computeKeywordsSet(KeywordsSet &keywordsSet, const std::vector<std::string> &keyword_matches,
    const Waap::Util::map_of_stringlists_t &found_patterns)
{
    // Add all detected keyword_matches
    keywordsSet.insert(keyword_matches.begin(), keyword_matches.end());

    for (auto it = found_patterns.begin(); it != found_patterns.end(); ++it) {
        const std::string& key = it->first;
        const std::vector<std::string>& keywordsList = it->second;
        bool foundPatternNotInMatches = false;

        for (auto pKeyword = keywordsList.begin(); pKeyword != keywordsList.end(); ++pKeyword) {
            if (std::find(keyword_matches.begin(), keyword_matches.end(), *pKeyword) != keyword_matches.end()) {
                foundPatternNotInMatches = true;
            }
        }

        // Only add keys from found_patterns for which there are no values in keyword_matches
        // The reason is to avoid adding both value and its related key to the same mix, which would
        // unjustfully pump up the score for the keywordsSet.
        if (!foundPatternNotInMatches) {
            keywordsSet.insert(key);
        }
    }
}

}
}
