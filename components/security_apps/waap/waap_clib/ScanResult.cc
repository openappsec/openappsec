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

#include "ScanResult.h"

Waf2ScanResult::Waf2ScanResult()
:
keyword_matches(),
regex_matches(),
filtered_keywords(),
found_patterns(),
unescaped_line(),
param_name(),
location(),
score(0.0f),
scoreArray(),
keywordCombinations(),
attack_types(),
m_isAttackInParam(false)
{
}

void Waf2ScanResult::clear()
{
    keyword_matches.clear();
    regex_matches.clear();
    filtered_keywords.clear();
    found_patterns.clear();
    unescaped_line.clear();
    param_name.clear();
    location.clear();
    score = 0;
    scoreArray.clear();
    keywordCombinations.clear();
    attack_types.clear();
}

void Waf2ScanResult::mergeFrom(const Waf2ScanResult& other)
{
    location = other.location;
    param_name = other.param_name;

    Waap::Util::mergeFromVectorWithoutDuplicates(
        other.keyword_matches,
        keyword_matches
    );
    Waap::Util::mergeFromVectorWithoutDuplicates(
        other.regex_matches,
        regex_matches
    );
    Waap::Util::mergeFromMapOfVectorsWithoutDuplicates(
        other.found_patterns,
        found_patterns
    );
    if (unescaped_line.empty())
    {
        unescaped_line = other.unescaped_line;
    }

    unescaped_line = other.unescaped_line + "?" + unescaped_line;


    Waap::Util::mergeFromVectorWithoutDuplicates(
        other.scoreArray,
        scoreArray
    );

    attack_types.insert(other.attack_types.begin(), other.attack_types.end());
}
