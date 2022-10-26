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

#ifndef __SCAN_RESULT_H__
#define __SCAN_RESULT_H__

#include "Waf2Util.h"
#include <string>
#include <vector>
#include <set>


struct Waf2ScanResult {
    std::vector<std::string> keyword_matches;
    std::vector<std::string> regex_matches;
    std::vector<std::string> filtered_keywords;
    Waap::Util::map_of_stringlists_t found_patterns;
    std::string unescaped_line;
    std::string param_name;
    std::string location;
    double score;
    std::vector<double> scoreArray;
    std::vector<std::string> keywordCombinations;
    std::set<std::string> attack_types;
    bool m_isAttackInParam;
    void clear(); // clear Waf2ScanResult
    Waf2ScanResult();
    void mergeFrom(const Waf2ScanResult& other);
};

#endif // __SCAN_RESULT_H__
