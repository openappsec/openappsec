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

bool checkUrlEncoded(const char *buf, size_t len);

// Process value (buffer) and calculate some statistics/insights over it, for use in later processing.
// The insights are computed in te same for loop for performance reasons.
struct ValueStatsAnalyzer
{
    ValueStatsAnalyzer(const std::string &cur_val);
    bool hasCharSlash;
    bool hasCharColon;
    bool hasCharAmpersand;
    bool hasCharEqual;
    bool hasTwoCharsEqual;
    bool hasCharSemicolon;
    bool hasCharPipe;
    unsigned int longestZerosSeq[2]; // longest zeros sequence. counted over even (index 0) and odd (index 1) offsets
    bool isUTF16;
    bool canSplitSemicolon;
    bool canSplitPipe;
    bool hasSpace;
    bool isUrlEncoded;
    bool hasCharLess;
    bool hasDoubleQuote;
    std::string textual;
};


