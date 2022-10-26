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
#include <vector>
#include <functional>
#include "FpMitigation.h"
#include "BehaviorAnalysis.h"

struct D2InputData {
    std::string siteId;
    std::string sourceIdentifier;
    std::string userAgent;
    std::string uri;
    std::string param;
    std::vector<std::string> keywordMatches;
    double score;
    std::string location;
};

struct D2OutputData {
    double finalScore;
    double absoluteReputation;
    double relativeReputation;
    double fpMitigationScore;
    PolicyCounterType fpClassification;
    double reputationMean;
    double variance;

    D2OutputData() : finalScore(0.0),
        absoluteReputation(0.0),
        relativeReputation(0.0),
        fpMitigationScore(0.0),
        fpClassification(UNKNOWN_TYPE),
        reputationMean(0.0),
        variance(0.0)
    {
    }
};

class D2Main {
public:
    D2Main(const std::string& assetId);
    virtual ~D2Main();
    virtual D2OutputData analyzeData(const D2InputData& inputData);

private:
    std::string m_assetId;
    std::unique_ptr<FpMitigationScore> m_fpMitigation;
    BehaviorAnalyzer m_BehaviorAnalyzer;
};

bool operator==(const D2OutputData& lhs, const D2OutputData& rhs);
