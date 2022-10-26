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

#include "D2Main.h"
#include "FpMitigation.h"
#include "BehaviorAnalysis.h"
#include "WaapDefines.h"

D2Main::D2Main(const std::string& assetId) :
    m_assetId(assetId),
    m_fpMitigation(std::make_unique<FpMitigationScore>(BACKUP_DIRECTORY_PATH + assetId + std::string("/3.data")))
{
}

D2Main::~D2Main()
{
    m_fpMitigation.reset();
}

D2OutputData D2Main::analyzeData(const D2InputData& inputData)
{
    D2OutputData d2Output;
    BehaviorAnalysisInputData behaviorInput;
    PolicyCounterType fpType = UNKNOWN_TYPE;
    std::string userAgentSource = inputData.userAgent + inputData.sourceIdentifier;

    if (!inputData.keywordMatches.empty())
    {
        d2Output.fpMitigationScore = m_fpMitigation->calculateFpMitigationScore(inputData.uri, inputData.param);
    }

    behaviorInput.fp_mitigation_score = d2Output.fpMitigationScore;
    behaviorInput.keyword_matches = inputData.keywordMatches;
    behaviorInput.score = inputData.score;
    behaviorInput.site_id = inputData.siteId;
    behaviorInput.short_uri = inputData.uri;
    behaviorInput.uri = inputData.uri;
    behaviorInput.source_identifier = inputData.sourceIdentifier;
    behaviorInput.user_agent = inputData.userAgent;
    behaviorInput.location = inputData.location;

    ReputationData reputationInfo = m_BehaviorAnalyzer.analyze_behavior(behaviorInput);

    d2Output.relativeReputation = reputationInfo.relativeReputation;
    d2Output.absoluteReputation = reputationInfo.absoluteReputation;
    d2Output.reputationMean = m_BehaviorAnalyzer.getReputationMean();
    d2Output.variance = m_BehaviorAnalyzer.getVariance();

    if (!inputData.keywordMatches.empty())
    {
        fpType = m_fpMitigation->IdentifyFalseTruePositive(reputationInfo.relativeReputation, inputData.uri,
            inputData.param, userAgentSource);
        m_fpMitigation->learnFalsePositive(inputData.keywordMatches, fpType, inputData.uri, inputData.param);

        d2Output.finalScore = inputData.score * (10 - reputationInfo.relativeReputation * 0.8) /
            10 * d2Output.fpMitigationScore / 10;
        d2Output.finalScore = std::min(d2Output.finalScore * 2, 10.0);
    }

    d2Output.fpClassification = fpType;

    return d2Output;
}
