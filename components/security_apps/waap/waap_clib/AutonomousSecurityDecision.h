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

#ifndef __AUTONOMOUS_SECURITY_DECISION_H__
#define __AUTONOMOUS_SECURITY_DECISION_H__

#include "SingleDecision.h"
#include "DecisionType.h"
#include "WaapEnums.h"
#include <string>

class AutonomousSecurityDecision: public SingleDecision
{
public:
    explicit AutonomousSecurityDecision(DecisionType type);
    virtual ~AutonomousSecurityDecision();

    std::string getTypeStr() const override;
    void setRelativeReputation(double relativeReputation);
    void setFpMitigationScore(double fpMitigationScore);
    void setFinalScore(double finalScore);
    void setThreatLevel(ThreatLevel threatLevel);
    void setOverridesLog(bool overridesLog);
    void setRelativeReputationMean(double relativeReputationMean);
    void setVariance(double variance);
    double getRelativeReputation() const;
    double getFpMitigationScore() const;
    double getFinalScore() const;
    ThreatLevel getThreatLevel() const;
    bool getOverridesLog() const;
    double getRelativeReputationMean() const;
    double getVariance() const;

private:
    double m_relativeReputation;
    double m_fpMitigationScore;
    double m_finalScore;
    ThreatLevel m_threatLevel;
    bool m_overridesLog;
    double m_relativeReputationMean;
    double m_variance;
};
#endif
