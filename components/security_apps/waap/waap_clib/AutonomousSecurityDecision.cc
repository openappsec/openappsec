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

#include "AutonomousSecurityDecision.h"

AutonomousSecurityDecision::AutonomousSecurityDecision(DecisionType type) :
    SingleDecision(type),
    m_relativeReputation(0.0f),
    m_fpMitigationScore(0.0f),
    m_finalScore(0.0f),
    m_threatLevel(NO_THREAT),
    m_overridesLog(false),
    m_relativeReputationMean(0.0),
    m_variance(0.0)
{}

AutonomousSecurityDecision::~AutonomousSecurityDecision()
{}

std::string AutonomousSecurityDecision::getTypeStr() const
{
    return "Autonomous Security";
}

void AutonomousSecurityDecision::setRelativeReputation(double relativeReputation)
{
    m_relativeReputation = relativeReputation;
}

void AutonomousSecurityDecision::setFpMitigationScore(double fpMitigationScore)
{
    m_fpMitigationScore = fpMitigationScore;
}

void AutonomousSecurityDecision::setFinalScore(double finalScore)
{
    m_finalScore = finalScore;
}

void AutonomousSecurityDecision::setThreatLevel(ThreatLevel threatLevel)
{
    m_threatLevel = threatLevel;
}

void AutonomousSecurityDecision::setOverridesLog(bool overridesLog)
{
    m_overridesLog = overridesLog;
}
void AutonomousSecurityDecision::setRelativeReputationMean(double relativeReputationMean)
{
    m_relativeReputationMean = relativeReputationMean;
}
void AutonomousSecurityDecision::setVariance(double variance)
{
    m_variance = variance;
}
double AutonomousSecurityDecision::getRelativeReputation() const
{
    return m_relativeReputation;
}
double AutonomousSecurityDecision::getFpMitigationScore() const
{
    return m_fpMitigationScore;
}
double AutonomousSecurityDecision::getFinalScore() const
{
    return m_finalScore;
}
ThreatLevel AutonomousSecurityDecision::getThreatLevel() const
{
    return m_threatLevel;
}
bool AutonomousSecurityDecision::getOverridesLog() const
{
    return m_overridesLog;
}
double AutonomousSecurityDecision::getRelativeReputationMean() const
{
    return m_relativeReputationMean;
}
double AutonomousSecurityDecision::getVariance() const
{
    return m_variance;
}
