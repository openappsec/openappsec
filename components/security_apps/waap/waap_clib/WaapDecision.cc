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

#include "WaapDecision.h"
#include "OpenRedirectDecision.h"

#include "debug.h"
#include <algorithm>
#include <type_traits>

USE_DEBUG_FLAG(D_WAAP);

WaapDecision::WaapDecision() :
    m_json(""),
    m_decisionFactory()
{
}

std::shared_ptr<SingleDecision>
WaapDecision::getDecision(DecisionType type) const
{
    return m_decisionFactory.getDecision(type);
}

void
WaapDecision::orderDecisions()
{
    const DecisionsArr& decisions = m_decisionFactory.getDecisions();
    dbgTrace(D_WAAP) << "Original: " << decisions;
    std::copy_if(decisions.begin(),
                decisions.end(),
                std::back_inserter(m_ordered_decisions),
                [](const std::shared_ptr<SingleDecision>& decision) {
                    return decision && (decision->shouldBlock() || decision->shouldLog());
                });
    if (!m_ordered_decisions.empty()) {
        dbgTrace(D_WAAP) << "Reduced: " << m_ordered_decisions;
        m_ordered_decisions.sort(sortDecisions);
        dbgTrace(D_WAAP) << "Sorted: " << m_ordered_decisions;
    }

    setIteratorToFirstDecisionToLog();
}

void WaapDecision::setIteratorToFirstDecisionToLog()
{
    m_first_decision_to_log =
        std::find_if(
            m_ordered_decisions.begin(),
            m_ordered_decisions.end(),
            [](const std::shared_ptr<SingleDecision>& decision)
    {
        return decision && decision->shouldLog();
    });
}

bool
WaapDecision::sortDecisions(const std::shared_ptr<SingleDecision>& lhs, const std::shared_ptr<SingleDecision>& rhs)
{
    if (lhs->shouldBlock() && !rhs->shouldBlock()) {
        return true;
    }
    else if (!lhs->shouldBlock() && rhs->shouldBlock()) {
        return false;
    }
    else if (lhs->shouldLog() && !rhs->shouldLog()) {
        return true;
    }
    else if (!lhs->shouldLog() && rhs->shouldLog()) {
        return false;
    }
    else if (lhs->getType() < rhs->getType()) {
        return true;
    }
    return false;
}

std::ostream& operator<<(std::ostream& os, const DecisionsArr& decisions)
{
    os << "Decision(block, log): ";
    for (auto decision : decisions)
    {
        os << decision->getTypeStr() << "(" << decision->shouldBlock() << ", " <<
            decision->shouldLog() << ")  ";
    }
    return os;
}

std::ostream& operator<<(std::ostream& os, const std::list<std::shared_ptr<SingleDecision>>& decisions)
{
    os << "Decision(block, log): ";
    for (auto decision : decisions)
    {
        os << decision->getTypeStr() << "(" << decision->shouldBlock() << ", " <<
            decision->shouldLog() << ")  ";
    }
    return os;
}

bool WaapDecision::getShouldBlockFromHighestPriorityDecision() const
{
    if (!m_ordered_decisions.empty())
    {
        return m_ordered_decisions.front()->shouldBlock();
    }
    return false;
}

bool WaapDecision::anyDecisionsToLogOrBlock() const
{
    return !m_ordered_decisions.empty();
}

DecisionType WaapDecision::getHighestPriorityDecisionToLog() const
{
    if (m_first_decision_to_log == m_ordered_decisions.end())
    {
        return DecisionType::NO_WAAP_DECISION;
    }
    return (*m_first_decision_to_log)->getType();
}

void WaapDecision::getIncidentLogFields(
    const std::string& responseStatus,
    std::string& incidentDetails,
    std::string& incidentType
) const
{
    incidentDetails.clear();
    incidentType.clear();

    for (decision_list::const_iterator iter = m_first_decision_to_log; iter != m_ordered_decisions.end(); ++iter)
    {
        const std::shared_ptr<SingleDecision>& nextDecision = *iter;
        std::string tempIncidentDetails;
        std::string tempIncidentType;

        if (!nextDecision->shouldLog())
        {
            continue;
        }

        bool isRelevant = true;
        switch (nextDecision->getType())
        {
            case OPEN_REDIRECT_DECISION:
            {
                tempIncidentDetails = "OpenRedirect attack detected (" +
                    std::dynamic_pointer_cast<OpenRedirectDecision>(nextDecision)->getLink() + ")";
                tempIncidentType = "Cross Site Redirect";
                break;
            }

            case ERROR_LIMITING_DECISION:
            {
                tempIncidentDetails = "Application scanning detected";
                tempIncidentType = "Error Limit";
                break;
            }

            case RATE_LIMITING_DECISION:
            {
                tempIncidentDetails = "High request rate detected";
                tempIncidentType = "Request Rate Limit";
                break;
            }
            case ERROR_DISCLOSURE_DECISION:
                tempIncidentDetails = "Information disclosure in server response detected";
                tempIncidentDetails += ", response status code: " + responseStatus;
                tempIncidentType = "Error Disclosure";
                break;
            default:
                isRelevant = false;
                break;
        }
        if (isRelevant) {
            if (!incidentDetails.empty())
            {
                incidentDetails += " and ";
            }
            if (!incidentType.empty())
            {
                incidentType += ", ";
            }
            incidentDetails += tempIncidentDetails;
            incidentType += tempIncidentType;
        }
    }
}

void WaapDecision::setJson(const std::string& json)
{
    m_json = json;
}

std::string WaapDecision::getJson() const
{
    return m_json;
}
