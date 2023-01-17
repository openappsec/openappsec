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

#ifndef __WAAP_DECISION_H__
#define __WAAP_DECISION_H__

#include <string>
#include <memory>
#include <array>
#include <list>
#include "WaapEnums.h"
#include "SingleDecision.h"
#include "DecisionFactory.h"
#include "AutonomousSecurityDecision.h"
#include <iterator>


std::ostream& operator<<(std::ostream& os, const std::list<std::shared_ptr<SingleDecision>>& decisions);
std::ostream& operator<<(std::ostream& os, const DecisionsArr& decisions);
typedef std::list<std::shared_ptr<SingleDecision>> decision_list;

class WaapDecision {
public:
    WaapDecision();
    std::shared_ptr<SingleDecision> getDecision(DecisionType type) const;
    void orderDecisions();
    static bool
    sortDecisions(const std::shared_ptr<SingleDecision>& lhs, const std::shared_ptr<SingleDecision>& rhs);
    bool getShouldBlockFromHighestPriorityDecision() const;
    bool anyDecisionsToLogOrBlock() const;
    DecisionType getHighestPriorityDecisionToLog() const;
    void getIncidentLogFields(
        const std::string& response_status,
        std::string& incidentDetails,
        std::string& incidentType
    ) const;
    void setJson(const std::string& json);
    std::string getJson() const;

private:
    friend std::ostream& operator<<(std::ostream& os, const DecisionsArr& decisions);
    friend std::ostream& operator<<(std::ostream& os,
        const std::list<std::shared_ptr<SingleDecision>>& decisions);

    void setIteratorToFirstDecisionToLog();

    std::string m_json;
    DecisionFactory m_decisionFactory;
    decision_list m_ordered_decisions;
    decision_list::const_iterator m_first_decision_to_log;
};
#endif
