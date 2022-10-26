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

#ifndef __DECISION_FACTORY_H__
#define __DECISION_FACTORY_H__

#include "DecisionType.h"
#include "SingleDecision.h"
#include <array>
#include <memory>

typedef std::array<std::shared_ptr<SingleDecision>, NO_WAAP_DECISION> DecisionsArr;

class DecisionFactory
{
public:
    DecisionFactory();
    std::shared_ptr<SingleDecision> getDecision(DecisionType type) const;
    const DecisionsArr& getDecisions() const
    {
        return m_decisions;
    }

private:
    void initDecision(DecisionType type);
    void initAutonomousSecurityDecision();
    void initCsrfDecision();
    void initOpenRedirectDecision();
    void initErrorDisclosureDecision();
    void initErrorLimitingDecision();
    void initRateLimitingDecision();
    void initUserLimitsDecision();
    DecisionsArr m_decisions;
};
#endif
