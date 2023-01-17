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

#include "DecisionFactory.h"
#include "debug.h"
#include "AutonomousSecurityDecision.h"
#include "CsrfDecision.h"
#include "OpenRedirectDecision.h"
#include "ErrorDisclosureDecision.h"
#include "ErrorLimitingDecision.h"
#include "RateLimitingDecision.h"
#include "UserLimitsDecision.h"

USE_DEBUG_FLAG(D_WAAP);

DecisionFactory::DecisionFactory()
{
    for (size_t i = 0; i < getDecisions().size(); i++)
    {
        initDecision(static_cast<DecisionType>(i));
    }
}

void DecisionFactory::initDecision(DecisionType type)
{
    switch (type)
    {
        case AUTONOMOUS_SECURITY_DECISION:
        {
            initAutonomousSecurityDecision();
            break;
        }
        case CSRF_DECISION:
        {
            initCsrfDecision();
            break;
        }
        case OPEN_REDIRECT_DECISION:
        {
            initOpenRedirectDecision();
            break;
        }
        case ERROR_DISCLOSURE_DECISION:
        {
            initErrorDisclosureDecision();
            break;
        }
        case ERROR_LIMITING_DECISION:
        {
            initErrorLimitingDecision();
            break;
        }
        case RATE_LIMITING_DECISION:
        {
            initRateLimitingDecision();
            break;
        }
        case USER_LIMITS_DECISION:
        {
            initUserLimitsDecision();
            break;
        }
        default:
            static_assert(true, "Illegal DecisionType ENUM value");
            dbgError(D_WAAP) << "Illegal DecisionType ENUM value " << type;
            break;
    }
}

void DecisionFactory::initAutonomousSecurityDecision()
{
    DecisionType type = DecisionType::AUTONOMOUS_SECURITY_DECISION;
    if (!m_decisions[type])
    {
        m_decisions[type] = std::make_shared<AutonomousSecurityDecision>(type);
    }
}

void DecisionFactory::initCsrfDecision()
{
    DecisionType type = DecisionType::CSRF_DECISION;
    if (!m_decisions[type])
    {
        m_decisions[type] = std::make_shared<CsrfDecision>(type);
    }
}


void DecisionFactory::initOpenRedirectDecision()
{
    DecisionType type = DecisionType::OPEN_REDIRECT_DECISION;
    if (!m_decisions[type])
    {
        m_decisions[type] = std::make_shared<OpenRedirectDecision>(type);
    }
}

void DecisionFactory::initErrorDisclosureDecision()
{
    DecisionType type = DecisionType::ERROR_DISCLOSURE_DECISION;
    if (!m_decisions[type])
    {
        m_decisions[type] = std::make_shared<ErrorDisclosureDecision>(type);
    }
}

void DecisionFactory::initErrorLimitingDecision()
{
    DecisionType type = DecisionType::ERROR_LIMITING_DECISION;
    if (!m_decisions[type])
    {
        m_decisions[type] = std::make_shared<ErrorLimitingDecision>(type);
    }
}

void DecisionFactory::initRateLimitingDecision()
{
    DecisionType type = DecisionType::RATE_LIMITING_DECISION;
    if (!m_decisions[type])
    {
        m_decisions[type] = std::make_shared<RateLimitingDecision>(type);
    }
}

void DecisionFactory::initUserLimitsDecision()
{
    DecisionType type = DecisionType::USER_LIMITS_DECISION;
    if (!m_decisions[type])
    {
        m_decisions[type] = std::make_shared<UserLimitsDecision>(type);
    }
}

std::shared_ptr<SingleDecision>
DecisionFactory::getDecision(DecisionType type) const
{
    return (type < NO_WAAP_DECISION) ? m_decisions[type] : nullptr;
}
