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

#ifndef __DECISION_TYPE_H__
#define __DECISION_TYPE_H__

#include <ostream>

enum DecisionType
{
    // This order determines the priority of the decisions sent to management
    // Priority goes from top to bottom
    AUTONOMOUS_SECURITY_DECISION,
    CSRF_DECISION,
    OPEN_REDIRECT_DECISION,
    ERROR_DISCLOSURE_DECISION,
    ERROR_LIMITING_DECISION,
    USER_LIMITS_DECISION,
    RATE_LIMITING_DECISION,
    // Must be kept last
    NO_WAAP_DECISION
};

inline const char *
decisionTypeToString(DecisionType type)
{
    switch (type) {
        case DecisionType::AUTONOMOUS_SECURITY_DECISION:
            return "AUTONOMOUS_SECURITY_DECISION";
        case DecisionType::CSRF_DECISION:
            return "CSRF_DECISION";
        case DecisionType::OPEN_REDIRECT_DECISION:
            return "OPEN_REDIRECT_DECISION";
        case DecisionType::ERROR_DISCLOSURE_DECISION:
            return "ERROR_DISCLOSURE_DECISION";
        case DecisionType::ERROR_LIMITING_DECISION:
            return "ERROR_LIMITING_DECISION";
        case DecisionType::USER_LIMITS_DECISION:
            return "USER_LIMITS_DECISION";
        case DecisionType::RATE_LIMITING_DECISION:
            return "RATE_LIMITING_DECISION";
        case DecisionType::NO_WAAP_DECISION:
            return "NO_WAAP_DECISION";
        default:
            return "INVALID_DECISION_TYPE";
    }
}

inline std::ostream & operator<<(std::ostream& os, const DecisionType& type)
{
    return os << decisionTypeToString(type);
}

#endif
