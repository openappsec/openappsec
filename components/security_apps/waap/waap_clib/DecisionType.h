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
#endif
