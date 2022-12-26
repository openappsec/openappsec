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

#ifndef __UPDATE_POLICY_NOTIFICATION__H__
#define __UPDATE_POLICY_NOTIFICATION__H__

#include <string>
#include <ostream>
#include "rest.h"

class UpdatePolicyCrdObject : public ClientRest
{
public:
    UpdatePolicyCrdObject(const std::string &_policy_version) : policy_version(_policy_version) {}

private:
    C2S_LABEL_PARAM(std::string, policy_version, "policyVersion");
};

#endif //__UPDATE_POLICY_NOTIFICATION__H__
