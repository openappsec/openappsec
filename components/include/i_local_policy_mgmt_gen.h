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

#ifndef __I_LOCAL_POLICY_MGMT_GEN_H__
#define __I_LOCAL_POLICY_MGMT_GEN_H__

#include "i_env_details.h"

class I_LocalPolicyMgmtGen
{
public:
    virtual std::string generateAppSecLocalPolicy(
        EnvType env_type,
        const std::string &policy_version,
        const std::string &local_policy_path) = 0;

protected:
    ~I_LocalPolicyMgmtGen() {}
};

#endif //__I_LOCAL_POLICY_MGMT_GEN_H__
