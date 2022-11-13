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

class I_K8S_Policy_Gen
{
public:
    virtual std::string parsePolicy(const std::string &policy_version) = 0;
    virtual const std::string & getPolicyPath(void) const = 0;

protected:
    ~I_K8S_Policy_Gen() {}
};

#endif //__I_LOCAL_POLICY_MGMT_GEN_H__
