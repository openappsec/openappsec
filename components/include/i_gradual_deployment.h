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

#ifndef __I_GRADUAL_DEPLOYMENT_H__
#define __I_GRADUAL_DEPLOYMENT_H__

#include <memory>
#include <vector>
#include <arpa/inet.h>

#include "maybe_res.h"
#include "c_common/ip_common.h"

class I_GradualDeployment
{
public:
    enum class AttachmentType { NGINX, KERNEL, COUNT };

    virtual Maybe<void> setPolicy(AttachmentType type, const std::vector<std::string> &str_ip_ranges) = 0;
    virtual std::vector<std::string> getPolicy(AttachmentType type) = 0;
    virtual std::vector<IPRange> & getParsedPolicy(AttachmentType type) = 0;

protected:
    virtual ~I_GradualDeployment() {}
};

#endif // __I_GRADUAL_DEPLOYMENT_H__
