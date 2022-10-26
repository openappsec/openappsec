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

#ifndef __I_IOCTL_H__
#define __I_IOCTL_H__

#include "maybe_res.h"
#include "common_is/ioctl_common.h"

class I_Ioctl
{
public:
    virtual Maybe<int> sendIoctl(AgentIoctlCmdNumber request, void *ioctl_data, uint32_t size_of_data) = 0;

protected:
    virtual ~I_Ioctl() {}
};

#endif // __I_IOCTL_H__
