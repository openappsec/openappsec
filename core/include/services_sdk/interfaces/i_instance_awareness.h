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

#ifndef __I_INSTANCE_AWARENESS_H__
#define __I_INSTANCE_AWARENESS_H__

#include <string>

#include "maybe_res.h"

class I_InstanceAwareness
{
public:
    virtual Maybe<std::string> getUniqueID() = 0;
    virtual Maybe<std::string> getFamilyID() = 0;
    virtual Maybe<std::string> getInstanceID() = 0;

    virtual std::string getUniqueID(const std::string &defaul_value) = 0;
    virtual std::string getFamilyID(const std::string &defaul_value) = 0;
    virtual std::string getInstanceID(const std::string &defaul_value) = 0;
};

#endif // __I_INSTANCE_AWARENESS_H__
