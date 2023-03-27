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

#ifndef __I_ENV_DETAILS_H__
#define __I_ENV_DETAILS_H__

#include <string>
#include <stdbool.h>

enum class EnvType { LINUX, K8S, COUNT };

class I_EnvDetails
{
public:
    virtual EnvType getEnvType() = 0;
    virtual std::string getToken() = 0;

protected:
    virtual ~I_EnvDetails() {}
};

#endif // __I_ENV_DETAILS_H__
