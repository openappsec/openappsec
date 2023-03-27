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

#ifndef __ENV_DETAILS_H__
#define __ENV_DETAILS_H__

#include <string>
#include <fstream>
#include <streambuf>

#include "i_env_details.h"
#include "singleton.h"
#include "debug.h"

class EnvDetails : Singleton::Provide<I_EnvDetails>::SelfInterface
{
public:
    EnvDetails();

    virtual EnvType getEnvType() override;
    virtual std::string getToken() override;

private:
    std::string retrieveToken();
    std::string readFileContent(const std::string &file_path);

    std::string token;
    EnvType env_type;
};

#endif // __ENV_DETAILS_H__
