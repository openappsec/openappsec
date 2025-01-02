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
#include "component.h"

class EnvDetails
        :
    public Component,
    Singleton::Provide<I_EnvDetails>::SelfInterface
{
public:
    EnvDetails();

    virtual EnvType getEnvType() override;
    virtual std::string getToken() override;
    virtual std::string getNameSpace() override;

private:
    std::string retrieveToken();
    std::string retrieveNamespace();
    std::string readFileContent(const std::string &file_path);
    bool doesFileExist(const std::string &file_path) const;

    std::string token;
    std::string agent_namespace;
    EnvType env_type = EnvType::LINUX;
};

#endif // __ENV_DETAILS_H__
