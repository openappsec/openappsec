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

#ifndef __DETAILS_RESOLVING_HANDLER_H__
#define __DETAILS_RESOLVING_HANDLER_H__

#include <string>
#include <map>

#include "i_shell_cmd.h"
#include "i_orchestration_tools.h"
#include "i_agent_details_reporter.h"

class DetailsResolvingHanlder
        :
    Singleton::Consume<I_ShellCmd>,
    Singleton::Consume<I_OrchestrationTools>,
    Singleton::Consume<I_AgentDetailsReporter>
{
public:
    DetailsResolvingHanlder();
    ~DetailsResolvingHanlder();

    std::map<std::string, std::string> getResolvedDetails() const;

    static Maybe<std::string> getCommandOutput(const std::string &cmd);

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __DETAILS_RESOLVING_HANDLER_H__
