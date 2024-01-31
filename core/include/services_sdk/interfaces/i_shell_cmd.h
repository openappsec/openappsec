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

#ifndef __I_SHELL_CMD_H__
#define __I_SHELL_CMD_H__

#include <string>
#include <utility>

#include "maybe_res.h"

class I_ShellCmd
{
    using FullOutput = Maybe<std::pair<std::string, int>>;
public:
    virtual Maybe<std::string> getExecOutput(const std::string &cmd, uint ms_tmout = 200, bool do_yield = false) = 0;
    virtual Maybe<int> getExecReturnCode(const std::string &cmd, uint ms_tmout = 200, bool do_yield = false) = 0;
    virtual FullOutput getExecOutputAndCode(const std::string &cmd, uint ms_tmout = 200, bool do_yield = false) = 0;

protected:
    virtual ~I_ShellCmd() {}
};

#endif // __I_SHELL_CMD_H__
