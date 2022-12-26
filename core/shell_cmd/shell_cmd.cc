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

#include "shell_cmd.h"

#include <fcntl.h>

#include "singleton.h"
#include "i_time_get.h"
#include "time_print.h"
#include "config.h"

using namespace std;

USE_DEBUG_FLAG(D_INFRA_API);

// LCOV_EXCL_START Reason: temp fix for random ut failure
class ShellCmd::Impl
        :
    Singleton::Provide<I_ShellCmd>::From<ShellCmd>
{
public:
    Impl() {};

    void
    init()
    {
        mainloop = Singleton::Consume<I_MainLoop>::by<ShellCmd>();
    }

    void
    fini()
    {
        mainloop = nullptr;
    }

    Maybe<string>
    getExecOutput(const string &cmd, uint ms_tmout, bool do_yield) override
    {
        auto res = getExecOutputAndCode(cmd, ms_tmout, do_yield);
        if (!res.ok()) return res.passErr();
        return (*res).first;
    }

    Maybe<int>
    getExecReturnCode(const string &cmd, uint ms_tmout, bool do_yield) override
    {
        auto res = getExecOutputAndCode(cmd, ms_tmout, do_yield);
        if (!res.ok()) return res.passErr();
        return (*res).second;
    }

    Maybe<pair<string, int>>
    getExecOutputAndCode(const string &cmd, uint ms_tmout, bool do_yield) override
    {
        if (cmd.size() == 0) {
            dbgError(D_INFRA_API) << "Received an empty command";
            return genError("Cannot execute an empty command");
        }

        uint max_ms_tmout = getConfigurationWithDefault(400000u, "Infra", "Shell Command Timeout");
        if (ms_tmout > max_ms_tmout) {
            return genError("Provided timeout is too long, max timeout is " + to_string(max_ms_tmout));
        }

        auto pipe = popen(cmd.c_str(), "r");
        if (!pipe) {
            dbgError(D_INFRA_API) << "Failed to open \"" << cmd << "\" command pipe";
            return genError("Popen(" + cmd + ", r) failed ");
        }
        fcntl(fileno(pipe), F_SETFL, O_NONBLOCK);

        auto timer = Singleton::Consume<I_TimeGet>::by<ShellCmd>();
        chrono::microseconds timeout = timer->getMonotonicTime() + chrono::milliseconds(ms_tmout);
        string result;
        while (!feof(pipe)) {
            if (timer->getMonotonicTime() >= timeout ) {
                pclose(pipe);
                dbgWarning(D_INFRA_API) << "Reached timeout while executing shell command: " << cmd;
                return genError("Reached timeout while executing shell command: " + cmd);
            }

            char buffer[128];
            if (fgets(buffer, sizeof(buffer)-1, pipe) != nullptr) result += buffer;
            if (do_yield && mainloop != nullptr) mainloop->yield();
        }

        auto code = pclose(pipe) / 256;
        dbgDebug(D_INFRA_API) << "Command \"" << cmd << "\" returned code" << code;
        dbgTrace(D_INFRA_API) << "Command \"" << cmd << "\"  output: " << result;
        return make_pair(result, code);
    }

private:
    I_MainLoop *mainloop = nullptr;
};

ShellCmd::ShellCmd()
        :
    Component("ShellCmd"),
    pimpl(make_unique<Impl>())
{
}

ShellCmd::~ShellCmd()
{
}

void
ShellCmd::preload()
{
    registerExpectedConfiguration<uint>("Infra", "Shell Command Timeout");
}

void
ShellCmd::init()
{
    pimpl->init();
}

void
ShellCmd::fini()
{
    pimpl->fini();
}
// LCOV_EXCL_STOP
