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

#include "details_resolving_handler.h"

#include <string>
#include <functional>
#include <map>
#include <fstream>
#include <iostream>

#include "maybe_res.h"
#include "enum_array.h"
#include "i_shell_cmd.h"
#include "i_orchestration_tools.h"
#include "config.h"

using namespace std;

USE_DEBUG_FLAG(D_AGENT_DETAILS);

using ShellCommandHandler = function<Maybe<string>(const string &raw_otput)>;
using FileContentHandler = function<Maybe<string>(shared_ptr<istream> file_otput)>;

#define __DETAILS_RESOLVER_HANDLER_CC__

#include "checkpoint_product_handlers.h"

class DetailsResolvingHanlder::Impl
{
public:
    map<string, string> getResolvedDetails() const;
    static Maybe<string> getCommandOutput(const string &cmd);

private:
#define SHELL_CMD_OUTPUT(ATTRIBUTE, COMMAND) SHELL_CMD_HANDLER(ATTRIBUTE, COMMAND, [](const string &s) { return s; })
#define SHELL_CMD_HANDLER(ATTRIBUTE, COMMAND, HANDLER) {ATTRIBUTE, {COMMAND, ShellCommandHandler(HANDLER)}},
    map<string, pair<string, ShellCommandHandler>> shell_command_handlers = {
        #include "details_resolver_impl.h"
    };
#undef SHELL_CMD_OUTPUT
#undef SHELL_CMD_HANDLER

#define FILE_CONTENT_HANDLER(ATTRIBUTE, FILE, HANDLER) {ATTRIBUTE, {FILE, FileContentHandler(HANDLER)}},
    map<string, pair<string, FileContentHandler>> file_content_handlers = {
        #include "details_resolver_impl.h"
    };
#undef FILE_CONTENT_HANDLER
};

map<string, string>
DetailsResolvingHanlder::Impl::getResolvedDetails() const
{
    map<string, string> resolved_details;
    for (auto shell_handler : shell_command_handlers) {
        const string &attr = shell_handler.first;
        const string &command = shell_handler.second.first;
        ShellCommandHandler handler = shell_handler.second.second;

        Maybe<string> shell_command_output = getCommandOutput(command);
        if (!shell_command_output.ok()) continue;
        Maybe<string> handler_ret = handler(*shell_command_output);
        if (handler_ret.ok()) resolved_details[attr] = *handler_ret;
    }

    for (auto file_handler : file_content_handlers) {
        const string &attr = file_handler.first;
        const string &path = file_handler.second.first;
        FileContentHandler handler = file_handler.second.second;

        shared_ptr<ifstream> in_file =
            Singleton::Consume<I_OrchestrationTools>::by<DetailsResolvingHanlder>()->fileStreamWrapper(path);
        if (!in_file->is_open()) {
            dbgWarning(D_AGENT_DETAILS) << "Could not open file for processing. Path: " << path;
            continue;
        }

        dbgDebug(D_AGENT_DETAILS) << "Successfully opened file for processing. Path: " << path;
        if (in_file->peek() != ifstream::traits_type::eof()) {
            Maybe<string> handler_ret = handler(in_file);
            if (handler_ret.ok()) resolved_details[attr] = *handler_ret;
        }
        in_file->close();
    }

    I_AgentDetailsReporter *reporter = Singleton::Consume<I_AgentDetailsReporter>::by<DetailsResolvingHanlder>();
    reporter->addAttr(resolved_details, true);

    return resolved_details;
}

Maybe<string>
DetailsResolvingHanlder::Impl::getCommandOutput(const string &cmd)
{
    I_ShellCmd *shell = Singleton::Consume<I_ShellCmd>::by<DetailsResolvingHanlder>();
    uint32_t timeout = getConfigurationWithDefault<uint32_t>(5000, "orchestration", "Details resolver time out");
    auto result = shell->getExecOutput(cmd, timeout);
    if (!result.ok()) return result;

    auto unpacked_result = result.unpack();
    if (!unpacked_result.empty() && unpacked_result.back() == '\n') unpacked_result.pop_back();

    return unpacked_result;
}

DetailsResolvingHanlder::DetailsResolvingHanlder() : pimpl(make_unique<Impl>()) {}
DetailsResolvingHanlder::~DetailsResolvingHanlder() {}


map<string, string>
DetailsResolvingHanlder::getResolvedDetails() const
{
    return pimpl->getResolvedDetails();
}

Maybe<string>
DetailsResolvingHanlder::getCommandOutput(const string &cmd)
{
    return DetailsResolvingHanlder::Impl::getCommandOutput(cmd);
}
