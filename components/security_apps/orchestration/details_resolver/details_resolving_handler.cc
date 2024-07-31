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

static const string filesystem_place_holder = "<FILESYSTEM-PREFIX>";

class DetailsResolvingHanlder::Impl
{
public:
    void init();
    map<string, string> getResolvedDetails() const;
    static Maybe<string> getCommandOutput(const string &cmd);

private:
#define SHELL_PRE_CMD(NAME, COMMAND) {NAME, COMMAND},
    map<string, string> shell_pre_commands = {
        #include "details_resolver_impl.h"
    };
#undef SHELL_PRE_CMD

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

#define SHELL_POST_CMD(NAME, COMMAND) {NAME, COMMAND},
    map<string, string> shell_post_commands = {
        #include "details_resolver_impl.h"
    };
#undef SHELL_POST_CMD

void
DetailsResolvingHanlder::Impl::init()
{
    string actual_filesystem_prefix = getFilesystemPathConfig();
    size_t place_holder_size = filesystem_place_holder.size();

    for (auto &file_handler : file_content_handlers) {
        string &path = file_handler.second.first;
        if (path.substr(0, place_holder_size) == filesystem_place_holder) {
            path = actual_filesystem_prefix + path.substr(place_holder_size);
        }
    }

    for (auto &cmd_handler_pair : shell_command_handlers) {
        string &cmd_str = cmd_handler_pair.second.first;
        size_t fs_pos = cmd_str.find(filesystem_place_holder);
        if (fs_pos != string::npos) {
            cmd_str.replace(fs_pos, place_holder_size, actual_filesystem_prefix);
        }
    }
}

map<string, string>
DetailsResolvingHanlder::Impl::getResolvedDetails() const
{
    I_ShellCmd *shell = Singleton::Consume<I_ShellCmd>::by<DetailsResolvingHanlder>();
    I_AgentDetailsReporter *reporter = Singleton::Consume<I_AgentDetailsReporter>::by<DetailsResolvingHanlder>();
    uint32_t timeout = getConfigurationWithDefault<uint32_t>(5000, "orchestration", "Details resolver time out");

    for (auto &shell_pre_command : shell_pre_commands) {
        const string &name = shell_pre_command.first;
        const string &command = shell_pre_command.second;
        Maybe<int> command_ret = shell->getExecReturnCode(command, timeout);

        if (!command_ret.ok()) {
            dbgWarning(D_AGENT_DETAILS) << "Failed to run pre-command " << name;
        } else if (*command_ret) {
            dbgWarning(D_AGENT_DETAILS) << "Pre-command " << name << " failed (rc: " << *command_ret << ")";
        }
    }

    map<string, string> resolved_details;
    for (auto shell_handler : shell_command_handlers) {
        const string &attr = shell_handler.first;
        const string &command = shell_handler.second.first;
        ShellCommandHandler handler = shell_handler.second.second;

        Maybe<string> shell_command_output = getCommandOutput(command);
        if (!shell_command_output.ok()) continue;
        Maybe<string> handler_ret = handler(*shell_command_output);

        if (handler_ret.ok()) {
            resolved_details[attr] = *handler_ret;
        } else {
            if (reporter->isPersistantAttr(attr)) {
                dbgTrace(D_AGENT_DETAILS)<< "Persistent attribute changed, removing old value";
                reporter->deleteAttr(attr);
            }
        }
    }

    for (auto file_handler : file_content_handlers) {
        const string &attr = file_handler.first;
        const string &path = file_handler.second.first;
        FileContentHandler handler = file_handler.second.second;

        shared_ptr<ifstream> in_file =
            Singleton::Consume<I_OrchestrationTools>::by<DetailsResolvingHanlder>()->fileStreamWrapper(path);
        if (!in_file->is_open()) {
            dbgDebug(D_AGENT_DETAILS) << "Could not open file for processing. Path: " << path;
            continue;
        }

        dbgDebug(D_AGENT_DETAILS) << "Successfully opened file for processing. Path: " << path;
        if (in_file->peek() != ifstream::traits_type::eof()) {
            Maybe<string> handler_ret = handler(in_file);
            if (handler_ret.ok()) resolved_details[attr] = *handler_ret;
        }
        in_file->close();
    }

    for (auto &shell_post_command : shell_post_commands) {
        const string &name = shell_post_command.first;
        const string &command = shell_post_command.second;
        Maybe<int> command_ret = shell->getExecReturnCode(command, timeout);

        if (!command_ret.ok()) {
            dbgWarning(D_AGENT_DETAILS) << "Failed to run post-command " << name;
        } else if (*command_ret) {
            dbgWarning(D_AGENT_DETAILS) << "Post-command " << name << " failed (rc: " << *command_ret << ")";
        }
    }

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

void
DetailsResolvingHanlder::init()
{
    return pimpl->init();
}

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
