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

#include "attachment_registrator.h"

#include <iostream>
#include <fstream>
#include <map>
#include <sstream>
#include <fstream>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <climits>
#include <unordered_map>
#include <unistd.h>
#include <utility>

#include "common.h"
#include "config.h"
#include "singleton.h"
#include "i_mainloop.h"
#include "buffer.h"
#include "enum_array.h"
#include "nginx_attachment_common.h"

USE_DEBUG_FLAG(D_ATTACHMENT_REGISTRATION);

using namespace std;

class AttachmentRegistrator::Impl
{
public:
    void
    init()
    {
        i_socket = Singleton::Consume<I_Socket>::by<AttachmentRegistrator>();
        Singleton::Consume<I_MainLoop>::by<AttachmentRegistrator>()->addOneTimeRoutine(
            I_MainLoop::RoutineType::System,
            [this] ()
            {
                while(!initSocket()) {
                    Singleton::Consume<I_MainLoop>::by<AttachmentRegistrator>()->yield(chrono::seconds(1));
                }
            },
            "Initialize attachment registration IPC"
        );

        uint expiration_timeout = getProfileAgentSettingWithDefault<uint>(
            300, "attachmentRegistrator.expirationCheckSeconds"
        );
        Singleton::Consume<I_MainLoop>::by<AttachmentRegistrator>()->addRecurringRoutine(
            I_MainLoop::RoutineType::Timer,
            chrono::seconds(expiration_timeout),
            [this] () { handleExpiration(); },
            "Attachment's expiration handler",
            true
        );
    }

    void
    fini()
    {
        if (server_sock > 0) {
            i_socket->closeSocket(server_sock);
            server_sock = -1;
        }

        if (shared_registration_path != "") unlink(shared_registration_path.c_str());
    }

private:
    bool
    registerAttachmentProcess(
        const uint8_t &uid,
        const string &family_id,
        const uint8_t num_of_members,
        const AttachmentType type)
    {
        registered_attachments[family_id] = vector<bool>(num_of_members, true);

        const int cmd_tmout = 900;
        I_ShellCmd *shell_cmd = Singleton::Consume<I_ShellCmd>::by<AttachmentRegistrator>();
        Maybe<string> registration_res = shell_cmd->getExecOutput(
            genRegCommand(family_id, num_of_members, type),
            cmd_tmout
        );
        if (!registration_res.ok()) {
            dbgWarning(D_ATTACHMENT_REGISTRATION)
                << "Failed to register attachment."
                << "Attachment Type: "
                << static_cast<int>(type)
                << ", Attachment id: "
                << uid
                <<", Family id: "
                << family_id
                << ", Total number of instances: "
                << num_of_members;

            return false;
        }

        return true;
    }

    void
    replyWithRelevantHandler(
        I_Socket::socketFd socket,
        const uint8_t &uid,
        const string &family_id,
        const AttachmentType type)
    {
        string handler_path = genHandlerPath(uid, family_id, type);

        uint8_t path_size = handler_path.size();
        vector<char> path_size_data(reinterpret_cast<char *>(&path_size), reinterpret_cast<char *>(&path_size) + 1);
        if (!i_socket->writeData(socket, path_size_data)) {
            dbgWarning(D_ATTACHMENT_REGISTRATION) << "Failed to send handler path size to attachment";
            return;
        }

        dbgDebug(D_ATTACHMENT_REGISTRATION)
            << "Successfully sent handler path size to attachment. Size: "
            << to_string(path_size);

        vector<char> path_data(handler_path.data(), handler_path.data() + handler_path.size());
        if (!i_socket->writeData(socket, path_data)) {
            dbgWarning(D_ATTACHMENT_REGISTRATION)
                << "Failed to send handler path data to attachment. Path: "
                << handler_path;
            return;
        }

        dbgDebug(D_ATTACHMENT_REGISTRATION)
            << "Successfully sent handler path data to attachment. Path: "
            << handler_path;
    }

    string
    genHandlerPath(const uint8_t &uid, const string &family_id, const AttachmentType type) const
    {
        static const string handler_path_format = "/dev/shm/check-point/cp-nano-";
        stringstream handler_path;
        handler_path << handler_path_format;
        switch(type) {
            case (AttachmentType::SQUID_ATT_ID): {
                handler_path << "squid-http-transaction-handler-";
                break;
            }
            case (AttachmentType::NGINX_ATT_ID): {
                handler_path << "http-transaction-handler-";
                break;
            }
            default:
                dbgAssert(false) << "Unsupported Attachment " << static_cast<int>(type);
        }

        if (!family_id.empty()) handler_path << family_id << "_";
        handler_path << to_string(uid);

        return handler_path.str();
    }

    string
    genRegCommand(const string &family_id, const uint num_of_members, const AttachmentType type) const
    {
        dbgAssert(num_of_members > 0) << "Failed to generate a registration command for an empty group of attachments";

        static const string registration_format = "/etc/cp/watchdog/cp-nano-watchdog --register ";
        stringstream registration_command;
        registration_command<< registration_format;
        switch(type) {
            case (AttachmentType::SQUID_ATT_ID):
            case (AttachmentType::NGINX_ATT_ID):{
                registration_command << "/etc/cp/HttpTransactionHandler/cp-nano-http-transaction-handler";
                break;
            }
            default:
                dbgAssert(false) << "Unsupported Attachment " << static_cast<int>(type);
        }

        if (!family_id.empty()) registration_command << " --family " << family_id;
        registration_command << " --count " << to_string(num_of_members);

        return registration_command.str();
    }

    bool
    initSocket()
    {
        shared_registration_path = getConfigurationWithDefault<string>(
            "/dev/shm/check-point/cp-nano-attachment-registration",
            "Attachment Registration",
            "Registration IPC Path"
        );

        size_t last_slash_idx = shared_registration_path.find_last_of("/");
        string directory_path = shared_registration_path.substr(0, last_slash_idx);
        mkdir(directory_path.c_str(), 0777);

        if (server_sock < 0) {
            server_sock = getNewSocket(shared_registration_path);
            if (server_sock < 0) {
                dbgWarning(D_ATTACHMENT_REGISTRATION)
                    << "Failed to create server socket. Path: "
                    << shared_registration_path;
                return false;
            }

            Singleton::Consume<I_MainLoop>::by<AttachmentRegistrator>()->addFileRoutine(
                I_MainLoop::RoutineType::RealTime,
                server_sock,
                [this] () { handleAttachmentRegistration(); },
                "Attachment's registration handler",
                true
            );
        }

        string shared_expiration_path = getConfigurationWithDefault<string>(
            SHARED_KEEP_ALIVE_PATH,
            "Attachment Registration",
            "Registration IPC Path"
        );

        if (keep_alive_sock < 0) {
            keep_alive_sock = getNewSocket(shared_expiration_path);
            if (keep_alive_sock < 0) {
                dbgWarning(D_ATTACHMENT_REGISTRATION) << "Failed to create keep-alive socket";
                return false;
            }

            Singleton::Consume<I_MainLoop>::by<AttachmentRegistrator>()->addFileRoutine(
                I_MainLoop::RoutineType::System,
                keep_alive_sock,
                [this] () { handleKeepAlives(); },
                "Attachment keep alive registration",
                true
            );
        }
        return true;
    }

    I_Socket::socketFd
    getNewSocket(const string &path)
    {
        Maybe<I_Socket::socketFd> new_socket = i_socket->genSocket(
            I_Socket::SocketType::UNIX,
            false,
            true,
            path
        );
        if (!new_socket.ok()) {
            dbgWarning(D_ATTACHMENT_REGISTRATION) << "Failed to open a socket. Error: " << new_socket.getErr();
            return -1;
        }

        dbgAssert(new_socket.unpack() > 0) << "Generated socket is OK yet negative";
        return new_socket.unpack();
    }

    void
    handleKeepAlives()
    {
        Maybe<I_Socket::socketFd> accepted_socket = i_socket->acceptSocket(keep_alive_sock, false);
        if (!accepted_socket.ok()) {
            dbgWarning(D_ATTACHMENT_REGISTRATION)
                << "Failed to accept new keep-alive request socket: "
                << accepted_socket.getErr();
            return;
        }

        I_Socket::socketFd client_socket = accepted_socket.unpack();
        dbgAssert(client_socket > 0) << "Generated client socket is OK yet negative";
        auto close_socket_on_exit = make_scope_exit([&]() { i_socket->closeSocket(client_socket); });

        Maybe<uint8_t> attachment_id = readNumericParam(client_socket);
        if (!attachment_id.ok()) {
            dbgWarning(D_ATTACHMENT_REGISTRATION) << "Failed to register new attachment: " << attachment_id.getErr();
            return;
        }

        Maybe<string> family_id = readStringParam(client_socket);
        if (!family_id.ok()) {
            dbgWarning(D_ATTACHMENT_REGISTRATION) << "Failed to register new attachment: " << family_id.getErr();
            return;
        }

        if (family_id.unpack() == "") return;

        auto family_members = registered_attachments.find(family_id.unpack());
        if (family_members == registered_attachments.end()) {
            dbgWarning(D_ATTACHMENT_REGISTRATION)
                << "Adding new unregistered family. Family ID: "
                << family_id.unpack();
            registered_attachments[family_id.unpack()] = vector<bool>(attachment_id.unpack() + 1, true);
            return;
        }

        if (family_members->second.size() <= attachment_id.unpack()) {
            dbgWarning(D_ATTACHMENT_REGISTRATION)
                << "Adding new non-monitored family members. Family ID: "
                << family_id.unpack()
                << ", Instance ID:"
                << attachment_id.unpack();

            registered_attachments[family_id.unpack()] = vector<bool>(attachment_id.unpack() + 1, true);
            return;
        }
        family_members->second[attachment_id.unpack()] = true;
    }

    void
    handleExpiration()
    {
        I_ShellCmd *shell_cmd = Singleton::Consume<I_ShellCmd>::by<AttachmentRegistrator>();
        vector<string> deleted_families;
        for (pair<const string, vector<bool, allocator<bool>>> &family : registered_attachments) {
            const string &family_id = family.first;
            if (family_id == "") continue;

            bool is_family_inactive = true;
            vector<bool> &family_members = family.second;
            for (const bool member : family_members) {
                if (member == true) is_family_inactive = false;
            }

            if (is_family_inactive) {
                static const string unregister_format = "/etc/cp/watchdog/cp-nano-watchdog --un-register ";
                stringstream unregister_command;
                unregister_command << unregister_format;
                unregister_command << "/etc/cp/HttpTransactionHandler/cp-nano-http-transaction-handler";
                unregister_command << " --family " << family_id;

                Maybe<string> res = shell_cmd->getExecOutput(unregister_command.str());
                if (!res.ok()) {
                    dbgWarning(D_ATTACHMENT_REGISTRATION)
                        << "Failed to un-register attachment. Family id: "
                        << family_id;
                } else {
                    deleted_families.push_back(family_id);
                }
            } else {
                fill(family_members.begin(), family_members.end(), false);
            }
        }

        for (const string &family : deleted_families) {
            registered_attachments.erase(family);
            dbgWarning(D_ATTACHMENT_REGISTRATION)
                << "Successfully un-registered attachments family. Family id: "
                << family;
        }
    }

    void
    handleAttachmentRegistration()
    {
        Maybe<I_Socket::socketFd> accepted_socket = i_socket->acceptSocket(server_sock, false);
        if (!accepted_socket.ok()) {
            dbgWarning(D_ATTACHMENT_REGISTRATION)
                << "Failed to accept a new client socket: "
                << accepted_socket.getErr();
            return;
        }

        I_Socket::socketFd client_socket = accepted_socket.unpack();
        dbgAssert(client_socket > 0) << "Generated client socket is OK yet negative";
        auto close_socket_on_exit = make_scope_exit([&]() { i_socket->closeSocket(client_socket); });

        Maybe<AttachmentType> attachment_type = readAttachmentType(client_socket);
        if (!attachment_type.ok()) {
            dbgWarning(D_ATTACHMENT_REGISTRATION)
                << "Failed to register a new attachment: "
                << attachment_type.getErr();
            return;
        }

        Maybe<uint8_t> attachment_id = readNumericParam(client_socket);
        if (!attachment_id.ok()) {
            dbgWarning(D_ATTACHMENT_REGISTRATION) << "Failed to register a new attachment: " << attachment_id.getErr();
            return;
        }

        Maybe<uint8_t> instances_count = readNumericParam(client_socket);
        if (!instances_count.ok()) {
            dbgWarning(D_ATTACHMENT_REGISTRATION)
                << "Failed to register a new attachment: "
                << instances_count.getErr();
            return;
        }

        Maybe<string> family_id = readStringParam(client_socket);
        if (!family_id.ok()) {
            dbgWarning(D_ATTACHMENT_REGISTRATION) << "Failed to register a new attachment: " << family_id.getErr();
            return;
        }

        if (!registerAttachmentProcess(*attachment_id, *family_id, *instances_count, *attachment_type)) {
            return;
        }

        replyWithRelevantHandler(client_socket, *attachment_id, *family_id, *attachment_type);
    }

    Maybe<uint8_t>
    readNumericParam(I_Socket::socketFd socket)
    {
        Maybe<vector<char>> param_to_read = i_socket->receiveData(socket, sizeof(uint8_t));
        if (!param_to_read.ok()) {
            dbgWarning(D_ATTACHMENT_REGISTRATION) << "Failed to read param: " << param_to_read.getErr();
            return genError("Failed to read numeric parameter");
        }

        return *reinterpret_cast<const uint8_t *>(param_to_read.unpack().data());
    }

    Maybe<AttachmentType>
    readAttachmentType(I_Socket::socketFd socket)
    {
        Maybe<uint8_t> attachment_type = readNumericParam(socket);
        if (!attachment_type.ok()) return attachment_type.passErr();

        dbgTrace(D_ATTACHMENT_REGISTRATION)
            << "Successfully received attachment type. Attachment type value: "
            << static_cast<int>(*attachment_type);

        return convertToEnum<AttachmentType>(*attachment_type);
    }

    Maybe<string>
    readStringParam(I_Socket::socketFd socket)
    {
        Maybe<uint8_t> param_size = readNumericParam(socket);
        if (!param_size.ok()) return param_size.passErr();

        dbgTrace(D_ATTACHMENT_REGISTRATION)
            << "Successfully received string size. Size: "
            << static_cast<int>(*param_size);

        Maybe<vector<char>> param_to_read = i_socket->receiveData(socket, param_size.unpack());

        return string(param_to_read.unpack().begin(), param_to_read.unpack().end());
    }

    I_Socket::socketFd server_sock = -1;
    I_Socket::socketFd keep_alive_sock = -1;
    I_Socket *i_socket = nullptr;
    map<string, vector<bool>> registered_attachments;
    string shared_registration_path;
};

AttachmentRegistrator::AttachmentRegistrator() : Component("AttachmentRegistrator"), pimpl(make_unique<Impl>()) {}

AttachmentRegistrator::~AttachmentRegistrator() {}

void AttachmentRegistrator::init() { pimpl->init(); }

void AttachmentRegistrator::fini() { pimpl->fini(); }

void
AttachmentRegistrator::preload()
{
    registerExpectedConfiguration<string>("Attachment Registration", "Registration IPC Path");
}
