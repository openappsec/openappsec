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

#include "attachment_channel.h"
#include "debug.h"
#include "maybe_res.h"

using namespace std;

Maybe<void>
AttachmentChannel::initializeListenSocket(
    I_Socket *i_socket,
    const string &socket_path,
    function<bool(bool, bool*)> failure_check_func,
    bool* did_fail_on_purpose
)
{
    if (i_socket == nullptr) {
        return genError("Invalid socket interface");
    }

    Maybe<I_Socket::socketFd> sock = i_socket->genSocket(
        I_Socket::SocketType::UNIX,
        true,
        true,
        socket_path
    );

    bool should_fail = false;
    if (failure_check_func != nullptr && did_fail_on_purpose != nullptr) {
        should_fail = failure_check_func(sock.ok(), did_fail_on_purpose);
    } else if (failure_check_func != nullptr) {
        bool dummy = false;
        should_fail = failure_check_func(sock.ok(), &dummy);
    } else {
        should_fail = !sock.ok();
    }

    if (should_fail) {
        if (!sock.ok()) {
            return genError(sock.getErr());
        }
        return genError("Socket initialization failed");
    }

    if (sock.unpack() <= 0) {
        return genError("Generated socket is invalid (non-positive)");
    }

    listen_socket = sock.unpack();
    return Maybe<void>();
}

bool
AttachmentChannelManager::initializeChannelsIPCs(
    const string &base_unique_id,
    uint32_t user_id,
    uint32_t group_id,
    const vector<IPCInitConfig> &configs,
    void (*debug_func)(int is_error, const char *func, const char *file, int line_num, const char *fmt, ...),
    function<bool(bool, bool*)> failure_check_func
)
{
    for (const auto &config : configs) {
        if (config.channel_index >= channels.size()) {
            return false;
        }

        auto &channel = channels[config.channel_index];
        
        if (channel.ipc != nullptr) {
            continue;
        }

        string channel_unique_id = base_unique_id;
        if (!config.unique_id_suffix.empty()) {
            channel_unique_id += config.unique_id_suffix;
        }

        channel.ipc = ::initIpc(
            channel_unique_id.c_str(),
            user_id,
            group_id,
            1,
            config.num_queue_elements,
            debug_func
        );

        if (config.enable_failure_test && failure_check_func != nullptr) {
            bool did_fail_on_purpose = false;
            if (failure_check_func(channel.ipc != nullptr, &did_fail_on_purpose)) {
                channel.ipc = nullptr;
                return false;
            }
        } else if (channel.ipc == nullptr) {
            return false;
        }
    }

    return true;
}

Maybe<void>
AttachmentChannelManager::initializeChannelsSockets(
    I_Socket *i_socket,
    const string &base_socket_path,
    const vector<SocketInitConfig> &configs,
    function<bool(bool, bool*)> failure_check_func,
    function<void(size_t, const string &, bool)> error_callback
)
{
    if (i_socket == nullptr) {
        return genError("Invalid socket interface");
    }

    for (const auto &config : configs) {
        if (config.channel_index >= channels.size()) {
            return genError("Channel index out of range: " + to_string(config.channel_index));
        }

        auto &channel = channels[config.channel_index];
        
        if (channel.listen_socket > 0) {
            continue;
        }

        string channel_socket_path = base_socket_path;
        if (!config.socket_path_suffix.empty()) {
            channel_socket_path += config.socket_path_suffix;
        }

        bool did_fail_on_purpose = false;
        
        function<bool(bool, bool*)> channel_failure_check = nullptr;
        if (config.enable_failure_test && failure_check_func != nullptr) {
            channel_failure_check = failure_check_func;
        }

        Maybe<void> result = channel.initializeListenSocket(
                i_socket,
                channel_socket_path,
                channel_failure_check,
                config.enable_failure_test ? &did_fail_on_purpose : nullptr
            );

        if (!result.ok()) {
            if (error_callback != nullptr) {
                error_callback(config.channel_index, result.getErr(), did_fail_on_purpose);
            }
            return genError(
                "Failed to initialize socket for channel " +
                to_string(config.channel_index) +
                ": " +
                result.getErr()
            );
        }

        if (channel.listen_socket <= 0) {
            string error_msg = "Generated socket is invalid (non-positive)";
            if (error_callback != nullptr) {
                error_callback(config.channel_index, error_msg, false);
            }
            return genError("Channel " + to_string(config.channel_index) + ": " + error_msg);
        }
    }

    return Maybe<void>();
}

void
AttachmentChannelManager::validateAllChannelsListenSockets(const AlertInfo &alert) const
{
    using namespace AttachmentChannelIndices;
    
    if (PRIMARY_CHANNEL < channels.size()) {
        dbgAssert(channels[PRIMARY_CHANNEL].listen_socket > 0)
            << alert << "The generated server socket is OK, yet negative";
    }
    
    if (SECONDARY_CHANNEL < channels.size()) {
        dbgAssert(channels[SECONDARY_CHANNEL].listen_socket > 0)
            << alert << "The generated secondary server socket is OK, yet negative";
    }
    
    if (WEBSOCKET_CHANNEL < channels.size()) {
        dbgAssert(channels[WEBSOCKET_CHANNEL].listen_socket > 0)
            << alert << "The generated websocket server socket is OK, yet negative";
    }
}
