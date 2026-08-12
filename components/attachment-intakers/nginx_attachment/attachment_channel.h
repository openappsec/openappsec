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

#ifndef __ATTACHMENT_CHANNEL_H__
#define __ATTACHMENT_CHANNEL_H__

#include <vector>
#include <functional>
#include <string>

#include "i_socket_is.h"
#include "shmem_ipc.h"
#include "maybe_res.h"

/// @brief Standard channel indices for common attachment configurations
namespace AttachmentChannelIndices
{
    static constexpr size_t PRIMARY_CHANNEL = 0;
    static constexpr size_t SECONDARY_CHANNEL = 1;
    static constexpr size_t WEBSOCKET_CHANNEL = 2;
}

/// @brief Configuration for initializing a channel's IPC
struct IPCInitConfig
{
    size_t channel_index;              ///< Index of the channel to initialize
    std::string unique_id_suffix;      ///< Suffix to append to base unique ID (empty string uses base ID as-is)
    uint16_t num_queue_elements;       ///< Number of IPC queue elements
    bool enable_failure_test;          ///< Whether to enable failure testing for this channel
};

/// @brief Configuration for initializing a channel's socket
struct SocketInitConfig
{
    size_t channel_index;              ///< Index of the channel to initialize
    std::string socket_path_suffix;    ///< Suffix to append to base socket path (empty string uses base path as-is)
    bool enable_failure_test;          ///< Whether to enable failure testing for this channel
};

/// @brief Get standard channel initialization configuration for nginx attachment
/// @param num_of_primary_ipc_elements Number of IPC elements for primary channel
/// @return Vector of channel initialization configurations using standard channel indices
inline std::vector<IPCInitConfig> getNginxIPCInitConfigs(uint16_t num_of_primary_ipc_elements)
{
    return {
        {
            AttachmentChannelIndices::PRIMARY_CHANNEL,
            "",  // Use base unique ID as-is
            num_of_primary_ipc_elements,
            true  // Enable failure testing for primary channel
        },
        {
            AttachmentChannelIndices::SECONDARY_CHANNEL,
            "_sync",  // Append suffix to base unique ID
            200,
            false  // No failure testing for secondary channel
        },
        {
            AttachmentChannelIndices::WEBSOCKET_CHANNEL,
            "_websocket",  // Append suffix to base unique ID
            200,
            false  // No failure testing for websocket channel
        }
    };
}

/// @brief Get standard socket initialization configuration for nginx attachment
/// @return Vector of socket initialization configurations using standard channel indices
inline std::vector<SocketInitConfig> getNginxSocketInitConfigs()
{
    return {
        {
            AttachmentChannelIndices::PRIMARY_CHANNEL,
            "",  // Use base socket path as-is
            true  // Enable failure testing for primary channel
        },
        {
            AttachmentChannelIndices::SECONDARY_CHANNEL,
            "_secondary",  // Append suffix to base socket path
            true  // Enable failure testing for secondary channel
        },
        {
            AttachmentChannelIndices::WEBSOCKET_CHANNEL,
            "_websocket",  // Append suffix to base socket path
            true  // Enable failure testing for websocket channel
        }
    };
}

/// @brief Class managing a listen socket, communication socket, and shared memory IPC
/// Provides unified methods for common operations on attachment channels
class AttachmentChannel
{
public:
    AttachmentChannel()
        : listen_socket(-1),
        comm_socket(-1),
        ipc(nullptr)
    {
    }

    /// @brief Close the listen socket if it's open
    /// @param i_socket Socket interface for closing the socket
    void closeListenSocket(I_Socket *i_socket)
    {
        if (listen_socket > 0 && i_socket != nullptr) {
            i_socket->closeSocket(listen_socket);
            listen_socket = -1;
        }
    }

    /// @brief Close the communication socket if it's open
    /// @param i_socket Socket interface for closing the socket
    void closeCommSocket(I_Socket *i_socket)
    {
        if (comm_socket > 0 && i_socket != nullptr) {
            i_socket->closeSocket(comm_socket);
            comm_socket = -1;
        }
    }

    /// @brief Close both sockets
    /// @param i_socket Socket interface for closing the sockets
    void closeAllSockets(I_Socket *i_socket)
    {
        closeListenSocket(i_socket);
        closeCommSocket(i_socket);
    }

    /// @brief Destroy the IPC if it exists
    void cleanupIpc()
    {
        if (ipc != nullptr) {
            ::destroyIpc(ipc, 1);
            ipc = nullptr;
        }
    }

    /// @brief Reset the IPC if it exists
    /// @param num_elements Number of IPC elements
    void resetChannelIpc(uint num_elements)
    {
        if (ipc != nullptr) {
            ::resetIpc(ipc, num_elements);
        }
    }

    /// @brief Check if IPC data is available
    /// @return true if data is available, false otherwise
    bool hasDataAvailable() const
    {
        return ipc != nullptr && ::isDataAvailable(ipc);
    }

    /// @brief Check if signal is pending on communication socket
    /// @param i_socket Socket interface for checking data availability
    /// @return true if signal is pending, false otherwise
    bool isSignalPending(I_Socket *i_socket) const
    {
        if (comm_socket < 0 || i_socket == nullptr) {
            return false;
        }
        return i_socket->isDataAvailable(comm_socket);
    }

    /// @brief Check if shared memory is corrupted
    /// @return true if corrupted, false otherwise
    bool hasCorruptedShmem() const
    {
        return ipc != nullptr && ::isCorruptedShmem(ipc, 1);
    }

    /// @brief Check if the channel is initialized (has a valid listen socket)
    /// @return true if initialized, false otherwise
    bool isInitialized() const
    {
        return listen_socket > 0;
    }

    /// @brief Initialize the listen socket for this channel
    /// @param i_socket Socket interface for creating the socket
    /// @param socket_path Path for the UNIX socket
    /// @param failure_check_func Optional function to check for intentional failures.
    ///                           Takes (bool success, bool* did_fail_on_purpose) and returns true if should fail.
    /// @param did_fail_on_purpose Optional pointer to set if failure was intentional
    /// @return Maybe<void> - success if socket was initialized successfully, error otherwise
    Maybe<void> initializeListenSocket(
        I_Socket *i_socket,
        const std::string &socket_path,
        std::function<bool(bool, bool*)> failure_check_func = nullptr,
        bool* did_fail_on_purpose = nullptr
    );

    I_Socket::socketFd listen_socket;
    I_Socket::socketFd comm_socket;
    SharedMemoryIPC *ipc;
};

/// @brief Manager class for multiple attachment channels
/// Provides infrastructure for managing and operating on multiple channels
class AttachmentChannelManager
{
public:
    /// @brief Construct a channel manager with a specified number of channels
    /// @param num_channels Number of channels to create (default: 3 for primary, secondary, and websocket)
    explicit AttachmentChannelManager(size_t num_channels = 3)
        : channels(num_channels)
    {
    }

    /// @brief Get the number of channels
    /// @return Number of channels
    size_t size() const
    {
        return channels.size();
    }

    /// @brief Get a channel by index
    /// @param index Channel index
    /// @return Reference to the channel
    AttachmentChannel &getChannel(size_t index)
    {
        return channels[index];
    }

    /// @brief Get a channel by index (const version)
    /// @param index Channel index
    /// @return Const reference to the channel
    const AttachmentChannel &getChannel(size_t index) const
    {
        return channels[index];
    }


    /// @brief Apply a function to all channels
    /// @param func Function to apply to each channel
    void forEachChannel(std::function<void(AttachmentChannel &)> func)
    {
        for (auto& channel : channels) {
            func(channel);
        }
    }

    /// @brief Close all sockets on all channels
    /// @param i_socket Socket interface for closing the sockets
    void closeAllSockets(I_Socket *i_socket)
    {
        forEachChannel([i_socket](AttachmentChannel &channel) {
            channel.closeAllSockets(i_socket);
        });
    }

    /// @brief Cleanup IPC on all channels
    void cleanupAllIpc()
    {
        forEachChannel([](AttachmentChannel &channel) {
            channel.cleanupIpc();
        });
    }

    /// @brief Reset IPC on all channels
    /// @param num_elements Number of IPC elements
    void resetAllIpc(uint num_elements)
    {
        forEachChannel([num_elements](AttachmentChannel &channel) {
            channel.resetChannelIpc(num_elements);
        });
    }

    /// @brief Check if any channel has corrupted shared memory
    /// @return true if any channel has corrupted shared memory, false otherwise
    bool hasAnyCorruptedShmem() const
    {
        for (const auto &channel : channels) {
            if (channel.hasCorruptedShmem()) {
                return true;
            }
        }
        return false;
    }

    /// @brief Check if any channel has data available
    /// @return true if any channel has data available, false otherwise
    bool hasAnyDataAvailable() const
    {
        for (const auto &channel : channels) {
            if (channel.hasDataAvailable()) {
                return true;
            }
        }
        return false;
    }

    /// @brief Initialize IPC for multiple channels based on configuration
    /// @param base_unique_id Base unique ID to use for channel naming
    /// @param user_id User ID for IPC initialization
    /// @param group_id Group ID for IPC initialization
    /// @param configs Vector of channel initialization configurations
    /// @param debug_func Debug function to use for IPC initialization
    /// @param failure_check_func Optional function to check for intentional failures.
    ///                           Takes (bool success, bool* did_fail_on_purpose) and returns true if should fail.
    ///                           Only called for channels with enable_failure_test=true.
    /// @return true if all channels were initialized successfully, false otherwise
    bool initializeChannelsIPCs(
        const std::string &base_unique_id,
        uint32_t user_id,
        uint32_t group_id,
        const std::vector<IPCInitConfig> &configs,
        void (*debug_func)(int is_error, const char *func, const char *file, int line_num, const char *fmt, ...),
        std::function<bool(bool, bool*)> failure_check_func = nullptr
    );

    /// @brief Initialize sockets for multiple channels based on configuration
    /// @param i_socket Socket interface for creating the sockets
    /// @param base_socket_path Base socket path to use for channel naming
    /// @param configs Vector of socket initialization configurations
    /// @param failure_check_func Optional function to check for intentional failures.
    ///                           Takes (bool success, bool* did_fail_on_purpose) and returns true if should fail.
    ///                           Only called for channels with enable_failure_test=true.
    /// @param error_callback Optional callback function called when initialization fails.
    ///                       Takes (size_t channel_index, const std::string &error_msg, bool did_fail_on_purpose).
    /// @return Maybe<void> - success if all channels were initialized successfully, error otherwise
    Maybe<void> initializeChannelsSockets(
        I_Socket *i_socket,
        const std::string &base_socket_path,
        const std::vector<SocketInitConfig> &configs,
        std::function<bool(bool, bool*)> failure_check_func = nullptr,
        std::function<void(size_t, const std::string &, bool)> error_callback = nullptr
    );

    /// @brief Validate that all channels have valid listen sockets
    /// @param alert AlertInfo reference for error reporting
    void validateAllChannelsListenSockets(const class AlertInfo &alert) const;

    /// @brief Get iterator to the beginning of channels
    /// @return Iterator to the beginning
    std::vector<AttachmentChannel>::iterator begin()
    {
        return channels.begin();
    }

    /// @brief Get iterator to the end of channels
    /// @return Iterator to the end
    std::vector<AttachmentChannel>::iterator end()
    {
        return channels.end();
    }

    /// @brief Get const iterator to the beginning of channels
    /// @return Const iterator to the beginning
    std::vector<AttachmentChannel>::const_iterator begin() const
    {
        return channels.begin();
    }

    /// @brief Get const iterator to the end of channels
    /// @return Const iterator to the end
    std::vector<AttachmentChannel>::const_iterator end() const
    {
        return channels.end();
    }

private:
    std::vector<AttachmentChannel> channels;
};

#endif // __ATTACHMENT_CHANNEL_H__
