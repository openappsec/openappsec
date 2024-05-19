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

#include "messaging.h"

#include <memory>

#include "connection_comp.h"
#include "interfaces/i_messaging_connection.h"
#include "messaging_buffer.h"
#include "messaging_comp.h"

using namespace std;

USE_DEBUG_FLAG(D_MESSAGING);

// LCOV_EXCL_START Reason: This wrapper for the other components, all logic is tested there.

class Messaging::Impl : Singleton::Provide<I_Messaging>::From<Messaging>
{
public:
    void
    init()
    {
        messaging_comp.init();
        connection_comp.init();
        messaging_buffer_comp.init();
    }

    Maybe<HTTPResponse, HTTPResponse>
    sendSyncMessage(
        HTTPMethod method,
        const std::string &uri,
        const std::string &body,
        MessageCategory category,
        MessageMetadata message_metadata
    ) override
    {
        return messaging_comp.sendSyncMessage(method, uri, body, category, message_metadata);
    }

    void
    sendAsyncMessage(
        const HTTPMethod method,
        const std::string &uri,
        const std::string &body,
        const MessageCategory category,
        const MessageMetadata &message_metadata,
        bool force_buffering
    ) override
    {
        return messaging_comp.sendAsyncMessage(method, uri, body, category, message_metadata, force_buffering);
    }

    Maybe<void, HTTPResponse>
    downloadFile(
        const HTTPMethod method,
        const std::string &uri,
        const std::string &download_file_path,
        const MessageCategory category,
        MessageMetadata message_metadata
    ) override
    {
        return messaging_comp.downloadFile(method, uri, download_file_path, category, message_metadata);
    }

    Maybe<void, HTTPResponse>
    uploadFile(
        const std::string &uri,
        const std::string &upload_file_path,
        const MessageCategory category,
        MessageMetadata message_metadata
    ) override
    {
        return messaging_comp.uploadFile(uri, upload_file_path, category, message_metadata);
    }

    bool
    setFogConnection(const string &host, uint16_t port, bool is_secure, MessageCategory category) override
    {
        return messaging_comp.setFogConnection(host, port, is_secure, category);
    }

    bool
    setFogConnection(MessageCategory category = MessageCategory::GENERIC) override
    {
        return messaging_comp.setFogConnection(category);
    }

private:
    MessagingComp messaging_comp;
    ConnectionComponent connection_comp;
    MessagingBufferComponent messaging_buffer_comp;
};

Messaging::Messaging() : Component("Messaging"), pimpl(make_unique<Impl>())
{}

Messaging::~Messaging()
{}

void
Messaging::init()
{
    pimpl->init();
}

void
Messaging::preload()
{
    registerExpectedConfiguration<int>("message", "Cache timeout");
    registerExpectedConfiguration<uint>("message", "Connection timeout");
    registerExpectedConfiguration<uint>("message", "Connection handshake timeout");
    registerExpectedConfiguration<bool>("message", "Verify SSL pinning");
    registerExpectedConfiguration<bool>("message", "Buffer Failed Requests");
    registerExpectedConfiguration<string>("message", "Certificate chain file path");
    registerExpectedConfiguration<string>("message", "Trusted CA directory");
    registerExpectedConfiguration<string>("message", "Public key path");
    registerExpectedConfiguration<string>("message", "Data printout type");
    registerExpectedConfiguration<uint>("message", "Data printout length");
}

// LCOV_EXCL_STOP
