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
#ifndef __I_MESSAGING_H__
#define __I_MESSAGING_H__

#include <string>
#include <map>
#include <sstream>
#include <fstream>
#include <ostream>

#include "i_agent_details.h"
#include "i_proxy_configuration.h"
#include "flags.h"
#include "maybe_res.h"
#include "messaging/http_response.h"
#include "messaging/messaging_metadata.h"

USE_DEBUG_FLAG(D_MESSAGING);

class I_Messaging
        :
    Singleton::Consume<I_AgentDetails>,
    Singleton::Consume<I_ProxyConfiguration>
{
public:
    template <typename serializableObject>
    Maybe<void, HTTPResponse> sendSyncMessage(
        HTTPMethod method,
        const std::string &uri,
        serializableObject &req_obj,
        MessageCategory category = MessageCategory::GENERIC,
        MessageMetadata message_metadata = MessageMetadata());

    template <typename serializableObject>
    bool sendSyncMessageWithoutResponse(
        const HTTPMethod method,
        const std::string &uri,
        serializableObject &req_obj,
        const MessageCategory category = MessageCategory::GENERIC,
        MessageMetadata message_metadata = MessageMetadata());

    template <typename serializableObject>
    void sendAsyncMessage(
        const HTTPMethod method,
        const std::string &uri,
        serializableObject &req_obj,
        const MessageCategory category = MessageCategory::GENERIC,
        MessageMetadata message_metadata = MessageMetadata(),
        bool force_buffering = true);

    virtual void sendAsyncMessage(
        const HTTPMethod method,
        const std::string &uri,
        const std::string &body,
        const MessageCategory category,
        const MessageMetadata &message_metadata = MessageMetadata(),
        bool force_buffering = true
    ) = 0;

    virtual Maybe<HTTPResponse, HTTPResponse> sendSyncMessage(
        const HTTPMethod method,
        const std::string &uri,
        const std::string &body,
        const MessageCategory category = MessageCategory::GENERIC,
        MessageMetadata message_metadata = MessageMetadata()
    ) = 0;

    virtual Maybe<void, HTTPResponse> downloadFile(
        const HTTPMethod method,
        const std::string &uri,
        const std::string &download_file_path,
        const MessageCategory category = MessageCategory::GENERIC,
        MessageMetadata message_metadata = MessageMetadata()
    ) = 0;

    virtual Maybe<void, HTTPResponse> uploadFile(
        const std::string & uri,
        const std::string & upload_file_path,
        const MessageCategory category = MessageCategory::GENERIC,
        MessageMetadata message_metadata = MessageMetadata()
    ) = 0;

    virtual bool setFogConnection(
        const std::string &host,
        uint16_t port,
        bool is_secure,
        MessageCategory category
    ) = 0;

    virtual bool setFogConnection(MessageCategory category = MessageCategory::GENERIC) = 0;

protected:
    virtual ~I_Messaging() {}
};

#include "messaging/interface_impl.h"

#endif // __I_MESSAGING_H__
