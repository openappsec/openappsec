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

#ifndef __MESSAGNIG_COMP_H__
#define __MESSAGNIG_COMP_H__

#include "messaging.h"

#include <fstream>
#include <map>
#include <ostream>
#include <sstream>
#include <string>

#include "cache.h"
#include "connection.h"
#include "connection_comp.h"
#include "flags.h"
#include "interfaces/i_messaging_buffer.h"
#include "interfaces/i_messaging_connection.h"
#include "maybe_res.h"
#include "messaging_buffer.h"
#include "singleton.h"

class MessagingComp
{
public:
    void init();

    Maybe<HTTPResponse, HTTPResponse> sendSyncMessage(
        HTTPMethod method,
        const std::string &uri,
        const std::string &body,
        MessageCategory category,
        const MessageMetadata &message_metadata
    );

    void sendAsyncMessage(
        HTTPMethod method,
        const std::string &uri,
        const std::string &body,
        MessageCategory category,
        const MessageMetadata &message_metadata,
        bool force_buffering = true
    );

    Maybe<HTTPStatusCode, HTTPResponse> downloadFile(
        HTTPMethod method,
        const std::string &uri,
        const std::string &download_file_path,
        MessageCategory category = MessageCategory::GENERIC,
        const MessageMetadata &message_metadata = MessageMetadata()
    );

    Maybe<HTTPStatusCode, HTTPResponse> uploadFile(
        const std::string &uri,
        const std::string &upload_file_path,
        MessageCategory category,
        const MessageMetadata &message_metadata
    );

    bool setFogConnection(const std::string &host, uint16_t port, bool is_secure, MessageCategory category);
    bool setFogConnection(MessageCategory category);

private:
    Maybe<Connection> getConnection(MessageCategory category, const MessageMetadata &message_metadata);
    Maybe<Connection> getPersistentConnection(const MessageMetadata &metadata, MessageCategory category) const;

    Maybe<HTTPResponse, HTTPResponse> sendMessage(
        HTTPMethod method,
        const std::string &uri,
        const std::string &body,
        MessageCategory category,
        const MessageMetadata &message_metadata
    );

    Maybe<HTTPResponse, HTTPResponse> suspendMessage(
        const std::string &body,
        HTTPMethod method,
        const std::string &uri,
        MessageCategory category,
        const MessageMetadata &message_metadata
    ) const;

    I_MessagingConnection *i_conn;
    I_MessageBuffer *i_messaging_buffer;
    I_AgentDetails *agent_details;
    bool should_buffer_failed_messages;
    TemporaryCache<std::string, HTTPResponse> fog_get_requests_cache;
};

#endif //__MESSAGNIG_COMP_H__
