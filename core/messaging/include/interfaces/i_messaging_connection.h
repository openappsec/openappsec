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

#ifndef __I_MESSAGING_CONNECTION_H__
#define __I_MESSAGING_CONNECTION_H__

#include <map>
#include <string>

#include "http_request.h"
#include "i_messaging.h"

#include "connection.h"
#include "maybe_res.h"

class I_MessagingConnection
{
public:
    virtual Maybe<Connection> establishConnection(const MessageMetadata &metadata, MessageCategory category) = 0;

    virtual Maybe<Connection> getPersistentConnection(
        const std::string &host_name, uint16_t port, MessageCategory category
    ) = 0;

    virtual Maybe<Connection> getFogConnectionByCategory(MessageCategory category) = 0;
    virtual Maybe<HTTPResponse, HTTPResponse> sendRequest(Connection &connection, HTTPRequest request) = 0;

protected:
    virtual ~I_MessagingConnection() {}
};

#endif // __I_MESSAGING_CONNECTION_H__
