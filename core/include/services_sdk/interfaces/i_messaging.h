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

#ifndef __I_FOG_MESSAGING_H__
#define __I_FOG_MESSAGING_H__

#include <string>
#include <sstream>
#include <fstream>
#include <functional>

#include "cereal/archives/json.hpp"
#include "cereal/types/common.hpp"
#include "cereal/types/string.hpp"
#include "cereal/types/vector.hpp"

#include "maybe_res.h"
#include "debug.h"
#include "messaging/http_core.h"
#include "flags.h"

USE_DEBUG_FLAG(D_COMMUNICATION);

enum class MessageTypeTag
{
    GENERIC,
    LOG,
    DEBUG,
    METRIC,
    REPORT,
    WAAP_LEARNING,
    INTELLIGENCE,
    BUFFERED_MESSAGES,

    COUNT
};

enum class MessageConnConfig
{
    SECURE_CONN,
    ONE_TIME_CONN,
    EXPECT_REPLY,
    EXTERNAL,
    IGNORE_SSL_VALIDATION,

    COUNT
};

class I_Messaging
{
public:
    using string = std::string;
    using ErrorCB = std::function<void(HTTPStatusCode)>;

    enum class Method { GET, POST, PATCH, CONNECT, PUT };

    template <typename T, typename ...Args>
    bool
    sendObject(T &obj, Args ...args)
    {
        auto req = obj.genJson();
        if (!req.ok()) {
            dbgWarning(D_COMMUNICATION) << "Failed to create a request. Error: " << req.getErr();
            return false;
        }

        dbgTrace(D_COMMUNICATION) << "Request generated from json. Request: " << req.unpack();
        auto res = sendMessage(true, *req, args...);
        if (!res.ok()) {
            dbgWarning(D_COMMUNICATION) << "Failed to send request. Error: " << res.getErr();
            return false;
        }
        dbgTrace(D_COMMUNICATION) << "Successfully got response: " << res.unpack();


        auto res_json = obj.loadJson(res.unpack());
        if (!res_json) {
            dbgWarning(D_COMMUNICATION) << "Failed to parse response body. Content: " << res.unpack();
        } else {
            dbgTrace(D_COMMUNICATION) << "Successfully parsed response body";
        }
        return res_json;
    }

    template <typename T, typename ...Args>
    bool
    sendNoReplyObject(T &obj, Args ...args)
    {
        auto req = obj.genJson();
        if (!req.ok()) {
            dbgWarning(D_COMMUNICATION) << "Failed to create a request. Error: " << req.getErr();;
            return false;
        }

        auto res = sendMessage(false, *req, args...);
        if (!res.ok()) {
            dbgWarning(D_COMMUNICATION) << "Failed to send request. Error: " << res.getErr();
        }
        return res.ok();
    }

    template <typename T, typename ...Args>
    void
    sendObjectWithPersistence(T &obj, Args ...args)
    {
        auto req = obj.genJson();
        if (!req.ok()) {
            dbgWarning(D_COMMUNICATION) << "Failed to create a request. Error: " << req.getErr();;
            return;
        }

        sendPersistentMessage(false, req.unpackMove(), args...);
    }

    template <typename T, typename ...Args>
    Maybe<string>
    downloadFile(T &obj, Args ...args)
    {
        auto req = obj.genJson();
        if (!req.ok()) return genError("Invalid request");
        auto response = sendMessage(true, *req, args...);
        if (response.ok()) {
            return response.unpack();
        }
        return genError("Failed to download file. Error: " + response.getErr());
    }

    virtual bool setActiveFog(MessageTypeTag tag)                                                          = 0;
    virtual bool setActiveFog(const string &host, const uint16_t port, bool is_secure, MessageTypeTag tag) = 0;

protected:
    ~I_Messaging() {}

private:
    virtual Maybe<string>
    sendPersistentMessage(
        bool get_reply,
        const string &&body,
        Method method,
        const string &uri,
        const string &headers = "",
        bool should_yield = true,
        MessageTypeTag tag = MessageTypeTag::GENERIC,
        bool skip_sending = false) = 0;

    virtual Maybe<string>
    sendMessage(
        bool get_reply,
        const string &body,
        Method method,
        const string &uri,
        const string &headers = "",
        ErrorCB err_call_back = nullptr,
        bool should_yield = true,
        MessageTypeTag tag = MessageTypeTag::GENERIC) = 0;

    virtual Maybe<string>
    sendMessage(
        bool get_reply,
        const string &body,
        Method method,
        const std::string &host,
        uint16_t port,
        Flags<MessageConnConfig> &conn_flags,
        const string &uri,
        const string &headers = "",
        ErrorCB err_call_back = nullptr,
        MessageTypeTag tag = MessageTypeTag::GENERIC) = 0;
};

#endif // __I_FOG_MESSAGING_H__
