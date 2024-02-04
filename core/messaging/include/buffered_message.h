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

#ifndef __BUFFERED_MESSAGE_H__
#define __BUFFERED_MESSAGE_H__

#include <iostream>
#include <sstream>
#include <string>

#include "i_messaging.h"

#include "cereal/archives/json.hpp"
#include "cereal/types/string.hpp"
#include "maybe_res.h"

class BufferedMessage
{
public:
    BufferedMessage() {}

    BufferedMessage(
        std::string _body,
        HTTPMethod _method,
        std::string _uri,
        MessageCategory _category,
        MessageMetadata _message_metadata
    ) :
        body(_body), method(_method), uri(_uri), category(_category), message_metadata(_message_metadata)
    {}

    void save(cereal::JSONOutputArchive &out_ar) const;
    void load(cereal::JSONInputArchive &archive_in);

    std::string toString() const;
    bool operator==(const BufferedMessage &other) const;

    const std::string &getBody() const;
    const std::string &getURI() const;
    HTTPMethod getMethod() const;
    MessageCategory getCategory() const;
    const MessageMetadata &getMessageMetadata() const;

private:
    std::string body;
    HTTPMethod method;
    std::string uri;
    MessageCategory category;
    MessageMetadata message_metadata;
    uint16_t retries_number = 0;
};

#endif // __BUFFERED_MESSAGE_H__
