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

#ifndef __I_MESSAGING_BUFFER_H__
#define __I_MESSAGING_BUFFER_H__

#include <iostream>
#include <sstream>
#include <string>

#include "i_messaging.h"

#include "../buffered_message.h"
#include "cereal/archives/json.hpp"
#include "cereal/types/string.hpp"
#include "maybe_res.h"

class I_MessageBuffer
{
public:
    virtual void pushNewBufferedMessage(
        const std::string &body,
        HTTPMethod method,
        const std::string &uri,
        MessageCategory category,
        MessageMetadata message_metadata,
        bool force_immediate_writing
    ) = 0;

    virtual Maybe<BufferedMessage> peekMessage() = 0;
    virtual void popMessage() = 0;
    virtual void cleanBuffer() = 0;
};

#endif // __I_MESSAGING_BUFFER_H__
