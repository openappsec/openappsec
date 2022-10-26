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

#include "messaging_buffer/http_request_event.h"
#include "maybe_res.h"

class I_MessagingBuffer
{
public:
    virtual Maybe<HTTPRequestEvent> peekRequest() = 0;
    virtual void popRequest() = 0;
    virtual void bufferNewRequest(const HTTPRequestEvent &request, bool is_rejected = false) = 0;
    virtual bool isPending(const HTTPRequestSignature &request) = 0;
    virtual void cleanBuffer() = 0;

protected:
    ~I_MessagingBuffer() {}
};

#endif // __I_MESSAGING_BUFFER_H__
