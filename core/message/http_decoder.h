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

#ifndef __HTTP_DECODDER_H__
#define __HTTP_DECODDER_H__

#include <string>

#include "singleton.h"
#include "maybe_res.h"
#include "messaging/http_core.h"
#include "i_message_decoder.h"
#include "i_messaging.h"
#include "i_env_details.h"

class HTTPDecoder
        :
    public I_MessageDecoder <HTTPResponse>,
    Singleton::Consume<I_EnvDetails>
{
public:
    HTTPDecoder(I_Messaging::Method _method);

    Maybe<HTTPResponse> decodeBytes(const std::string &data) override;

private:
    Maybe<HTTPHeaders> handleHeaders();
    Maybe<HTTPStatusCode> parseStatusLine();
    bool handleBody();

    bool getChunkedResponse();
    bool isLegalChunkedResponse(const std::string &res);

    I_Messaging::Method method;
    bool connection_is_closed = false;

    Maybe<HTTPStatusCode> status_code;
    Maybe<HTTPHeaders> headers;
    std::string response;
    std::string body;
    size_t body_size = 0;
};

#endif // __HTTP_DECODDER_H__
