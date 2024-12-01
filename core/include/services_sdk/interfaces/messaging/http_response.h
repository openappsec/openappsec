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

#ifndef __HTTP_RESPONSE_H__
#define __HTTP_RESPONSE_H__

#include <string>
#include <map>
#include <cereal/archives/json.hpp>

#include "singleton.h"
#include "i_env_details.h"
#include "i_agent_details.h"
#include "i_encryptor.h"
#include "messaging/messaging_enums.h"

class HTTPResponse
{
public:
// LCOV_EXCL_START Reason: Not actually called but is required by the caching interface
    HTTPResponse() = default;
// LCOV_EXCL_STOP

    HTTPResponse(
        HTTPStatusCode _status_code,
        const std::string &_body,
        std::unordered_map<std::string, std::string> _headers = std::unordered_map<std::string, std::string>()
    )
            :
        status_code(_status_code),
        body(_body),
        headers(_headers)
    {}

    HTTPStatusCode getHTTPStatusCode() const;
    const std::string & getBody() const;
    std::string toString() const;
    Maybe<std::string> getHeaderVal(const std::string &header_key);

private:
    HTTPStatusCode status_code;
    std::string body;
    std::unordered_map<std::string, std::string> headers;
};

#endif // __HTTP_RESPONSE_H__
