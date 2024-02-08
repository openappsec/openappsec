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

#ifndef __INTELLIGENCE_SERVER_H__
#define __INTELLIGENCE_SERVER_H__

#include <vector>
#include "maybe_res.h"

#include "i_messaging.h"
#include "intelligence_is_v2/intelligence_response.h"
#include "intelligence_request.h"

namespace Intelligence {

class Sender
{
public:
    Sender(IntelligenceRequest request);
    Maybe<Response> sendIntelligenceRequest();

private:
    Maybe<Response> sendQueryObjectToLocalServer(bool is_primary_port);
    Maybe<Response> sendQueryMessage();
    Maybe<Response> sendMessage();
    Maybe<Response> createResponse();

    IntelligenceRequest request;
    Flags<MessageConnectionConfig> conn_flags;
    bool is_local_intelligence;
    Maybe<std::string> server_ip = genError("No server ip set");
    Maybe<unsigned int> server_port = genError("No port is set");
    I_Messaging * i_message = nullptr;
    I_TimeGet * i_timer = nullptr;
    I_MainLoop * i_mainloop = nullptr;
};

}

#endif // __INTELLIGENCE_SERVER_H__
