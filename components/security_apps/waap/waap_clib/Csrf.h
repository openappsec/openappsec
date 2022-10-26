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

#pragma once
#include "debug.h"
#include "WaapDecision.h"
#include "i_waapConfig.h"
#include <iostream>
#include <string>

USE_DEBUG_FLAG(D_WAAP);


namespace Waap {

namespace CSRF {

    class State
    {
    public:
        State();
        bool decide(
            const std::string &method,
            WaapDecision &decision,
            const std::shared_ptr<Waap::Csrf::Policy>& csrfPolicy) const;
        void injectCookieHeader(std::string& injectStr) const;
        void set_CsrfToken(const char* v, size_t v_len);
        void set_CsrfHeaderToken(const char* v, size_t v_len);
        void set_CsrfFormToken(const char* v, size_t v_len);
    private:
        std::string csrf_token;
        std::string csrf_header_token;
        std::string csrf_form_token;
    };

}
}
