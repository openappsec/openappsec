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

#include "Csrf.h"
#include <algorithm>
#include <boost/uuid/uuid.hpp>            // uuid class
#include <boost/uuid/uuid_generators.hpp> // uuid generators
#include <boost/uuid/uuid_io.hpp>

namespace Waap {

namespace CSRF {

State::State()
:
csrf_token(),
csrf_header_token(),
csrf_form_token()
{
}

bool
State::decide
    (const std::string &method, WaapDecision &decision, const std::shared_ptr<Waap::Csrf::Policy>& csrfPolicy) const
{
    dbgTrace(D_WAAP) << "Waap::CSRF::State::decide(): Start.";

    std::string low_method = method;
    std::transform(low_method.begin(), low_method.end(), low_method.begin(), ::tolower);

    if (low_method.compare("get") == 0)
    {
        dbgTrace(D_WAAP) << "Waap::CSRF::State::decide(): Should not block. Method : " << low_method;
        return false;
    }

    auto csrfDecision = decision.getDecision(CSRF_DECISION);
    if (csrf_token.empty())
    {
        dbgTrace(D_WAAP) << "Waap::CSRF::State::decide(): missing token.";
        csrfDecision->setLog(true);
        if(!csrfPolicy->enforce) {
            return false;
        }
        csrfDecision->setBlock(true);
        return true;
    }

    dbgTrace(D_WAAP) << "Waap::CSRF::State::decide(): CSRF compare: csrf_token: " << csrf_token
        << " csrf_header_token: " << csrf_header_token << " csrf_form_token: " << csrf_form_token;

    bool result = (csrf_token == csrf_header_token ||
        csrf_token == csrf_form_token);

    dbgTrace(D_WAAP) << "Waap::CSRF::State::decide(): CSRF result : " << result;

    if(!result)
    {
        dbgTrace(D_WAAP) << "Waap::CSRF::State::decide(): invalid token.";
        csrfDecision->setLog(true);
        if(!csrfPolicy->enforce) {
            return false;
        }
        csrfDecision->setBlock(true);
        return true;
    }
    return false;

}

void State::injectCookieHeader(std::string& injectStr) const
{
    // creating CSRF token
    boost::uuids::random_generator csrfTokenRand;
    boost::uuids::uuid csrfToken = csrfTokenRand();
    injectStr = "x-chkp-csrf-token=" + boost::uuids::to_string(csrfToken) + "; Path=/; SameSite=Lax";
    dbgTrace(D_WAAP) << "Waap::CSRF::State::injectCookieHeader(): CSRF Token was created:" <<
        boost::uuids::to_string(csrfToken);
}

void
State::set_CsrfToken(const char* v, size_t v_len)
{
    csrf_token = std::string(v, v_len);
    dbgTrace(D_WAAP) << "Waap::CSRF::State::set_CsrfToken(): set csrf_token : " << csrf_token;
}
void
State::set_CsrfHeaderToken(const char* v, size_t v_len)
{
    csrf_header_token = std::string(v, v_len);
    dbgTrace(D_WAAP) << "Waap::CSRF::State::set_CsrfHeaderToken(): set csrf_token : " << csrf_header_token;
}
void
State::set_CsrfFormToken(const char* v, size_t v_len)
{
    csrf_form_token = std::string(v, v_len);
    dbgTrace(D_WAAP) << "Waap::CSRF::State::set_CsrfFormToken(): set csrf_form_token : " << csrf_form_token;
}

}
}
