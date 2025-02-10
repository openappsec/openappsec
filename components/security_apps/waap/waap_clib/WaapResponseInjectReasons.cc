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

#include "WaapResponseInjectReasons.h"
#include "debug.h"
#include <iostream>

USE_DEBUG_FLAG(D_WAAP);

namespace Waap {

ResponseInjectReasons::ResponseInjectReasons()
:
csrf(false),
antibot(false),
captcha(false),
securityHeaders(false)
{
}

void
ResponseInjectReasons::clear()
{
    dbgTrace(D_WAAP) << "ResponseInjectReasons::clear()";
    setCsrf(false);
    setAntibot(false);
    setSecurityHeaders(false);
}

bool
ResponseInjectReasons::shouldInject() const
{
    dbgTrace(D_WAAP) << "ResponseInjectReasons::shouldInject():" <<
    " AntiBot= " << antibot <<
    " CSRF= " << csrf <<
    " SecurityHeaders= " << securityHeaders;
    return csrf || antibot || securityHeaders;
}

void
ResponseInjectReasons::setAntibot(bool flag)
{
    dbgTrace(D_WAAP) << "Change ResponseInjectReasons(Antibot) " << antibot << " to " << flag;
    antibot = flag;
}

void
ResponseInjectReasons::setCaptcha(bool flag)
{
    dbgTrace(D_WAAP) << "Change ResponseInjectReasons(Captcha) " << captcha << " to " << flag;
    captcha = flag;
}

void
ResponseInjectReasons::setCsrf(bool flag)
{
    dbgTrace(D_WAAP) << "Change ResponseInjectReasons(CSRF) " << csrf << " to " << flag;
    csrf = flag;
}

void
ResponseInjectReasons::setSecurityHeaders(bool flag)
{
    dbgTrace(D_WAAP) << "Change ResponseInjectReasons(Security Headers) " << securityHeaders << " to " << flag;
    securityHeaders = flag;
}

bool
ResponseInjectReasons::shouldInjectAntibot() const
{
    dbgTrace(D_WAAP) << "shouldInjectAntibot():: " << antibot;
    return antibot;
}

bool
ResponseInjectReasons::shouldInjectCaptcha() const
{
    dbgTrace(D_WAAP) << "shouldInjectCaptcha():: " << captcha;
    return captcha;
}

bool
ResponseInjectReasons::shouldInjectCsrf() const
{
    dbgTrace(D_WAAP) << "shouldInjectCsrf():: " << csrf;
    return csrf;
}

bool
ResponseInjectReasons::shouldInjectSecurityHeaders() const
{
    dbgTrace(D_WAAP) << "shouldInjectSecurityHeaders():: " << securityHeaders;
    return securityHeaders;
}

}
