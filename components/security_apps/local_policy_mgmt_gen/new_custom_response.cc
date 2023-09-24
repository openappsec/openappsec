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

#include "new_custom_response.h"

#define MIN_RESPONSE_CODE 100
#define MAX_RESPOMSE_CODE 599

using namespace std;

USE_DEBUG_FLAG(D_LOCAL_POLICY);
// LCOV_EXCL_START Reason: no test exist

static const set<string> valid_modes = {"block-page", "response-code-only", "redirect"};

void
NewAppSecCustomResponse::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec web user response spec";
    parseAppsecJSONKey<string>("appsecClassName", appsec_class_name, archive_in);
    parseAppsecJSONKey<int>("httpResponseCode", http_response_code, archive_in, 403);
    if (http_response_code < MIN_RESPONSE_CODE || http_response_code > MAX_RESPOMSE_CODE) {
        dbgWarning(D_LOCAL_POLICY) << "AppSec web user response code invalid: " << http_response_code;
    }
    parseAppsecJSONKey<string>("mode", mode, archive_in, "block-page");
    if (valid_modes.count(mode) == 0) {
        dbgWarning(D_LOCAL_POLICY) << "AppSec web user response mode invalid: " << mode;
    }
    parseAppsecJSONKey<string>("name", name, archive_in);
    parseAppsecJSONKey<string>("redirectUrl", redirect_url, archive_in);
    parseAppsecJSONKey<bool>("redirectAddXEventId", redirect_add_x_event_id, archive_in);
    if (mode == "block-page") {
        parseAppsecJSONKey<string>(
            "messageBody",
            message_body,
            archive_in,
            "Openappsec's <b>Application Security</b> has detected an attack and blocked it."
        );
        parseAppsecJSONKey<string>(
            "messageTitle",
            message_title,
            archive_in,
            "Attack blocked by web application protection"
        );
    }
}

void
NewAppSecCustomResponse::setName(const string &_name)
{
    name = _name;
}

int
NewAppSecCustomResponse::getHttpResponseCode() const
{
    return http_response_code;
}

const string &
NewAppSecCustomResponse::getMessageBody() const
{
    return message_body;
}

const string &
NewAppSecCustomResponse::getMessageTitle() const
{
    return message_title;
}

const string &
NewAppSecCustomResponse::getAppSecClassName() const
{
    return appsec_class_name;
}

const string &
NewAppSecCustomResponse::getMode() const
{
    return mode;
}

const string &
NewAppSecCustomResponse::getName() const
{
    return name;
}
// LCOV_EXCL_STOP
