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

#ifndef __NEW_CUSTOM_RESPONSE_H__
#define __NEW_CUSTOM_RESPONSE_H__

#include <string>
#include <cereal/archives/json.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "config.h"
#include "debug.h"
#include "local_policy_common.h"

class NewAppSecCustomResponse
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    int getHttpResponseCode() const;
    const std::string & getMessageBody() const;
    const std::string & getMessageTitle() const;
    const std::string & getAppSecClassName() const;
    const std::string & getMode() const;
    const std::string & getName() const;
    void setName(const std::string &_name);

private:
    bool            redirect_add_x_event_id;
    int             http_response_code;
    std::string     appsec_class_name;
    std::string     redirect_url;
    std::string     message_title;
    std::string     message_body;
    std::string     mode;
    std::string     name;
};

#endif // __NEW_CUSTOM_RESPONSE_H__
