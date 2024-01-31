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

#include "buffered_message.h"
#include "customized_cereal_map.h"

using namespace std;

static const std::map<std::string, MessageCategory> string_to_category = {
    {"generic",       MessageCategory::GENERIC     },
    { "log",          MessageCategory::LOG         },
    { "debug",        MessageCategory::DEBUG       },
    { "metric",       MessageCategory::METRIC      },
    { "intelligence", MessageCategory::INTELLIGENCE}
};

static const std::map<MessageCategory, std::string> category_to_string = {
    {MessageCategory::GENERIC,       "generic"     },
    { MessageCategory::LOG,          "log"         },
    { MessageCategory::DEBUG,        "debug"       },
    { MessageCategory::METRIC,       "metric"      },
    { MessageCategory::INTELLIGENCE, "intelligence"}
};

static const std::map<std::string, HTTPMethod> string_to_method = {
    {"get",      HTTPMethod::GET    },
    { "post",    HTTPMethod::POST   },
    { "patch",   HTTPMethod::PATCH  },
    { "connect", HTTPMethod::CONNECT},
    { "put",     HTTPMethod::PUT    }
};

static const std::map<HTTPMethod, std::string> method_to_string = {
    {HTTPMethod::GET,      "get"    },
    { HTTPMethod::POST,    "post"   },
    { HTTPMethod::PATCH,   "patch"  },
    { HTTPMethod::CONNECT, "connect"},
    { HTTPMethod::PUT,     "put"    }
};

void
BufferedMessage::save(cereal::JSONOutputArchive &out_ar) const
{
    string category_str = category_to_string.find(category)->second;
    string method_str = method_to_string.find(method)->second;

    out_ar(
        cereal::make_nvp("body", body),
        cereal::make_nvp("uri", uri),
        cereal::make_nvp("method", method_str),
        cereal::make_nvp("category", category_str),
        cereal::make_nvp("message_metadata", message_metadata)
    );
}

void
BufferedMessage::load(cereal::JSONInputArchive &archive_in)
{
    string method_str;
    string category_str;
    archive_in(
        cereal::make_nvp("body", body),
        cereal::make_nvp("uri", uri),
        cereal::make_nvp("method", method_str),
        cereal::make_nvp("category", category_str),
        cereal::make_nvp("message_metadata", message_metadata)
    );
    method = string_to_method.find(method_str)->second;
    category = string_to_category.find(category_str)->second;
}

string
BufferedMessage::toString() const
{
    stringstream ss;
    {
        cereal::JSONOutputArchive ar(ss);
        save(ar);
    }

    return ss.str();
}

bool
BufferedMessage::operator==(const BufferedMessage &other) const
{
    return body == other.body && uri == other.uri;
}

const string &
BufferedMessage::getBody() const
{
    return body;
}

const string &
BufferedMessage::getURI() const
{
    return uri;
}

HTTPMethod
BufferedMessage::getMethod() const
{
    return method;
}

MessageCategory
BufferedMessage::getCategory() const
{
    return category;
}

const MessageMetadata &
BufferedMessage::getMessageMetadata() const
{
    return message_metadata;
}
