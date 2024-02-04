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

#ifndef __READ_ATTRIBUTE_V2_H__
#define __READ_ATTRIBUTE_V2_H__

#include "intelligence_is_v2/data_string_v2.h"
#include "intelligence_is_v2/data_map_v2.h"

template <typename UserSerializableReply>
class ReadAttribute
{
public:
    ReadAttribute(const std::string &_key, UserSerializableReply &_data);

    template <typename Archive> void serialize(Archive &ar);

    UserSerializableReply getData() const;

private:
    std::string key = "";
    UserSerializableReply &data;
};

#include "intelligence_is_v2/read_attribute_v2_impl.h"

#endif //__READ_ATTRIBUTE_V2_H__
