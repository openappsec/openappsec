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

#ifndef __GENERIC_RULEBASE_UTILS_H__
#define __GENERIC_RULEBASE_UTILS_H__

#include <string>

#include "debug.h"
#include "cereal/archives/json.hpp"

USE_DEBUG_FLAG(D_RULEBASE_CONFIG);

template <typename T>
void
parseJSONKey(const std::string &key_name, T &value, cereal::JSONInputArchive &archive_in)
{
    try {
        archive_in(cereal::make_nvp(key_name, value));
    } catch (const cereal::Exception &e) {
        dbgDebug(D_RULEBASE_CONFIG)
            << "Could not parse the required key. Key: "
            << key_name
            << ", Error: "
            << e.what();
    }
}

#endif //__GENERIC_RULEBASE_UTILS_H__
