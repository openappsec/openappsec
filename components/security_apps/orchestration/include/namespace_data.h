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

#ifndef __NAMESPACE_DATA_H__
#define __NAMESPACE_DATA_H__

#include <vector>
#include <map>

#include "cereal/archives/json.hpp"
#include <cereal/types/map.hpp>

#include "rest.h"

class NamespaceData : public ClientRest
{
public:
    bool loadJson(const std::string &json);
    Maybe<std::string> getNamespaceUidByName(const std::string &name);

private:
    std::map<std::string, std::string> ns_name_to_uid;
};

#endif // __NAMESPACE_DATA_H__
