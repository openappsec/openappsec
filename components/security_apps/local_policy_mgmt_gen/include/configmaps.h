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

#ifndef __CONFIGMAPS_H__
#define __CONFIGMAPS_H__

#include <vector>
#include <map>

#include "config.h"
#include "debug.h"
#include "rest.h"
#include "cereal/archives/json.hpp"
#include <cereal/types/map.hpp>
#include "customized_cereal_map.h"

#include "local_policy_common.h"

class ConfigMaps : public ClientRest
{
public:
    bool loadJson(const std::string &json);

    std::string getFileContent() const;
    std::string getFileName() const;

private:
    std::map<std::string, std::string> data;
};

#endif // __CONFIGMAPS_H__
