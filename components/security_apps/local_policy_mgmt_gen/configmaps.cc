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

#include "configmaps.h"

using namespace std;

USE_DEBUG_FLAG(D_LOCAL_POLICY);

// LCOV_EXCL_START Reason: no test exist
bool
ConfigMaps::loadJson(const std::string &json)
{
    string modified_json = json;
    modified_json.pop_back();
    stringstream in;
    in.str(modified_json);
    dbgTrace(D_LOCAL_POLICY) << "Loading ConfigMaps data";
    try {
        cereal::JSONInputArchive in_ar(in);
        in_ar(
            cereal::make_nvp("data", data)
        );
    } catch (cereal::Exception &e) {
        dbgError(D_LOCAL_POLICY) << "Failed to load ConfigMaps JSON. Error: " << e.what();
        return false;
    }
    return true;
}

string
ConfigMaps::getFileContent() const
{
    if (data.size()) {
        return data.begin()->second;
    }
    return string();
}

string
ConfigMaps::getFileName() const
{
    if (data.size()) {
        return data.begin()->first;
    }
    return string();
}
// LCOV_EXCL_STOP
