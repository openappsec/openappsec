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

#ifndef __ASSET_H__
#define __ASSET_H__

#include <unordered_map>

#include "i_environment.h"

class Asset
{
public:
    const std::map<Context::MetaDataType, std::string> & getAttrs() const { return attr; }
    void setAttr(Context::MetaDataType type, const std::string &attr_val) { attr[type] = attr_val; }

private:
    std::map<Context::MetaDataType, std::string> attr;
};

#endif // __ASSET_H__
