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

#pragma once

#include <unordered_map>
#include <unordered_set>
#include "WaapEnums.h"
#include "i_serialize.h"

class KeywordTypeValidator : public SerializeToFileBase
{
public:
    KeywordTypeValidator(const std::string& mapFilePath);
    ~KeywordTypeValidator();

    bool isKeywordOfType(const std::string& keyword, ParamType type) const;

    virtual void serialize(std::ostream& stream);
    virtual void deserialize(std::istream& stream);
    virtual void saveData();

private:
    std::unordered_map<std::string, std::unordered_set<ParamType>> m_keywordTypeMap;
};
