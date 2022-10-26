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

#include "KeywordTypeValidator.h"
#include <cereal/archives/json.hpp>
#include <cereal/types/unordered_map.hpp>
#include <cereal/types/unordered_set.hpp>
#include "debug.h"
#include "Waf2Util.h"

USE_DEBUG_FLAG(D_WAAP);

KeywordTypeValidator::KeywordTypeValidator(const std::string& mapFilePath) :
    SerializeToFileBase(mapFilePath),
    m_keywordTypeMap()
{
    restore();
}

KeywordTypeValidator::~KeywordTypeValidator()
{

}

void KeywordTypeValidator::serialize(std::ostream& stream)
{
    (void)stream;
}

void KeywordTypeValidator::saveData()
{
    // do not override existing file
}

void KeywordTypeValidator::deserialize(std::istream& stream)
{
    cereal::JSONInputArchive archive(stream);

    std::unordered_map<std::string, std::unordered_set<std::string>> typesStrToKeysMap;

    archive(cereal::make_nvp("keywordsTypeMap", typesStrToKeysMap));

    for (auto typeStrItr : typesStrToKeysMap)
    {
        ParamType type = Waap::Util::convertTypeStrToEnum(typeStrItr.first);
        for (auto keyword : typeStrItr.second)
        {
            if (m_keywordTypeMap.find(keyword) == m_keywordTypeMap.end())
            {
                // initialize type set
                m_keywordTypeMap[keyword];
            }
            m_keywordTypeMap[keyword].insert(type);
        }
    }
}

bool KeywordTypeValidator::isKeywordOfType(const std::string& keyword, ParamType type) const
{
    auto keywordEntry = m_keywordTypeMap.find(keyword);
    if (keywordEntry != m_keywordTypeMap.end())
    {
        auto &typeSet = keywordEntry->second;
        return (typeSet.count(type) != 0);
    }
    else
    {
        dbgTrace(D_WAAP) << "keyword: " << keyword << " not found";
    }
    return false;
}
