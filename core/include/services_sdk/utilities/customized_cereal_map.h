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

#ifndef __CUSTOMIZED_CEREAL_MAP_H__
#define __CUSTOMIZED_CEREAL_MAP_H__

#include <string>
#include <map>
#include <cereal/archives/json.hpp>

namespace cereal
{
    template <
        class Archive,
        class Value,
        class C,
        class A,
        traits::EnableIf<traits::is_text_archive<Archive>::value> = traits::sfinae
    >
    inline void
    save(Archive &archive, std::map<std::string, Value, C, A> const &map)
    {
        for (const auto &pair : map) {
            archive(cereal::make_nvp(pair.first, pair.second));
        }
    }

    template <
        class Archive,
        class Value,
        class C,
        class A,
        traits::EnableIf<traits::is_text_archive<Archive>::value> = traits::sfinae
    >
    inline void
    load(Archive &archive, std::map<std::string, Value, C, A> &map)
    {
        map.clear();
        auto hint = map.begin();

        while (true) {
            const auto node_name = archive.getNodeName();
            if (!node_name) break;

            std::string key = node_name;
            Value value;
            archive(value);
            hint = map.emplace_hint(hint, std::move(key), std::move(value));
        }
    }

} // namespace cereal

#endif //__CUSTOMIZED_CEREAL_MAP_H__
