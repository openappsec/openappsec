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

#include <sstream>
#include <iostream>
#include <map>

#include "cereal/types/common.hpp"
#include "cereal/types/string.hpp"
#include "cereal/types/vector.hpp"
#include "cereal/archives/json.hpp"

#include "rest/schema_printer.h"

template <typename ... Types>
class SerializableMultiMap : std::map<std::string, Types> ...
{
public:
    template <typename Archive>
    void
    load(Archive &archive)
    {
        clear();

        while (true) {
            const auto node_name = archive.getNodeName();

            if (!node_name) break;

            std::string key = node_name;
            load(key, archive, Types()...);
        }
    }

    void clear() { clear(Types()...); }

    template <typename T>
    std::map<std::string, T> &
    getMap()
    {
        return static_cast<std::map<std::string, T> &>(*this);
    }

    void
    performOutputingSchema(std::ostream &out, int level)
    {
        RestHelper::printIndent(out, level) << "\"additionalProperties\": {\n";
        RestHelper::printIndent(out, level + 1) << "\"anyOf\": [";
        printTypes<Types...>(out, level +2, 0);
        out << '\n';
        RestHelper::printIndent(out, level + 1) << "]\n";
        RestHelper::printIndent(out, level) << "}";
    }

private:
    template <typename Archive, typename T, typename ... More>
    void
    load(const std::string &key, Archive &archive, T t, More ... more)
    {
        try {
            load(key, archive, t);
        } catch(...) {
            load(key, archive, more ...);
        }
    }

    template <typename Archive, typename T>
    void
    load(const std::string &key, Archive &archive, T t)
    {
        archive(t);
        std::map<std::string, T>::operator[](key) = t;
    }

    template <typename T, typename ... More>
    void clear(const T &t, const More & ... more) { clear(t); clear(more...); }

    template <typename T>
    void clear(const T &) { std::map<std::string, T>::clear(); }

    template <typename T, typename ... More>
    void
    printTypes(std::ostream &out, int level, uint)
    {
        printTypes<T>(out, level, 0);
        out << ",";
        printTypes<More...>(out, level, 0);
    }

    template <typename T>
    void
    printTypes(std::ostream &out, int level, int)
    {
        out << '\n';
        RestHelper::printIndent(out, level) << "{\n";
        TypeDector<T>::type(out, level + 1);
        RestHelper::printIndent(out, level) << "}";
    }

};
