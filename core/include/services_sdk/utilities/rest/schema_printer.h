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

#ifndef __SCHEMA_PRINTER_H__
#define __SCHEMA_PRINTER_H__

#include "rest/rest_param.h"
#include "rest/rest_helper.h"

template <typename N>
class TypeDector
{
public:
    static void
    type(std::ostream &os, int level)
    {
        RestHelper::printIndent(os, level) << "\"type\": \"object\",\n";
        N obj;
        obj.performOutputingSchema(os, level);
        os << "\n";
    }
};

template <typename N>
class TypeDector<RestParam<N>>
{
};

template <>
class TypeDector<bool>
{
public:
    static void
    type(std::ostream &os, int level)
    {
        RestHelper::printIndent(os, level) << "\"type\": \"boolean\"\n";
    }
};

template <>
class TypeDector<std::string>
{
public:
    static void
    type(std::ostream &os, int level)
    {
        RestHelper::printIndent(os, level) << "\"type\": \"string\"\n";
    }
};

template <>
class TypeDector<int>
{
public:
    static void
    type(std::ostream &os, int level)
    {
        RestHelper::printIndent(os, level) << "\"type\": \"integer\"\n";
    }
};

template <>
class TypeDector<uint>
{
public:
    static void
    type(std::ostream &os, int level)
    {
        RestHelper::printIndent(os, level) << "\"type\": \"unsigned integer\"\n";
    }
};

template <typename N>
class TypeDector<std::map<std::string, N>>
{
public:
    static void
    type(std::ostream &os, int level)
    {
        RestHelper::printIndent(os, level) << "\"type\": \"object\",\n";
        RestHelper::printIndent(os, level) << "\"additionalProperties\": {\n";
        TypeDector<N>::type(os, level+1);
        RestHelper::printIndent(os, level) << "}\n";
    }
};

template <typename N>
class TypeDector<std::vector<N>>
{
public:
    static void
    type(std::ostream &os, int level)
    {
        RestHelper::printIndent(os, level) << "\"type\": \"array\",\n";
        RestHelper::printIndent(os, level) << "\"items\": {\n";
        TypeDector<N>::type(os, level+1);
        RestHelper::printIndent(os, level) << "}\n";
    }
};

template <typename N>
class TypeDector<std::set<N>>
{
public:
    static void
    type(std::ostream &os, int level)
    {
        RestHelper::printIndent(os, level) << "\"type\": \"array\",\n";
        RestHelper::printIndent(os, level) << "\"items\": {\n";
        TypeDector<N>::type(os, level+1);
        RestHelper::printIndent(os, level) << "}\n";
    }
};

template <typename N>
class SchemaPrinter
{
public:
    static void
    print(std::ostream &os, int level, std::string name)
    {
        RestHelper::printIndent(os, level) << "\"" << name << "\": {\n";
        TypeDector<N>::type(os, level+1);
        RestHelper::printIndent(os, level) << "}";
    }
};

#endif // __SCHEMA_PRINTER_H__
