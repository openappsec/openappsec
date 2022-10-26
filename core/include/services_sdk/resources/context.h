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

#ifndef __CONTEXT_H__
#define __CONTEXT_H__

#include <typeinfo>
#include <typeindex>
#include <string>
#include <map>

#include "common.h"
#include "singleton.h"
#include "maybe_res.h"

USE_DEBUG_FLAG(D_ENVIRONMENT);

class I_Environment;

namespace EnvKeyAttr
{

// All attributes should start with `NONE`, which marks that the parameter doesn't have an attribute of that type.
// When filtering `NONE` means that we don't wish to filter by this attribute.

enum class LogSection { NONE, SOURCE, DATA, MARKER, SOURCEANDDATA };
enum class Verbosity { NONE, LOW, MEDIUM, HIGH };

} // EnvKeyAttr

#include "environment/param.h"

class Context : Singleton::Consume<I_Environment>
{
public:
    enum class MetaDataType {
        File,
        SubjectIpAddr,
        OtherIpAddr,
        Port,
        Protocol,
        Service,
        User,
        Domain,
        Url,
        Direction,
        Email,
        COUNT
    };

    enum class Error { NO_VALUE, NO_EVAL, WRONG_TYPE };
    template <typename T> using Return = Maybe<T, Error>;

private:
    class AbstractValue;

    template <typename T>
    class Value;

    class Key;

public:
    void activate();
    void deactivate();

    template <typename T, typename ... Attr>
    void registerValue(const std::string &name, const T &value, Attr ... attr);

    template <typename ... Params>
    void registerValue(MetaDataType name, Params ... params);

    template <typename T, typename ... Attr>
    void registerFunc(const std::string &name, std::function<T()> &&func, Attr ... attr);

    template <typename T, typename ... Attr>
    void registerFunc(const std::string &name, std::function<Return<T>()> &&func, Attr ... attr);

    template <typename T>
    void unregisterKey(const std::string &name);

    template <typename T>
    void unregisterKey(MetaDataType name);

    template <typename T>
    Return<T> get(const std::string &name) const;

    template <typename T>
    Return<T> get(MetaDataType name) const;

    std::map<std::string, std::string> getAllStrings(const EnvKeyAttr::ParamAttr &param) const;
    std::map<std::string, uint64_t> getAllUints(const EnvKeyAttr::ParamAttr &param) const;
    std::map<std::string, bool> getAllBools(const EnvKeyAttr::ParamAttr &param) const;

    static const std::string convertToString(MetaDataType type);

private:
    std::map<Key, std::unique_ptr<AbstractValue>> values;
};

class ScopedContext;

#include "environment/context_impl.h"

#endif // __CONTEXT_H__
