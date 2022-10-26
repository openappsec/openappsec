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
#error "context_impl.h should not be included directly"
#endif // __CONTEXT_H__

#include <limits>
#include <sstream>

#include "debug.h"

USE_DEBUG_FLAG(D_ENVIRONMENT);

class Context::AbstractValue
{
public:
    virtual ~AbstractValue() {}
    virtual Return<uint64_t>    getUint()   const = 0;
    virtual Return<bool>        getBool()   const = 0;
    virtual Return<std::string> getString() const = 0;
};

template <typename T>
class Context::Value : public Context::AbstractValue
{
    template <bool B> class MatchCond {};

public:
    Value(std::function<Return<T>()> &&f) : value_getter(std::move(f)) {}

    Return<T> get() const { return value_getter(); }

    Return<std::string> getString() const override { return getString(MatchCond<isString()>()); }
    Return<bool>        getBool()   const override { return getBool(MatchCond<isBool()>()); }
    Return<uint64_t>    getUint()   const override { return getUint(MatchCond<isUint()>()); }

private:
    static constexpr bool isUint()   { return std::numeric_limits<T>::is_integer && !std::is_same<T, bool>::value; }
    Return<uint64_t>    getUint(MatchCond<false>) const { return genError(Error::WRONG_TYPE); }
    Return<uint64_t>    getUint(MatchCond<true>)  const { return get(); }

    static constexpr bool isBool()   { return std::is_same<T, bool>::value; }
    Return<bool>        getBool(MatchCond<false>) const { return genError(Error::WRONG_TYPE); }
    Return<bool>        getBool(MatchCond<true>)  const { return get(); }

    static constexpr bool isString() { return std::IsPrintable<T>() && !std::numeric_limits<T>::is_integer; }
    Return<std::string> getString(MatchCond<false>) const { return genError(Error::WRONG_TYPE); }

    Return<std::string>
    getString(MatchCond<true>) const
    {
        auto val = get();
        if (!val.ok()) return val.passErr();

        return getString(MatchCond<std::is_convertible<T, std::string>::value>(), *val);
    }

    std::string
    getString(MatchCond<true>, const T &val) const
    {
        return static_cast<std::string>(val);
    }

    std::string
    getString(MatchCond<false>, const T &val) const
    {
        std::stringstream output;
        output << val;
        return output.str();
    }

    std::function<Return<T>()> value_getter;
};

class Context::Key : public std::pair<std::string, std::type_index>
{
public:
    Key(const std::string &name, const std::type_index &type) : Key(name, type, EnvKeyAttr::ParamAttr()) {}

    Key(const std::string &name, const std::type_index &type, const EnvKeyAttr::ParamAttr &_params)
            :
        std::pair<std::string, std::type_index>(name, type),
        params(_params)
    {
    }

    bool doesMatch(const EnvKeyAttr::ParamAttr &param) const { return params.doesMatch(param); }

private:
    EnvKeyAttr::ParamAttr params;
};

template <typename T, typename ... Attr>
void
Context::registerValue(const std::string &name, const T &value, Attr ... attr)
{
    std::function<Return<T>()> new_func = [value] () { return Return<T>(value); };
    registerFunc(name, std::move(new_func), attr ...);
}

template <typename ... Params>
void
Context::registerValue(MetaDataType name, Params ... params)
{
    return registerValue(convertToString(name), params ...);
}

template <typename T, typename ... Attr>
void
Context::registerFunc(const std::string &name, std::function<T()> &&func, Attr ... attr)
{
    std::function<Return<T>()> new_func = [func] () { return Return<T>(func()); };
    registerFunc(name, std::move(new_func), attr ...);
}

template <typename T, typename ... Attr>
void
Context::registerFunc(const std::string &name, std::function<Return<T>()> &&func, Attr ... attr)
{
    dbgTrace(D_ENVIRONMENT) << "Registering key : " << name;
    Key key(name, typeid(T), EnvKeyAttr::ParamAttr(attr ...));
    values[key] = std::make_unique<Value<T>>(std::move(func));
}

template <typename T>
void
Context::unregisterKey(const std::string &name)
{
    dbgTrace(D_ENVIRONMENT) << "Unregistering key : " << name;
    Key key(name, typeid(T));
    values.erase(key);
}

template <typename T>
void
Context::unregisterKey(MetaDataType name)
{
    unregisterKey<T>(convertToString(name));
}

template <typename T>
Context::Return<T>
Context::get(const std::string &name) const
{
    Key key(name, typeid(T));
    auto iter = values.find(key);
    if (iter == values.end()) return genError(Error::NO_VALUE);
    Value<T> *val = dynamic_cast<Value<T> *>(iter->second.get());
    return val->get();
}

template <typename T>
Context::Return<T>
Context::get(MetaDataType name) const
{
    return get<T>(convertToString(name));
}

class ScopedContext : public Context
{
public:
    ScopedContext();
    ~ScopedContext();
};
