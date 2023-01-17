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

#ifndef __I_ENVIRONMENT_H__
#define __I_ENVIRONMENT_H__

#include <vector>
#include <functional>

#include "context.h"
#include "environment/span.h"
#include "scope_exit.h"

class I_Environment
{
    using Param = EnvKeyAttr::ParamAttr;

public:
    enum class TracingStatus { ON, OFF, DISABLED };

    using ActiveContexts = std::pair<std::vector<Context *>, bool>;

    template <typename T>
    Maybe<T, Context::Error>
    get(const std::string &name) const
    {
        auto active_contexts_vec = getActiveContexts().first;
        for (auto iter = active_contexts_vec.crbegin(); iter != active_contexts_vec.crend(); iter++) {
            auto value = (*iter)->get<T>(name);
            if (value.ok() || (value.getErr() != Context::Error::NO_VALUE)) return value;
        }
        return genError(Context::Error::NO_VALUE);
    }

    template <typename T>
    Maybe<T, Context::Error>
    get(Context::MetaDataType name) const
    {
        return get<T>(Context::convertToString(name));
    }

    virtual Context & getConfigurationContext() = 0;

    template <typename T>
    void
    registerValue(const std::string &name, const T &value)
    {
        getConfigurationContext().registerValue(name, value);
    }

    template <typename T>
    void
    unregisterKey(const std::string &name)
    {
        getConfigurationContext().unregisterKey<T>(name);
    }

    template <typename ... Attr>
    std::map<std::string, std::string> getAllStrings(Attr ... attr) const { return getAllStrings(Param(attr ...)); }

    template <typename ... Attr>
    std::map<std::string, uint64_t> getAllUints(Attr ... attr) const { return getAllUints(Param(attr ...)); }

    template <typename ... Attr>
    std::map<std::string, bool> getAllBools(Attr ... attr) const { return getAllBools(Param(attr ...)); }

    virtual void setActiveTenantAndProfile(const std::string &tenant_id, const std::string &profile_id = "") = 0;
    virtual void unsetActiveTenantAndProfile() = 0;

    virtual std::string getCurrentTrace() const = 0;
    virtual std::string getCurrentSpan() const = 0;
    virtual std::string getCurrentHeaders() = 0;
    virtual void startNewTrace(bool new_span = true, const std::string &_trace_id = std::string()) = 0;
    virtual void startNewSpan(
        Span::ContextType _type,
        const std::string &prev_span = std::string(),
        const std::string &trace = std::string()
    ) = 0;
    virtual std::scope_exit<std::function<void(void)>> startNewSpanScope(
        Span::ContextType _type,
        const std::string &prev_span = std::string(),
        const std::string &trace = std::string()
    ) = 0;
    virtual void finishTrace(const std::string &trace = std::string()) = 0;
    virtual void finishSpan(const std::string &span = std::string()) = 0;

protected:
    ~I_Environment() {}
    virtual const ActiveContexts & getActiveContexts() const = 0;
    virtual std::map<std::string, std::string> getAllStrings(const Param &param) const = 0;
    virtual std::map<std::string, uint64_t> getAllUints(const Param &param) const = 0;
    virtual std::map<std::string, bool> getAllBools(const Param &param) const = 0;

    // Registration of Contexts should be done from the Context object, therefore only those object
    // should have access to the environment registration methods.
    friend class Context;
    virtual void registerContext(Context *ptr) = 0;
    virtual void unregisterContext(Context *ptr) = 0;

    friend class MainloopComponent;
    virtual ActiveContexts createEnvironment() = 0;
    virtual ActiveContexts saveEnvironment() = 0;
    virtual void loadEnvironment(ActiveContexts &&env) = 0;
};

#endif // __I_ENVIRONMENT_H__
