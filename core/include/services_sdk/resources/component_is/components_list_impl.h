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

#ifndef __COMPONENTS_LIST_IMPL_H__
#define __COMPONENTS_LIST_IMPL_H__

#ifndef __COMPONENTS_LIST_H__
#error components_list_impl.h should not be included directly!
#endif // __COMPONENTS_LIST_H__

#include <type_traits>

#include "component.h"
#include "time_proxy.h"
#include "time_print.h"
#include "debug.h"
#include "config_component.h"
#include "mainloop.h"
#include "version.h"
#include "environment.h"
#include "rest_server.h"
#include "logging_comp.h"
#include "log_generator.h"
#include "proto_message_comp.h"
#include "table.h"
#include "agent_details.h"
#include "encryptor.h"
#include "signal_handler.h"
#include "cpu.h"
#include "memory_consumption.h"
#include "instance_awareness.h"
#include "socket_is.h"
#include "generic_rulebase/generic_rulebase.h"
#include "generic_rulebase/generic_rulebase_context.h"
#include "messaging_buffer.h"
#include "shell_cmd.h"
#include "generic_metric.h"
#include "tenant_manager.h"
#include "buffer.h"
#include "intelligence_comp_v2.h"

USE_DEBUG_FLAG(D_COMP_IS);

namespace Infra
{

class ComponentListException
{
public:
    static ComponentListException
    createVersioException(const std::string &version)
    {
        return ComponentListException(version, false);
    }

    static ComponentListException
    createException(const std::string &_str)
    {
        return ComponentListException(_str, true);
    }

    const std::string & getError() const { return str; }
    bool getIsError() const { return is_error; }

private:
    ComponentListException(const std::string &_str, bool _is_error) : str(_str), is_error(_is_error) {}

    std::string str;
    bool is_error;
};

template <typename Component, bool>
class ComponentWrapper
{
public:
    void preload() { comp.preload(); }
    void init() { comp.init(); }
    void fini() { comp.fini(); }

    const std::string & getName() const { return comp.getName(); }

private:
    Component comp;
};

template <typename Component>
class ComponentWrapper<Component, false>
{
public:
    void preload() { Component::preload(); }
    void init() { Component::init(); }
    void fini() { Component::fini(); }

    const std::string getName() const { return Component::getName(); }
};

template <typename ... Components>
class ComponentList
{
};

template <typename Component, typename ... MoreComponents>
class ComponentList<Component, MoreComponents...> : public ComponentList<MoreComponents...>
{
protected:
    void
    preloadComponents(const std::string &nano_service_name)
    {
        dbgInfo(D_COMP_IS) << "Preloading component: " << comp.getName();
        comp.preload();
        ComponentList<MoreComponents...>::preloadComponents(nano_service_name);
    }

    void
    init()
    {
        dbgInfo(D_COMP_IS) << "Initializing component: " << comp.getName();
        comp.init();
        ComponentList<MoreComponents...>::init();
    }

    void
    fini()
    {
        ComponentList<MoreComponents...>::fini();
        dbgInfo(D_COMP_IS) << "Finalizing component: " << comp.getName();
        comp.fini();
    }

private:
    ComponentWrapper<Component, std::is_base_of<::Component, Component>::value> comp;
};

template <>
class ComponentList<>
        :
    Singleton::Consume<I_Environment>,
    Singleton::Consume<Config::I_Config>,
    Singleton::Consume<I_MainLoop>
{
public:
    template <typename T>
    void
    registerGlobalValue(const std::string &name, const T &value)
    {
        Singleton::Consume<I_Environment>::by<ComponentList>()->registerValue(name, value);
    }

    void
    handleArgs(const std::vector<std::string> &arg_vec)
    {
        for (auto &arg : arg_vec) {
            if (arg == "--version") {
                throw ComponentListException::createVersioException(Version::get());
            }
        }

        registerGlobalValue<std::string>("Executable Name", arg_vec.front());
    }

    void
    preloadComponents(const std::string &nano_service_name)
    {
        registerGlobalValue<std::string>("Service Name", nano_service_name);
    }

    void
    loadConfiguration(const std::vector<std::string> &arg_vec)
    {
        if (!Singleton::Consume<Config::I_Config>::by<ComponentList>()->loadConfiguration(arg_vec)) {
            throw ComponentListException::createException("Failed to load configuration");
        }
    }

    void init() {}
    void fini() {}

    void
    run(const std::string &nano_service_name)
    {
        LogGen(
            "Check Point Nano-service started",
            ReportIS::Audience::SECURITY,
            ReportIS::Severity::INFO,
            ReportIS::Priority::MEDIUM,
            ReportIS::Tags::INFORMATIONAL
        ) << LogField("serviceName", nano_service_name);
        Singleton::Consume<I_MainLoop>::by<ComponentList>()->run();
    }
};

template <typename ... Components>
class ComponentListCore
        :
    public ComponentList<
        Environment,
        Debug,
        Version,
        Buffer,
        ShellCmd,
        GenericMetric,
        ConfigComponent,
        InstanceAwareness,
        IntelligenceComponentV2,
        AgentDetails,
        LoggingComp,
        TimeProxyComponent,
        MainloopComponent,
        SignalHandler,
        RestServer,
        Encryptor,
        SocketIS,
        ProtoMessageComp,
        CPUCalculator,
        CPUManager,
        MemoryCalculator,
        MessagingBuffer,
        TenantManager,
        GenericRulebase,
        Components...
    >
{
};

} // namespace Infra

#endif // __COMPONENTS_LIST_IMPL_H__
