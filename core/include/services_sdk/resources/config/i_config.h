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

#ifndef __I_CONFIG_H__
#define __I_CONFIG_H__

#ifndef __CONFIG_H__
#error "i_config.h should not be included directly"
#endif // __CONFIG_H__

#include <istream>
#include <ostream>
#include <vector>
#include <string>

namespace Config
{

using namespace std;

class I_Config
{
    using PerContextValue = std::vector<std::pair<std::shared_ptr<EnvironmentEvaluator<bool>>, TypeWrapper>>;

public:
    enum class AsyncLoadConfigStatus { Success, Error, InProgress };

    virtual const TypeWrapper & getConfiguration(const std::vector<std::string> &paths) const = 0;
    virtual PerContextValue getAllConfiguration(const std::vector<std::string> &paths) const = 0;
    virtual const TypeWrapper & getResource(const std::vector<std::string> &paths) const = 0;
    virtual const TypeWrapper & getSetting(const std::vector<std::string> &paths) const = 0;
    virtual string getProfileAgentSetting(const string &setting_name) const = 0;
    virtual vector<string> getProfileAgentSettings(const string &setting_name_regex) const = 0;

    virtual const string & getConfigurationFlag(const string &flag_name) const = 0;

    virtual const string &
    getConfigurationFlagWithDefault(const string &default_val, const string &flag_name) const = 0;

    virtual const string & getFilesystemPathConfig() const = 0;
    virtual const string & getLogFilesPathConfig() const = 0;

    virtual string getPolicyConfigPath(
        const string &policy,
        ConfigFileType type,
        const string &tenant,
        const string &profile) const = 0;

    virtual bool setConfiguration(TypeWrapper &&value, const std::vector<std::string> &paths) = 0;
    virtual bool setResource(TypeWrapper &&value, const std::vector<std::string> &paths) = 0;
    virtual bool setSetting(TypeWrapper &&value, const std::vector<std::string> &paths) = 0;

    virtual void registerExpectedConfigFile(const string &file_name, ConfigFileType type) = 0;
    virtual void registerExpectedConfiguration(unique_ptr<GenericConfig<true>> &&config) = 0;
    virtual void registerExpectedResource(unique_ptr<GenericConfig<false>> &&config) = 0;
    virtual void registerExpectedSetting(unique_ptr<GenericConfig<false>> &&config) = 0;

    template<typename T>
    void
    registerExpectedConfiguration(const vector<string> &path)
    {
        registerExpectedConfiguration(make_unique<SpecificConfig<T, true>>(path));
    }

    template<typename T>
    void
    registerExpectedResource(const vector<string> &path)
    {
        registerExpectedResource(make_unique<SpecificConfig<T, false>>(path));
    }

    template<typename T>
    void
    registerExpectedSetting(const vector<string> &path)
    {
        registerExpectedSetting(make_unique<SpecificConfig<T, false>>(path));
    }

    // TODO: merge both loadConfiguration functions to one with vector of streams input when moving to c++17
    // (c++ < 17 does not support copy of streams and thus it cannot be part of any container)
    virtual bool loadConfiguration(istream &json_contents, const string &path = "") = 0;
    virtual bool loadConfiguration(const vector<string> &configuration_flags) = 0;

    virtual AsyncLoadConfigStatus
    reloadConfiguration(
        const std::string &ver = "",
        bool do_continuous_report = false,
        uint id = 0
    ) = 0;

    virtual bool saveConfiguration(ostream &os) const = 0;

    virtual void registerConfigPrepareCb(ConfigCb) = 0;
    virtual void registerConfigLoadCb(ConfigCb) = 0;
    virtual void registerConfigAbortCb(ConfigCb) = 0;

    virtual void clearOldTenants() = 0;

protected:
    virtual ~I_Config() {}
};

} // namespace Config

#endif // __I_CONFIG_H__
